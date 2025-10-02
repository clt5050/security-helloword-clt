package com.democlt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
/**
 * Spring Security 配置类
 * 到达controller 之前，进行过滤（ 过滤器链，按注册顺序执行）
 * 1-禁用 CSRF（csrf.disable()）；
 * 2-设置无状态会话（sessionCreationPolicy(STATELESS)）；
 * 3-配置 URL 授权规则（如/login允许匿名，/hello需要认证）；
 * 4-注册自定义过滤器：认证提供者；
 * 5-将自定义的jwtAuthFilter（JWT 认证过滤器）添加到过滤链中，并指定其执行顺序。
 * 6-return http.build();
 * 然后才能进入controller。
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig { //SecurityConfig的核心职责是配置安全规则（如接口权限、过滤链等），而JwtAuthenticationFilter是实现 JWT 认证的关键组件（负责令牌验证）。

    // 通过构造函数注入，明确声明了SecurityConfig对JwtAuthenticationFilter的强依赖（没有该过滤器，JWT 认证无法生效）。
    private final JwtAuthenticationFilter jwtAuthFilter;

    // 构造函数注入JwtAuthenticationFilter
    @Autowired
    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }


    // 安全过滤链
    //定义系统的安全规则（哪些接口需要认证、如何处理会话、使用哪些过滤器等），是 Spring Security 的 “规则中心”。
    //SecurityFilterChain 由一系列按特定顺序排列的过滤器（Filter） 组成

    /**
     * 创建安全过滤链，按序 执行
     * 1请求进入应用，依次经过WebAsyncManagerIntegrationFilter→SecurityContextPersistenceFilter等前置过滤器；
     * 2到达JwtAuthenticationFilter：提取 JWT 令牌，验证通过后将用户信息存入SecurityContext；
     * 3经过UsernamePasswordAuthenticationFilter等中间过滤器（无实际操作）；
     * 4到达FilterSecurityInterceptor：检查/hello需要认证，且SecurityContext中已有认证信息，允许访问；
     * 5请求离开过滤链，进入 Spring MVC 的DispatcherServlet，最终到达HelloController处理。
     * @param http
     * @return
     * @throws Exception
     */
    @Bean//将SecurityFilterChain注册到spring容器中
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //原因：项目使用 JWT 进行无状态认证（不依赖 Session），而 CSRF 保护的核心是通过 Session 中的令牌验证请求合法性，因此对 JWT 场景无效，禁用可简化配置。
                .csrf(csrf -> csrf.disable())
                //含义：服务器不创建、不使用任何 Session，所有请求的认证状态完全通过 JWT 令牌判断（符合 JWT 的无状态设计理念）。
                //效果：避免 Session 相关的安全问题（如 Session 固定攻击），同时适配分布式系统（无需共享 Session）。
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                //仅仅提供定义和配置 授权规则，不提供实际操作。
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll() // 匹配/login路径的请求，允许所有用户访问（包括未认证用户）。
                        .requestMatchers("/hello").authenticated() // 路径允许所有 “已认证” 的用户访问，拒绝匿名用户
                        // 其他所有未匹配的请求，默认要求用户必须已认证
                        //作为 “兜底规则”，确保除了明确开放的接口（如/login），其他接口都需要认证，遵循 “最小权限原则”。
                        .anyRequest().authenticated()
                )

                //作用：指定用户名密码的认证逻辑由我们下方配置的authenticationProvider()处理，负责加载用户信息和校验密码。
                .authenticationProvider(authenticationProvider())// 注册自定认证提供者

// 将自定义的JWT 认证过滤器（JwtAuthenticationFilter.java）添加到过滤链中，且位置在UsernamePasswordAuthenticationFilter（Security 默认的用户名密码认证过滤器）之前。
//确保 JWT 令牌验证逻辑优先执行 —— 如果请求携带有效 JWT 令牌，直接通过认证；只有当没有令牌或令牌无效时，才可能触发后续的用户名密码认证
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)//注册 JWT 过滤器
        ;
        //根据上述配置，构建SecurityFilterChain实例并返回，该实例会被 Spring Security 用于处理所有请求的安全校验。
        return http.build();
    }


    /**
     * 下面两个 方法;
     * 这两个 Bean 是 “指挥 - 执行” 的关系，共同完成认证：
     * 共同支撑了 “用户名密码验证” 的核心逻辑
     *  认证管理器:AuthenticationManager
     *      @Bean：将方法返回的AuthenticationManager对象注册为 Spring 容器中的 Bean，供其他组件（如AuthController的login方法）注入使用。
     *      AuthenticationManager：Spring Security 的 “认证总指挥”，负责接收认证请求（如用户名密码），并委托给合适的AuthenticationProvider执行实际验证。
     *      AuthenticationConfiguration config：参数是 Spring Security 提供的认证配置类，内部封装了认证管理器的默认配置逻辑。
     *  认证提供者:DaoAuthenticationProvider:
     *      工作流程：
     *         1- 接收 AuthenticationManager 传递的认证凭据（用户名密码）；
     *         2- 调用UserDetailsService加载用户信息（如从内存中获取test用户）；
     *         3- 调用PasswordEncoder比对输入密码与存储的加密密码；
     *         4- 验证通过 → 返回包含用户信息的Authentication对象；
     *         5- 验证失败 → 抛出BadCredentialsException（密码错误）等异常。
     *          @return
     */
    // 注册认证管理器
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    //认证提供者
    @Bean//@Bean：将DaoAuthenticationProvider注册为 Spring 容器中的 Bean，会被AuthenticationManager自动发现并使用。
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();//new 创建DaoAuthenticationProvider实例，它是处理用户名密码认证的核心组件。
        authProvider.setUserDetailsService(userDetailsService());// 设置用户信息源,来自userDetailsService（）
        authProvider.setPasswordEncoder(passwordEncoder());// 设置用户信息源，来自passwordEncoder（）
        return authProvider;
    }


    //UserDetailsService：用户信息数据源（认证的 “数据库”）
    @Bean
    public UserDetailsService userDetailsService() {
        // 创建内存用户（实际项目中可从数据库加载）
        UserDetails testUser = User.withUsername("test")
                .password(passwordEncoder().encode("123456"))// 密码加密存储
                .roles("USER")// 赋予USER角色
                .build();
        // 返回内存用户管理器（管理用户信息）
        return new InMemoryUserDetailsManager(testUser);
    }


    // 密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 使用BCrypt算法加密密码
    }

}
