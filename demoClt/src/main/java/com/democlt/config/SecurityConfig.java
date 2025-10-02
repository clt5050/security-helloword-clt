package com.democlt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
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
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthFilter;


   // @Autowired
   // @Lazy    //该注解会让 Spring 延迟初始化依赖的 Bean，直到首次使用该 Bean 时才创建
   // private UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }



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
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/hello").authenticated()

                        .anyRequest().authenticated()
                )


                .authenticationProvider(authenticationProvider())

                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        ;

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
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }


    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails testUser = User.withUsername("test")
                .password(passwordEncoder().encode("123456"))// 密码加密存储
                .roles("USER")// 赋予USER角色
                .build();
        return new InMemoryUserDetailsManager(testUser);
    }


    // 密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 使用BCrypt算法加密密码
    }

}
