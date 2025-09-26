package com.democlt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // 1. 配置密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 2. 配置测试用户（内存存储，适合快速测试，无需数据库）
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        // 构建test用户：用户名test，密码加密后存储（原密码123456），角色USER
        UserDetails testUser = User.withUsername("test")
                .password(encoder.encode("123456"))
                .roles("USER")
                .build();
        // 用内存管理器存储用户
        return new InMemoryUserDetailsManager(testUser);
    }

    // 3. 配置安全过滤链（控制接口权限、登录行为）
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 接口权限控制
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/hello") // HelloWorld接口
                        .authenticated() // 必须认证才能访问
                        .anyRequest() // 其他所有接口（含/login）
                        .permitAll() // 允许匿名访问（登录接口不能拦截）
                )
                // 启用默认登录页（SpringSecurity自动提供，无需自定义）
                .formLogin(form -> form.permitAll()) // 允许匿名访问登录页
                // 启用默认登出（可选，提升体验）
                .logout(logout -> logout.permitAll());

        return http.build();
    }


}
