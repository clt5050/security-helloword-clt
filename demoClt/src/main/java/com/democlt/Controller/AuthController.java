package com.democlt.Controller;

import com.democlt.until.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 *  登录接口（获取 JWT 令牌）
 *  负责接收用户名密码、通过 Spring Security 验证凭据，并在验证成功后生成 JWT 令牌返回给客户端。
 */
@RestController
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;// Spring Security认证管理器

    @Autowired
    private JwtUtils jwtUtils;// JWT工具类（生成令牌）
    /**
     * 登录接口
     *  AuthenticationManager会自动委托给DaoAuthenticationProvider（默认的认证提供者），后者会：
     * 调用UserDetailsService（我们配置的userDetailsService()方法）加载用户信息（从内存或数据库）；
     * 使用PasswordEncoder（如BCryptPasswordEncoder）比对输入密码与存储的加密密码；
     * 验证通过 → 返回包含用户信息的Authentication对象；
     * 验证失败 → 抛出异常（如BadCredentialsException，Spring Security 会自动转为 401 响应）。
     * @param username 用户名
     * @param password 密码
     * @return 登录成功返回JWT令牌
     */
    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password) {// 接收密码参数


        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );


        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // 打印
        System.out.println("主体信息authentication.getPrincipal() = " + authentication.getPrincipal());
        System.out.println("用户名userDetails.getUsername() = " + userDetails.getUsername());
        System.out.println("权限列表userDetails.getAuthorities() = " + userDetails.getAuthorities());
        System.out.println("密码userDetails.getPassword() = " + userDetails.getPassword());



        System.out.println("生成令牌generateToken(userDetails.getUsername())=[" + jwtUtils.generateToken(userDetails.getUsername())+ " ]");
        String jwt = jwtUtils.generateToken(userDetails.getUsername());

        return "Bearer " + jwt;
    }
}
