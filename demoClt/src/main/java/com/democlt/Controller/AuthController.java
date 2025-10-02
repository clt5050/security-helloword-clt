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
    // 负责接收客户端提交的用户名密码、触发认证流程，并在认证通过后生成 JWT 令牌返回
    @PostMapping("/login")
    public String login(@RequestParam String username,// 接收请求中用户名参数
                        @RequestParam String password) {// 接收密码参数

        //Spring Security认证
        // 调用 SecurityConfig.authenticationManager 方法认证用户名密码
        //创建UsernamePasswordAuthenticationToken对象（Spring Security 的标准 “认证请求令牌”）
        Authentication authentication = authenticationManager.authenticate(//authenticated属性为false（表示未认证状态
                new UsernamePasswordAuthenticationToken(username, password)//封装用户名和密码
        );


        // 提取认证成功的信息
        //authentication.getPrincipal()从认证成功的Authentication对象中获取 “主体信息”，即用户详情（UserDetails类型）。
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // 打印
        System.out.println("主体信息authentication.getPrincipal() = " + authentication.getPrincipal());
        System.out.println("用户名userDetails.getUsername() = " + userDetails.getUsername());
        System.out.println("权限列表userDetails.getAuthorities() = " + userDetails.getAuthorities());
        System.out.println("密码userDetails.getPassword() = " + userDetails.getPassword());



        // 调用来自JwtUtils中的方法jwtUtils.generateToken(test)根据用户名生成 JWT 令牌。令牌中包含用户名（subject）、过期时间等信息，并通过安全密钥签名。
        // userDetails.getUsername() → "test"
        System.out.println("生成令牌generateToken(userDetails.getUsername())=[" + jwtUtils.generateToken(userDetails.getUsername())+ " ]");
        String jwt = jwtUtils.generateToken(userDetails.getUsername());

        return "Bearer " + jwt;
    }
}
