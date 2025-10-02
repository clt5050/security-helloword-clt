package com.democlt.config;

import com.democlt.until.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
/**
 * JWT认证过滤器
 * 验证令牌的有效性
 * 继承OncePerRequestFilter，确保每个请求只被处理一次
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    // 声明JWT工具类依赖（必需，用于令牌解析和验证）
    private final JwtUtils jwtUtils;

    // 声明用户详情服务（非构造器注入，后续通过setter设置）
    private UserDetailsService userDetailsService;

    // 只注入JwtUtils，避免循环依赖
    @Autowired
    public JwtAuthenticationFilter(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }
    // 提供setter方法，用于后续注入UserDetailsService
    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * 负责拦截请求、验证 JWT 令牌、并将认证信息注入 Spring Security 上下文
     * doFilterInternal 是 Spring Security 过滤器的核心方法（继承自OncePerRequestFilter），会对每个请求执行一次拦截处理，主要完成：
     * 从请求头中提取 JWT 令牌；
     * 验证令牌有效性；
     * 若有效，将用户认证信息存入SecurityContext，让后续接口（如/hello）识别当前登录用户。
     * 整体流程总结:
     *         拦截请求 → 检查Authorization头是否有符合格式的 JWT 令牌；
     *         解析令牌 → 提取用户名并验证令牌签名（防篡改）；
     *         验证用户 → 加载系统用户信息，检查令牌是否有效（未过期 + 用户名匹配）；
     *         设置认证 → 有效则将用户信息存入SecurityContext，让后续流程识别登录状态；
     *         放行请求 → 继续处理请求（由授权规则决定最终是否允许访问接口）。
     * @param request 请求
     * @param response 响应
     * @param filterChain 过滤器链
     * @throws ServletException 抛给Servlet容器
     * @throws IOException 抛给Servlet容器
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt =authHeader.substring(7);
        try {
            username = jwtUtils.extractUsername(jwt);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                if (jwtUtils.isTokenValid(jwt, userDetails)) {

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {

            logger.error("error: Unable to verify JWT token: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
