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
   // @Override：重写OncePerRequestFilter的doFilterInternal方法，确保每个请求只被过滤一次。
   // 参数：
   //       HttpServletRequest request：客户端请求对象（包含请求头、路径等信息）；
   //       HttpServletResponse response：服务器响应对象；
   //       FilterChain filterChain：过滤器链，用于将请求传递给下一个过滤器。
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // 从请求头获取令牌（Authorization 头是行业标准的令牌传递方式，格式为 Bearer <令牌>）
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        // 无令牌或格式不正确，直接调用filterChain.doFilter(request, response)，将请求传递给下一个过滤器，不做 JWT 验证
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            //filterChain.doFilter(...) 让请求继续流向后续过滤器或控制器，由 Spring Security 的其他组件（如授权规则）决定是否允许访问。
            filterChain.doFilter(request, response);
            return;
        }

        // 提取令牌（去掉"Bearer "前缀，从索引7开始截取）
        jwt =authHeader.substring(7);
        try {
            // jwtUtils.extractUsername(jwt)：在jwtUtils中解析令牌中的用户名（内部会验证令牌签名，若篡改则抛异常）。
            username = jwtUtils.extractUsername(jwt);

            // 条件：用户名存在 + 当前上下文无认证信息（避免重复认证）
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // 从数据库/内存加载用户完整信息（如权限、角色）
                //userDetailsService.loadUserByUsername(username)：加载系统中存储的用户信息（目地：与令牌中的用户名匹配），用于后续验证。
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                // 验证令牌是否有效（用户名匹配 + 未过期）
                if (jwtUtils.isTokenValid(jwt, userDetails)) {
                    // 创建Spring Security认可的认证对象
                    // 令牌有效时，创建UsernamePasswordAuthenticationToken（Spring Security 的标准认证对象），并通过SecurityContextHolder存入上下文；
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()// 包含用户权限
                    );
                    //添加请求细节（如客户端 IP、会话 ID 等），用于审计或后续验证。(可选)
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // 将认证对象存入安全上下文，标记当前用户 “已认证”，后续过滤器和 Controller 可通过该上下文获取用户信息。
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            //捕获令牌验证过程中的所有异常（如签名错误、过期、用户名不存在等），仅记录错误日志，不中断过滤链（避免影响后续过滤器处理）
            logger.error("error: Unable to verify JWT token: " + e.getMessage());
        }

        // 无论 JWT 验证成功与否，都将请求传递给过滤链中的下一个过滤器
        filterChain.doFilter(request, response);
    }
}
