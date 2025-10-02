package com.democlt.until;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
/**
 * 工具类
 * 替代 Session 认证，用户登录后生成 JWT 令牌，后续请求通过令牌验证身份（无状态，适合分布式系统）。
 * 流程：
 *    从请求头中获取令牌；
 *    调用isTokenValid(token, userDetails)验证：
 *    先提取令牌中的用户名，与系统中查询到的用户（UserDetails）比对；
 *    再检查令牌是否未过期；
 *    两个条件均满足 → 令牌有效，允许访问；
 *    任一一个条件不满足 → 令牌无效，返回 401 未授权。
 */
@Component
public class JwtUtils {

    // 从资源文件获取密钥，应该是至少64个字节的安全密钥
    @Value("${jwt.secret}")//数据来自：application.properties
    private String secret;
    // 令牌有效期
    @Value("${jwt.expiration}")//数据来自：application.properties
    private long expiration;

    /**
     * main() & getSignInKey()
     * 作用：生成安全密钥
     * 目的：与jwt令牌的头和负载共同加密，生成令牌签名
     */

    public static void main(String[] args) {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);// 生成HS512算法的随机密钥

        String base64Key = java.util.Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("生成的安全密钥（保存到application.properties中）: " + base64Key);
    }
    // 解析密钥供 签名 / 验证使用
    private SecretKey getSignInKey() {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    public String generateToken(String username) {
        return generateToken(new HashMap<>(), username);
    }

    public String generateToken(Map<String, Object> extraClaims, String username) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))

                .signWith(getSignInKey(), SignatureAlgorithm.HS512)
                .compact();
    }


    /**
     * 下三个方法，提供通用的声明提取逻辑，支持从令牌中提取任意字段（不仅限于用户名）。
     * extractUsername（提取用户名）→ extractClaim（通用提取）→ extractAllClaims（底层解析 + 验证）
     */
    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);//解析令牌所有声明的Claims对象（载荷中的所有键值对）。
        return claimsResolver.apply(claims);// 用传入的函数提取特定声明
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()

                .parseClaimsJws(token)
                .getBody();// 获取令牌的载荷（所有声明）
    }


    /**
     * 作用：验证令牌有效性
     * 通过 “用户名匹配” 和 “令牌未过期” 两个核心条件，确保令牌既属于当前用户，又在有效期内。
     * @param token
     * @param userDetails
     * @return
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);

        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());//true&&false
    }

    private Date extractExpiration(String token) {

        return extractClaim(token, Claims::getExpiration);
    }
}
