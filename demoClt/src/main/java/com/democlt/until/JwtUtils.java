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
    // 运行main()生成安全的HS512密钥（复制粘贴到application.properties的secret中）
    public static void main(String[] args) {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);// 生成HS512算法的随机密钥
        // 将密钥进行Base64编码（方便存储和传输）
        //二进制密钥不适合直接存储在配置文件
        //key.getEncoded()：获取密钥的字节数组（原始二进制形式）。
        String base64Key = java.util.Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println("生成的安全密钥（保存到application.properties中）: " + base64Key);
    }
    // 解析密钥供 签名 / 验证使用
    private SecretKey getSignInKey() {
        // 将 Base64 字符串解码为原始二进制字节数组（与生成时的 key.getEncoded() 结果一致）。
        byte[] keyBytes = java.util.Base64.getDecoder().decode(secret);
        //Keys.hmacShaKeyFor(keyBytes) 要求传入的字节数组长度必须符合对应算法的安全要求：
        //对于 HS256：密钥长度 ≥ 256 位（32 字节）
        //对于 HS512：密钥长度 ≥ 512 位（64 字节）
        return Keys.hmacShaKeyFor(keyBytes);//JJWT 库方法，根据解码后的字节数组生成适用于 HS512 算法的SecretKey对象。
    }


    // 生成令牌（基于用户名），被AuthController.java引用
    public String generateToken(String username) {
        //：创建一个空的HashMap（用于存储额外声明），调用重载的generateToken方法（传递空 map 和用户名），实现代码复用。
        return generateToken(new HashMap<>(), username);
    }
    //重载方法，构建完整JWT（支持额外声明）
    public String generateToken(Map<String, Object> extraClaims, String username) {//Map<String, Object> extraClaims：自定义声明（可选）
        return Jwts.builder()//调用 JJWT 库的Jwts.builder()方法，创建一个 JWT 构建器（JwtBuilder），用于设置令牌的各种属性。
                .setClaims(extraClaims)// 附加自定义声明（可选）
                .setSubject(username)// 必需：用户唯一标识（如用户名）//JWT 标准字段（sub），用于标识令牌的主体（通常是用户名或用户 ID），是验证用户身份的核心依据。
                .setIssuedAt(new Date(System.currentTimeMillis())) // 必需：令牌签发时间，毫秒级//记录令牌生成时间，可用于判断令牌是否在合理时间内生成
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // 必需：令牌过期时间
                // 必需：根据密钥和算法对令牌的 “头部 + 载荷” 进行签名，生成签名部分（Signature），确保令牌未被篡改（验证时会重新计算签名比对）。
                .signWith(getSignInKey(), SignatureAlgorithm.HS512)
                .compact();   // 生成最终令牌字符串，格式：Header.Payload.Signature）
    }


    /**
     * 下三个方法，提供通用的声明提取逻辑，支持从令牌中提取任意字段（不仅限于用户名）。
     * extractUsername（提取用户名）→ extractClaim（通用提取）→ extractAllClaims（底层解析 + 验证）
     */
    // 从令牌中提取用户名（核心标识）,令牌载荷中的sub字段
    public String extractUsername(String token) {
        //Claims::getSubject等价于claims -> claims.getSubject()，
        // 即从Claims对象中调用getSubject()方法，获取sub字段的值（用户名）。
        return extractClaim(token, Claims::getSubject);
    }
    // 通用方法，提供通用的声明提取逻辑，支持从令牌中提取任意字段（不仅限于用户名），通过函数式接口实现灵活扩展。
    //<T>：泛型参数，表示提取结果的类型
    //String token：待解析的 JWT 令牌；
    //Function<Claims, T> claimsResolver：函数式接口，接收Claims对象，返回提取的字段值（T类型）。
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);//解析令牌所有声明的Claims对象（载荷中的所有键值对）。
        return claimsResolver.apply(claims);// 用传入的函数提取特定声明
    }
    // 解析 JWT 令牌的完整载荷（Claims），并在解析过程中验证令牌的签名完整性和有效性（如是否过期），是整个提取逻辑的安全基础。
    //验证逻辑：
    //解析时，JJWT 库会用服务器密钥重新计算令牌的签名，并与令牌中自带的Signature部分比对：
    //若签名一致 → 令牌未被篡改，解析成功；
    //若签名不一致 → 抛出SignatureException（令牌被篡改，验证失败）。
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()// 调用 JJWT 库的Jwts.parserBuilder()方法，创建解析器构建器（JwtParserBuilder），用于配置解析规则。
                .setSigningKey(getSignInKey())// 关键：指定签名密钥，用于验证令牌完整性
                .build()//根据配置（如签名密钥）构建 JWT 解析器（JwtParser）
                //签名验证：确保令牌未被篡改（依赖步骤 2 的密钥）；
                //过期验证：若令牌的exp（过期时间）早于当前时间，抛出ExpiredJwtException；
                //格式验证：若令牌格式错误（如非 JWT 结构），抛出MalformedJwtException。
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
        final String username = extractUsername(token);//调用extractUsername方法，从令牌中提取sub字段（用户名）。
        // 两个条件同时满足才视为true：
        // 1. 令牌中的用户名与系统中的用户匹配
        // 2. 令牌未过期
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);// 验证令牌是否有效（返回结果：用户名匹配且未过期）
    }
    // 检查令牌是否过期
    //before(...)：Date类的方法，判断 “令牌的过期时间” 是否在 “当前时间” 之前。
    //若返回true：过期时间 < 当前时间 → 令牌已过期；
    //若返回false：过期时间 > 当前时间 → 令牌未过期。
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());//true&&false
    }
    // 从 JWT 令牌中提取exp（过期时间）字段，供 isTokenExpired 方法判断是否过期。
    private Date extractExpiration(String token) {
        //从令牌的载荷（Claims）中获取exp字段的值（Date类型），即令牌的过期时间。
        return extractClaim(token, Claims::getExpiration);
    }
}
