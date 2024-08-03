package com.be.english.auth;

import com.be.english.common.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static com.be.english.common.TokenType.ACCESS_TOKEN;
import static com.be.english.common.TokenType.REFRESH_TOKEN;

@Service
@Slf4j
public class JwtService {

    /**
     *
     * Add [for SpringSecurity #9] No4
     * Biến secretKey lưu trữ khóa bí mật dùng để ký JWT.
     * Đây là một chuỗi được mã hóa Base64 (secretKey gốc đã được mã hoá) => Detail in application.properties
     * TODO: Xem https://youtu.be/o4NSbpJ4VdE?si=ERGp95r76f5Tq0C5 để hiểu secretKey là gì
     */
    @Value("${jwt.token.accessKey}")
    private String accessKey;

    @Value("${jwt.token.refreshKey}")
    private String refreshKey;

    @Value("${jwt.token.expiryDay}")
    private Integer expiryDay;


    /**
     *
     * Add [for SpringSecurity #9] No1 ==> Control F find all 'Add [for SpringSecurity #9]'
     * Tạo JWT cho người dùng với các claims mặc định hoặc thêm claims (extraClaimsMap.put("message", "demo");)
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaimsMap = new HashMap<>();
        extraClaimsMap.put("message1", "demo1");
        extraClaimsMap.put("message2", "demo2");
        extraClaimsMap.put("message3", "demo3");

        return generateToken(extraClaimsMap, userDetails);
    }


    /**
     *
     * Add [for SpringSecurity #9] No2
     * Tạo JWT với các claims bổ sung và thông tin người dùng.
     */
    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims) // Đặt các claims bổ sung vào JWT. Claims là các dữ liệu bổ sung (như thông tin tùy chỉnh) có thể được lưu trữ trong JWT.
                .setSubject(userDetails.getUsername()) // Đặt subject của JWT thành tên đăng nhập của người dùng. Subject thường là ID hoặc username của người dùng.
                .setIssuedAt(new Date(System.currentTimeMillis())) // Đặt thời gian phát hành JWT là thời điểm hiện tại.
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Đặt thời gian hết hạn của JWT. Trong trường hợp này, JWT sẽ hết hạn sau 24 phút (1000 ms * 60 giây * 24 phút).
                .signWith(getSigningKey(ACCESS_TOKEN), SignatureAlgorithm.HS256).compact(); // Ký JWT bằng khóa bí mật và thuật toán HS256.
    }


    /**
     *
     * Add [for SpringSecurity #9] No3
     * Phương thức này trả về khóa ký JWT.
     */
    private Key getSigningKey(TokenType type) {
        byte[] keyBytes = null;
        if (ACCESS_TOKEN.equals(type))
            keyBytes = Decoders.BASE64.decode(accessKey); // Giải mã khóa bí mật từ định dạng Base64 thành mảng byte.
        else
            keyBytes = Decoders.BASE64.decode(refreshKey);

        return Keys.hmacShaKeyFor(keyBytes); // Tạo và trả về khóa HMAC-SHA từ mảng byte, dùng để ký JWT.
    }


    /**
     *
     * Add [for SpringSecurity #10] No3
     * Trích xuất tên người dùng từ token JWT
     *
     * Claims::getSubject là một hàm lấy chủ thể (subject) từ đối tượng Claims
     * Chủ thể của token thường là tên người dùng hoặc ID của người dùng. => Ở đây thì đang là userName
     */
    public String extractUserName(String token, TokenType type) {
        return extractClaim(token, type, Claims::getSubject);
    }


    /**
     *
     * Add [for SpringSecurity #10] No4
     * Trích xuất một claim cụ thể từ token JWT.
     *
     * extractAllClaims để lấy tất cả các claims từ token JWT.
     * claimsResolvers (một hàm được truyền vào) để trích xuất giá trị cụ thể từ các claims.
     * T là kiểu dữ liệu của giá trị claim mà bạn muốn trích xuất (ví dụ: String, Date).
     */
    private <T> T extractClaim(String token, TokenType type, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token, type);
        return claimsResolvers.apply(claims);
    }


    /**
     *
     * Add [for SpringSecurity #10] No5
     * Trích xuất tất cả các claims từ token JWT
     *
     * Cách hoạt động:
     * Tạo một JwtParser bằng cách sử dụng Jwts.parserBuilder().
     * Đặt khóa ký (signing key) cho parser bằng phương thức setSigningKey(getSigningKey()).
     * Phân tích token JWT bằng parseClaimsJws(token), sau đó lấy phần thân (body) của token chứa các claims.
     * Phương thức trả về một đối tượng Claims chứa tất cả các thông tin trong token.
     */
    private Claims extractAllClaims(String token, TokenType type) {
        return Jwts.parserBuilder()
                .setSigningKey(ACCESS_TOKEN.equals(type) ? getSigningKey(ACCESS_TOKEN) : getSigningKey(REFRESH_TOKEN))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    /**
     *
     * Add [for SpringSecurity #10] No6
     * Xác thực tính hợp lệ của token JWT
     *
     * Cách hoạt động:
     * Trích xuất tên người dùng từ token bằng extractUserName(token).
     * So sánh tên người dùng từ token với tên người dùng trong UserDetails.
     * Kiểm tra xem token có hết hạn không bằng cách gọi isTokenExpired(token).
     * Token được coi là hợp lệ nếu tên người dùng khớp và token không bị hết hạn.
     */
    public boolean isTokenValid(String token, TokenType type, UserDetails userDetails) {
        final String userName = extractUserName(token, type);
        return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token, type);
    }


    /**
     *
     * Add [for SpringSecurity #10] No7
     * Kiểm tra xem token JWT có bị hết hạn hay không
     *
     * Cách hoạt động:
     * Trích xuất ngày hết hạn của token bằng phương thức extractExpiration(token).
     * So sánh ngày hết hạn với ngày hiện tại (new Date()).
     * Token được coi là hết hạn nếu ngày hết hạn trước ngày hiện tại.
     */
    private boolean isTokenExpired(String token, TokenType type) {
        return extractExpiration(token, type).before(new Date());
    }


    /**
     *
     * Add [for SpringSecurity #10] No8
     * Trích xuất ngày hết hạn của token từ token JWT
     *
     * Cách hoạt động:
     * Gọi phương thức extractClaim với tham số là Claims::getExpiration,
     * mà Claims::getExpiration là một hàm lấy ngày hết hạn từ đối tượng Claims.
     * Phương thức trả về đối tượng Date chứa ngày hết hạn của token.
     */
    private Date extractExpiration(String token, TokenType type) {
        return extractClaim(token, type, Claims::getExpiration);
    }


    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> extraClaimsMap = new HashMap<>();
        extraClaimsMap.put("message1", "demo1");
        return generateRefreshToken(extraClaimsMap, userDetails);
    }

    private String generateRefreshToken(Map<String, Object> claims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * expiryDay))
                .signWith(getSigningKey(REFRESH_TOKEN), SignatureAlgorithm.HS256)
                .compact();
    }
}
