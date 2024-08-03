package com.be.english.auth.db;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    /**
     * Add [for SpringSecurity #9] No4
     * Biến secretKey lưu trữ khóa bí mật dùng để ký JWT.
     * Đây là một chuỗi được mã hóa Base64 (secretKey gốc đã được mã hoá) => Detail in application.properties
     * TODO: Xem https://youtu.be/o4NSbpJ4VdE?si=ERGp95r76f5Tq0C5 để hiểu secretKey là gì
     */
    @Value("${jwt.token.secretKey}")
    private String secretKey;

    /** Add [for SpringSecurity #9] No1 ==> Control F find all 'Add [for SpringSecurity #9]'
     * Tạo JWT cho người dùng với các claims mặc định hoặc thêm claims (extraClaimsMap.put("message", "demo");)
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaimsMap = new HashMap<>();
        extraClaimsMap.put("message1", "demo1");
        extraClaimsMap.put("message2", "demo2");
        extraClaimsMap.put("message3", "demo3");

        return generateToken(extraClaimsMap, userDetails);
    }

    /** Add [for SpringSecurity #9] No2
     * Tạo JWT với các claims bổ sung và thông tin người dùng.
     */
    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims) // Đặt các claims bổ sung vào JWT. Claims là các dữ liệu bổ sung (như thông tin tùy chỉnh) có thể được lưu trữ trong JWT.
                .setSubject(userDetails.getUsername()) // Đặt subject của JWT thành tên đăng nhập của người dùng. Subject thường là ID hoặc username của người dùng.
                .setIssuedAt(new Date(System.currentTimeMillis())) // Đặt thời gian phát hành JWT là thời điểm hiện tại.
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // Đặt thời gian hết hạn của JWT. Trong trường hợp này, JWT sẽ hết hạn sau 24 phút (1000 ms * 60 giây * 24 phút).
                .signWith(getSigningKey(), SignatureAlgorithm.HS256).compact(); // Ký JWT bằng khóa bí mật và thuật toán HS256.
    }

    /**
     * Add [for SpringSecurity #9] No3
     * Phương thức này trả về khóa ký JWT.
     */
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey); // Giải mã khóa bí mật từ định dạng Base64 thành mảng byte.
        return Keys.hmacShaKeyFor(keyBytes); // Tạo và trả về khóa HMAC-SHA từ mảng byte, dùng để ký JWT.
    }
}
