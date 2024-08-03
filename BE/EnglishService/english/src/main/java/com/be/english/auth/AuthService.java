package com.be.english.auth;

import com.be.english.auth.db.AuthEntity;
import com.be.english.auth.db.AuthRepository;
import com.be.english.common.AbstractEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.be.english.common.TokenType.REFRESH_TOKEN;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthRepository authRepository;

    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder;

    @Autowired
    @Lazy
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    public Long signup(Auth.SignUpRequest request) {

        var signupEntityRO = authRepository.findByUsername(request.userName());
        if (signupEntityRO.isPresent()) {
            throw new RuntimeException("adasdasd");
        }

        ObjectMapper objectMapper = new ObjectMapper();
        String signupRequestJson;
        try {
            signupRequestJson = objectMapper.writeValueAsString(request);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }

        var signupEntity = AuthEntity.builder()
                .username(request.userName())
                .password(passwordEncoder.encode(request.password())) /**TODO [SpringSecurity #4] encode password with passwordEncoder */
                .status(AbstractEntity.Status.ACTIVE)
                .signupData(signupRequestJson)
                .build();

        signupEntity = authRepository.save(signupEntity);

        return signupEntity.getId();
    }


    public Auth.SignInResponse signIn(Auth.SignInRequest request) {
        /** TODO [SpringSecurity #7 START] xác thực thông tin đăng nhập của người dùng
         * 1/Tạo UsernamePasswordAuthenticationToken:
         * UsernamePasswordAuthenticationToken là một implementation của ===> interface Authentication
         * được sử dụng để chứa thông tin xác thực của người dùng.
         * Nó lưu trữ username và password và sẽ được sử dụng bởi AuthenticationManager để xác thực.
         *
         * 2/ Gọi phương thức authenticate:
         * Phương thức authenticate của authenticationManager được gọi để xác thực thông tin đăng nhập của người dùng.
         * Phương thức này nhận vào một đối tượng Authentication.
         *
         * 3/ Quá trình xác thực bên trong AuthenticationManager:
         * AuthenticationManager sẽ sử dụng một hoặc nhiều AuthenticationProvider để xác thực người dùng.
         * Trong trường hợp của DaoAuthenticationProvider,
         * nó sẽ gọi phương thức loadUserByUsername của UserDetailsService để tải thông tin người dùng từ cơ sở dữ liệu
         * và so sánh mật khẩu đã mã hóa.
         *
         * 4/ Xử lý kết quả xác thực:
         * Nếu thông tin đăng nhập hợp lệ, người dùng sẽ được xác thực và phương thức authenticate sẽ trả về một
         * đối tượng Authentication chứa thông tin người dùng đã được xác thực.
         */
        Authentication authRequest = new UsernamePasswordAuthenticationToken(request.userName(), request.password());
        Authentication authenticate = authenticationManager.authenticate(authRequest);
        /**
         * TODO [SpringSecurity #7 END] xác thực thông tin đăng nhập của người dùng
         */

        var user = authRepository.findByUsername(request.userName())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
        /**
         * TODO [SpringSecurity #9] impl generateToken
         */
        var accessToken = jwtService.generateToken(user); // impl generateToken

        var refreshToken = jwtService.generateRefreshToken(user);

        return Auth.SignInResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .phoneNumber("dummy")
                .role("dummy")
                .build();
    }

    /**
     * TODO [SpringSecurity #11] refresh Token
     * Nguyên tắc là tạo thêm 1 secretKey cho refresh Token => expiryDay nhiều hơn accessToken
     * Mỗi lần refreshToken thì giữ nguyên cái refreshToken gốc, chỉ rênw accessToken,
     * Đến khi nào refreshToken hết hạn thì bắt user đăng nhập lại.
     */
    public Object refreshToken(HttpServletRequest httpServletRequest) {
        System.out.println(httpServletRequest.getHeader("x-token"));
        String refreshToken = httpServletRequest.getHeader("x-token");

        // Extract user from token
        final String userName = jwtService.extractUserName(refreshToken, REFRESH_TOKEN);

        // Check it into DB
        var user = authRepository.findByUsername(userName);

        String accessToken = null;
        if (jwtService.isTokenValid(refreshToken, REFRESH_TOKEN, user.get())) {
            accessToken = jwtService.generateToken(user.get());
        }

        return Auth.SignInResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .userId(user.get().getId())
                .phoneNumber("dummy")
                .role("dummy")
                .build();
    }
}
