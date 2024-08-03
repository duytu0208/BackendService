package com.be.english.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class AppConfig {

    /**
     * TODO [SpringSecurity #2] define bean securityFilterChain
     * Sử dụng để cấu hình các quy tắc bảo mật cho ứng dụng web của bạn.
     * Bean này sẽ thiết lập các bộ lọc bảo mật cần thiết cho ứng dụng, quy định cách xử lý các yêu cầu HTTP,
     * và quản lý các phiên đăng nhập, đăng xuất, và quyền truy cập.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable) //Disable trang login khi call api tới BE
                .authorizeHttpRequests(request ->
                        request.requestMatchers("/auth/**").permitAll()// Cho phép truy cập vào các URL /auth mà không cần xác thực
                                .anyRequest().authenticated())// Các request khác đều phải xác thực
                .sessionManagement(manager -> manager.sessionCreationPolicy(STATELESS)); // mỗi yêu cầu đến server sẽ mang theo một token (thường trong header Authorization), và ứng dụng sẽ xác thực người dùng dựa trên token này mà không cần lưu trữ trạng thái người dùng trên server (stateless)
                // TODO: authenticationProvider
                // TODO: addFilterBefore

        return http.build();
    }

    /**
     * TODO [SpringSecurity #3] define bean passwordEncoder
     * mã hóa mật khẩu trước khi lưu vào cơ sở dữ liệu,
     * hoặc để so sánh mật khẩu đã mã hóa với mật khẩu người dùng nhập vào.
     * Tích hợp với spring security thì sẽ được dùng trong authenticationProvider
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
