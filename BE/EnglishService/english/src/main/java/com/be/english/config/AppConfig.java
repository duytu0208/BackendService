package com.be.english.config;

import com.be.english.auth.db.AuthRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AppConfig {

    private final AuthRepository authRepository;
    private final PreFilter preFilter;

    /**
     * TODO [SpringSecurity #2] define bean securityFilterChain
     * Sử dụng để cấu hình các quy tắc bảo mật cho ứng dụng web của bạn.
     * Bean này sẽ thiết lập các bộ lọc bảo mật cần thiết cho ứng dụng, quy định cách xử lý các yêu cầu HTTP,
     * và quản lý các phiên đăng nhập, đăng xuất, và quyền truy cập.
     *
     * csrf:
     *     Tắt bảo vệ CSRF (Cross-Site Request Forgery). Đây là bảo mật giúp ngăn chặn các cuộc tấn công CSRF.
     *     Việc tắt CSRF thường được thực hiện trong các ứng dụng RESTful
     *     nơi mà các yêu cầu chủ yếu được thực hiện qua API và không sử dụng session để lưu trạng thái.
     *
     *authorizeHttpRequests:
     *    Cho phép truy cập vào các URL /auth mà không cần xác thực, Các request khác đều phải xác thực
     *
     *sessionManagement:
     *    Thiết lập ứng dụng không sử dụng session để lưu trữ trạng thái. Điều này thường được sử dụng trong các ứng dụng RESTful để đảm bảo rằng mỗi yêu cầu là độc lập và không dựa vào session. mỗi yêu cầu đến server sẽ mang theo một token (thường trong header Authorization), và ứng dụng sẽ xác thực người dùng dựa trên token này mà không cần lưu trữ trạng thái người dùng trên server (stateless)
     *
     * authenticationProvider
     *    Đăng ký AuthenticationProvider tùy chỉnh (được định nghĩa trong phương thức authenticationProvider()) để xử lý việc xác thực người dùng.
     *
     * addFilterBefore:
     *    Thêm bộ lọc tùy chỉnh preFilter vào list filter của Spring Security trước filter UsernamePasswordAuthenticationFilter.
     *    Điều này cho phép bạn thực hiện các chức năng tùy chỉnh
     *    trước khi request được xử lý bởi UsernamePasswordAuthenticationFilter
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request ->
                        request.requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated())
                .sessionManagement(manager -> manager.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider()) // TODO [SpringSecurity #8] define bean authenticationProvider
                .addFilterBefore(preFilter, UsernamePasswordAuthenticationFilter.class); // TODO [SpringSecurity #10] addFilterBefore
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


    /**
     * TODO [SpringSecurity #6] define AuthenticationManager
     * Đây là một đối tượng của AuthenticationManager, một thành phần chính trong Spring Security chịu trách nhiệm quản lý
     * quá trình xác thực. AuthenticationManager thường được cấu hình
     * để sử dụng một hoặc nhiều ===> AuthenticationProvider để xác thực người dùng.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Từ mô tả của [SpringSecurity #7] để hiểu username được truyền vào như thế nào
     *
     * Bean authenticationProvider được sử dụng để cấu hình một nhà cung cấp xác thực (authentication provider) trong Spring Security.
     * authenticationProvider này sẽ chịu trách nhiệm xác thực(Authentication) người dùng
     * bằng cách sử dụng một dịch vụ UserDetailsService và một PasswordEncoder.
     *
     * Giải thích chi tiết về các thành phần:
     * 1/ DaoAuthenticationProvider:
     * Đây là một implementation của AuthenticationProvider được sử dụng để xác thực người dùng bằng cách tải thông tin người dùng
     * từ cơ sở dữ liệu (hoặc một nguồn dữ liệu khác) thông qua ===> UserDetailsService.
     * Nó sử dụng một PasswordEncoder để mã hóa mật khẩu trước khi so sánh với mật khẩu đã lưu trong cơ sở dữ liệu.
     *
     * 2/ UserDetailsService:
     * UserDetailsService là một interface cung cấp phương thức loadUserByUsername để tải thông tin người dùng dựa trên tên đăng nhập.
     * Thông tin này thường bao gồm tên đăng nhập, mật khẩu đã mã hóa, và danh sách các quyền hạn của người dùng.
     *
     * 3/ PasswordEncoder:
     * PasswordEncoder được sử dụng để mã hóa mật khẩu người dùng trước khi lưu trữ trong cơ sở dữ liệu
     * và để kiểm tra mật khẩu khi người dùng đăng nhập.
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return authRepository.findByUsername(username).get(); // AuthEntity đang implements UserDetails
            }
        });
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }
}
