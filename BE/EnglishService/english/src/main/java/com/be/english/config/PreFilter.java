package com.be.english.config;

import com.be.english.auth.JwtService;
import com.be.english.auth.db.AuthRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
@Slf4j
public class PreFilter extends OncePerRequestFilter {
    /**
     * Add [for SpringSecurity #10] No1
     * extends OncePerRequestFilter => đảm bảo rằng PreFilter thực thi một lần cho mỗi yêu cầu.
     */

    private final JwtService jwtService;
    private final AuthRepository authRepository;

    /**
     * Add [for SpringSecurity #10] No2
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        log.debug("------------- PreFilter -------------");

        final String authHeader = request.getHeader(AUTHORIZATION); // Lấy giá trị của header Authorization từ yêu cầu HTTP.
        if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, "Bearer ")) { // Kiểm tra xem header có tồn tại và có bắt đầu bằng "Bearer " không. Nếu không, tiếp tục xử lý yêu cầu mà không thực hiện thêm bước nào.
            filterChain.doFilter(request, response);
            return;
        }
        final String jwt = authHeader.substring(7); // Cắt bỏ phần "Bearer " để lấy token JWT.
        final String userName = jwtService.extractUserName(jwt); // trích xuất tên người dùng từ token JWT.

        // Kiểm tra xem tên người dùng có hợp lệ và người dùng chưa được xác thực trong SecurityContext hay không.
        if (StringUtils.isNotEmpty(userName) && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = authRepository.findByUsername(userName).get(); // tải thông tin người dùng từ tên người dùng.

            if (jwtService.isTokenValid(jwt, userDetails)) { // Kiểm tra tính hợp lệ của token JWT bằng cách so sánh với thông tin người dùng

                // Cập nhật SecurityContext với thông tin đã xác thực.
                SecurityContext context = SecurityContextHolder.createEmptyContext();

                // Tạo một UsernamePasswordAuthenticationToken mới với thông tin người dùng và quyền hạn của họ.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); // Đặt các chi tiết bổ sung cho đối tượng authToken, chẳng hạn như địa chỉ IP và thông tin session.

                context.setAuthentication(authToken);
                SecurityContextHolder.setContext(context);
            }
        }

        filterChain.doFilter(request, response);
    }
}
