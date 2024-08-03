package com.be.english.auth.db;


import com.be.english.common.AbstractEntity;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Builder
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "app_signup")
public class AuthEntity extends AbstractEntity<Long> implements UserDetails {
    /**
     * TODO [SpringSecurity #1] implements UserDetails of SpringSecurity
     * Trong Spring Security, UserDetails là một interface đại diện cho các thông tin về người dùng,
     * được sử dụng bởi Spring Security để xác thực và phân quyền.
     * Interface này định nghĩa một số phương thức cần thiết để lấy thông tin
     * về người dùng như tên đăng nhập, mật khẩu, quyền hạn, tình trạng tài khoản, v.v.
     *
     * Dưới đây là một số phương thức quan trọng của interface UserDetails:
     *
     * String getUsername(): Trả về tên đăng nhập của người dùng.
     * String getPassword(): Trả về mật khẩu của người dùng.
     * Collection<? extends GrantedAuthority> getAuthorities(): Trả về danh sách các quyền hạn của người dùng.
     * boolean isAccountNonExpired(): Kiểm tra xem tài khoản có hết hạn hay không.
     * boolean isAccountNonLocked(): Kiểm tra xem tài khoản có bị khóa hay không.
     * boolean isCredentialsNonExpired(): Kiểm tra xem thông tin xác thực (mật khẩu) có hết hạn hay không.
     * boolean isEnabled(): Kiểm tra xem tài khoản có được kích hoạt hay không.
     */

    @Column(name = "user_name")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    private Status status;

    //    @Column(name = "signup_data", columnDefinition = "jsonb", nullable = false)
    @Column(name = "signup_data")
    private String signupData;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
