package com.be.english.auth;

import com.be.english.common.Platform;
import lombok.Builder;
import lombok.Getter;

import java.io.Serializable;

public class Auth {

    public record SignUpRequest(String userName, String password) {}

    /**
     *
     * @param userName
     * @param password
     * @param platform Để biết user đang login từ thiết bị nào, Để trả về token tương ứng và các thông tin liên quan tới web hoặc mobile
     * @param version Với mobi thì họ cần version để biết họ request các api thuộc ver đó nếu người dùng k update app mobi của họ
     * @param deviceToken Khi viết api cho mobi, ta hay có chức năng push notification đến cho FE. Thì mỗi thiết bị sẽ có 1 deviceToken => Cần lưu nó vào DB và trả về ở thời điểm login
     */
    public record SignInRequest(String userName, String password, Platform platform, String version, String deviceToken) {}

    @Getter
    @Builder
    public static class SignInResponse implements Serializable {

        private String accessToken;
        private String refreshToken;

        private Long userId;
        private String phoneNumber;
        private String role;
        // more over ...
    }

}
