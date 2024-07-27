package com.be.english.auth;

import com.be.english.common.ResponseSuccess;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseSuccess signup(@RequestBody Auth.SignUpRequest signUpRequest) {
        return new ResponseSuccess(HttpStatus.CREATED, "Created user", authService.signup(signUpRequest));
    }
}
