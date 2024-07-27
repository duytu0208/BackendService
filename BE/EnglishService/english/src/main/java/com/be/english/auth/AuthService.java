package com.be.english.auth;

import com.be.english.auth.db.AuthEntity;
import com.be.english.auth.db.AuthRepository;
import com.be.english.common.AbstractEntity;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthRepository authRepository;

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
                .password(request.password())
                .status(AbstractEntity.Status.ACTIVE)
                .signupData(signupRequestJson)
                .build();

        signupEntity = authRepository.save(signupEntity);

        return signupEntity.getId();
    }
}
