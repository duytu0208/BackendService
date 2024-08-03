package com.be.english.auth;

import com.be.english.auth.db.TokenEntity;
import com.be.english.auth.db.TokenRepository;
import com.be.english.common.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final TokenRepository tokenRepository;


    public Long save(TokenEntity tokenEntity) {
        Optional<TokenEntity> tokenEntityOptional = tokenRepository.findByUsername(tokenEntity.getUsername());
        if (tokenEntityOptional.isEmpty()) {
            tokenRepository.save(tokenEntity);
            return tokenEntity.getId();
        } else {
            TokenEntity currentToken = tokenEntityOptional.get();
            currentToken.setAccessToken(tokenEntity.getAccessToken());
            currentToken.setRefreshToken(tokenEntity.getRefreshToken());

            tokenRepository.save(currentToken);
            return currentToken.getId();
        }
    }

    public TokenEntity findByUserName(String username) {
        return tokenRepository.findByUsername(username).orElseThrow(() -> new ResourceNotFoundException("Token not found"));
    }

    public void delete(TokenEntity currentToken) {
        tokenRepository.delete(currentToken);
    }
}
