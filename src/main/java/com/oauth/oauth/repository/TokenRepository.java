package com.oauth.oauth.repository;

import com.oauth.oauth.model.Token;
import com.oauth.oauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByAccessToken(String accessToken);
    List<Token> findByUserAndRevokedFalse(User user);
}


/**package com.oauth.oauth.repository;

import com.oauth.oauth.model.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByAccessToken(String accessToken);
}*/