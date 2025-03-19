package com.oauth.oauth.repository;

import com.oauth.oauth.model.AuthCode;
import com.oauth.oauth.model.User;
import com.oauth.oauth.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.jpa.repository.Modifying;

public interface AuthCodeRepository extends JpaRepository<AuthCode, String> {
    Optional<AuthCode> findByCodeAndUsedFalse(String code);
    @Modifying
    @Transactional
    void deleteByUser(User user);
    void deleteByClient(Client client);
}