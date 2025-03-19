package com.oauth.oauth.repository;

import com.oauth.oauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.jpa.repository.Modifying;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    //Optional<User> findByResetToken(String resetToken);
    
    @Modifying
    @Transactional
    void deleteByEmail(String email);

}
