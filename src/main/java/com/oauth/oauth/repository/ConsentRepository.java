package com.oauth.oauth.repository;

import com.oauth.oauth.model.Client;
import com.oauth.oauth.model.User;
import com.oauth.oauth.model.Consent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.jpa.repository.Modifying;

public interface ConsentRepository extends JpaRepository<Consent, Long> {
    boolean existsByUserAndClient(User user, Client client);
    @Transactional
    void deleteByUser(User user);
    void deleteByClient(Client client);
}
