package com.oauth.oauth.repository;

import com.oauth.oauth.model.Client;
import com.oauth.oauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.List;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ClientRepository extends JpaRepository<Client, Long> {
    //Client findByClientId(String clientId);
    Optional<Client> findByClientId(String clientId);
    boolean existsByOwnerEmail(String email);
    Optional<Client> findByUsers(User user);
    List<Client> findByOwnerEmail(String email);
    Optional<Client> findByClientName(String clientName);
    //Optional<Client> findClientWithRedirectUris(@Param("clientId") String clientId);

    @Modifying
    @Transactional
    void deleteByClientId(String clientId);
}