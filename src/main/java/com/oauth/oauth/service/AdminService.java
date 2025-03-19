package com.oauth.oauth.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.oauth.oauth.repository.UserRepository;
import com.oauth.oauth.model.User;
import com.oauth.oauth.repository.AuthCodeRepository;
import com.oauth.oauth.repository.ConsentRepository;

@Service
public class AdminService {

    private final UserRepository userRepository;
    private final AuthCodeRepository authCodeRepository;
    private final ConsentRepository ConsentRepository;


    public AdminService(UserRepository userRepository,
                        AuthCodeRepository authCodeRepository,
                        ConsentRepository ConsentRepository) {
        this.userRepository = userRepository;
        this.authCodeRepository = authCodeRepository;
        this.ConsentRepository = ConsentRepository;
    }

    @Transactional
    public void deleteUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        authCodeRepository.deleteByUser(user); // Delete associated auth codes
        ConsentRepository.deleteByUser(user);
        userRepository.delete(user);
    }
}
