package com.oauth.oauth.service;

import com.oauth.oauth.model.AuthCode;
import com.oauth.oauth.model.Client;
import com.oauth.oauth.model.User;
import com.oauth.oauth.model.Token;
import com.oauth.oauth.model.Consent;
import com.oauth.oauth.repository.AuthCodeRepository;
import com.oauth.oauth.repository.UserRepository;
import com.oauth.oauth.repository.TokenRepository;
import com.oauth.oauth.repository.ConsentRepository;
import com.oauth.oauth.security.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;


@Service
public class AuthService {
    private final AuthCodeRepository authCodeRepository;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final ConsentRepository consentRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private static final int AUTH_CODE_VALIDITY_MINUTES = 10;

    public AuthService(AuthCodeRepository authCodeRepository, UserRepository userRepository,
                       TokenRepository tokenRepository,ConsentRepository consentRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.authCodeRepository = authCodeRepository;
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.consentRepository = consentRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @Transactional
    public String register(User user) {
        if (!user.getPassword().equals(user.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }
        
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User savedUser = userRepository.save(user);
        return savedUser.getUser_id().toString();
    }

    public String login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
            
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }
        
        return jwtUtil.generateToken(user);
    }

    @Transactional
    public String generateAuthCode(User user, Client client, String redirectUri) {
        AuthCode authCode = new AuthCode();
        //authCode.setCode(UUID.randomUUID().toString()); // Ensure a unique code is set
        authCode.setUser(user);
        authCode.setClient(client);
        authCode.setRedirectUri(redirectUri);
        authCode.setExpiresAt(Instant.now().plus(AUTH_CODE_VALIDITY_MINUTES, ChronoUnit.MINUTES));
        authCode.setUsed(false);
        authCode.setCreatedAt(Instant.now());

        AuthCode savedAuthCode = authCodeRepository.save(authCode);
        return savedAuthCode.getCode();
    }

    public Optional<AuthCode> validateAuthCode(String code) {
        return authCodeRepository.findByCodeAndUsedFalse(code)
                .filter(authCode -> authCode.getExpiresAt().isAfter(Instant.now()));
    }

    public void markAuthCodeAsUsed(String code) {
        authCodeRepository.findById(code).ifPresent(authCode -> {
            authCode.setUsed(true);
            authCodeRepository.save(authCode);
        });
    }
    @Transactional
    public String exchangeAuthCodeForToken(String code) {
        Optional<AuthCode> authCodeOpt = validateAuthCode(code);
        if (authCodeOpt.isEmpty()) {
            throw new RuntimeException("Invalid or expired authorization code");
        }
    
        AuthCode authCode = authCodeOpt.get();
        User user = authCode.getUser();
    
        // ✅ Generate Access Token
        String accessToken = jwtUtil.generateToken(user);
        LocalDateTime expiryTime = LocalDateTime.now().plusSeconds(jwtUtil.getJwtExpirationInMs() / 1000);
    
        // ✅ Save the token in the database
        Token token = new Token();
        token.setAccessToken(accessToken);
        token.setAccessTokenExpiry(expiryTime);
        token.setUser(user);
        token.setRevoked(false);
        
        tokenRepository.save(token); // ✅ Store in database
    
        // ✅ Mark Auth Code as Used
        markAuthCodeAsUsed(code);
    
        return accessToken;
    }
    
    /**@Transactional
    public String exchangeAuthCodeForToken(String code) {
        Optional<AuthCode> authCodeOpt = validateAuthCode(code);
    
        if (authCodeOpt.isEmpty()) {
            throw new RuntimeException("Invalid or expired authorization code");
        }
    
        AuthCode authCode = authCodeOpt.get();
        User user = authCode.getUser();
    
        // Generate Access Token
        String accessToken = jwtUtil.generateToken(user);
    
        // Save token to DB
        Token token = new Token();
        token.setAccessToken(accessToken);
        //token.setAccessTokenExpiry(LocalDateTime.now().plusSeconds(jwtUtil.getJwtExpirationInMs() / 1000));
        token.setUser(user);
        token.setRevoked(false);
    
        tokenRepository.save(token);  // Ensure token is stored in the database
    
        // Mark Auth Code as Used
        markAuthCodeAsUsed(code);
    
        return accessToken;
    }*/
    public boolean hasUserGivenConsent(User user, Client client) {
        return consentRepository.existsByUserAndClient(user, client);
    }
    
    @Transactional
    public void storeUserConsent(User user, Client client) {
        if (!hasUserGivenConsent(user, client)) {
            Consent consent = new Consent();
            
            // ✅ Use the new setters
            consent.setUser(user);
            consent.setClient(client);
            
            consentRepository.save(consent);
        }
    }

    
    }
