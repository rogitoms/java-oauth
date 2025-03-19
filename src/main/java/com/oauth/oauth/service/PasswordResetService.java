package com.oauth.oauth.service;

import com.oauth.oauth.model.PasswordResetToken;
import com.oauth.oauth.model.User;
import com.oauth.oauth.repository.PasswordResetTokenRepository;
import com.oauth.oauth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Random;

@Service
public class PasswordResetService {
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordResetTokenRepository passwordresettokenRepository;
    
    @Autowired
    private EmailService emailService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public boolean requestPasswordReset(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        
        if (userOptional.isPresent()) {
            // Generate a 6-digit numeric token
            String token = generateOTP();
            
            // Check if a token already exists for this email
            Optional<PasswordResetToken> existingToken = passwordresettokenRepository.findByEmail(email);
            existingToken.ifPresent(passwordresettokenRepository::delete);
            
            // Create and save a new token
            PasswordResetToken passwordResetToken = new PasswordResetToken(token, email);
            passwordresettokenRepository.save(passwordResetToken);
            
            // Send email with token
            emailService.sendPasswordResetEmail(email, token);
            
            return true;
        }
        
        return false;
    }
    
    public boolean validateOTP(String email, String token) {
        Optional<PasswordResetToken> tokenOptional = passwordresettokenRepository.findByToken(token);
        
        if (tokenOptional.isPresent()) {
            PasswordResetToken resetToken = tokenOptional.get();
            
            if (resetToken.getEmail().equals(email) && !resetToken.isUsed() && !resetToken.isExpired()) {
                return true;
            }
        }
        
        return false;
    }
    
    public boolean resetPassword(String email, String token, String newPassword) {
        Optional<PasswordResetToken> tokenOptional = passwordresettokenRepository.findByToken(token);
        
        if (tokenOptional.isPresent()) {
            PasswordResetToken resetToken = tokenOptional.get();
            
            if (resetToken.getEmail().equals(email) && !resetToken.isUsed() && !resetToken.isExpired()) {
                Optional<User> userOptional = userRepository.findByEmail(email);
                
                if (userOptional.isPresent()) {
                    User user = userOptional.get();
                    user.setPassword(passwordEncoder.encode(newPassword));
                    userRepository.save(user);
                    
                    // Mark token as used
                    resetToken.setUsed(true);
                    passwordresettokenRepository.save(resetToken);
                    
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private String generateOTP() {
        Random random = new Random();
        int otp = 100000 + random.nextInt(900000);
        return String.valueOf(otp);
    }
}
