package com.oauth.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.oauth.oauth.model.User;
import com.oauth.oauth.repository.UserRepository;
import com.oauth.oauth.util.OtpGenerator;

import java.time.LocalDateTime;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class OtpService {
    private static final Logger log = LoggerFactory.getLogger(OtpService.class);

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private EmailService emailService;
    
    @Autowired
    private OtpGenerator otpGenerator;
    
    // OTP validity in minutes
    private static final int OTP_VALIDITY_MINUTES = 5;
    
    public void generateAndSendOtp(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            
            // Generate OTP
            String otp = otpGenerator.generateOtp();
            
            log.info("📌 Generating OTP for email: {}", email);
            log.info("📌 OTP: {} | Expiry Time: {}", otp, LocalDateTime.now().plusMinutes(OTP_VALIDITY_MINUTES));

            user.setOtp(otp);
            user.setOtpExpiryTime(LocalDateTime.now().plusMinutes(OTP_VALIDITY_MINUTES));

            userRepository.save(user);  // 🔹 Ensure this executes without errors

            log.info("📌 OTP saved successfully for: {}", email);
            emailService.sendOtpEmail(email, otp);

        }
    }
    
    public boolean validateOtp(String email, String otp) {
        Optional<User> userOptional = userRepository.findByEmail(email);
    
        if (userOptional.isPresent()) {
            User user = userOptional.get();
    
            log.info("📌 Stored OTP: {}", user.getOtp());
            log.info("📌 Entered OTP: {}", otp);
            log.info("📌 Expiry Time: {}", user.getOtpExpiryTime());
            log.info("📌 Current Time: {}", LocalDateTime.now());
    
            if (user.getOtp() == null) {
                log.error("❌ No OTP found for email: {}", email);
                return false;
            }
    
            if (!user.getOtp().equals(otp)) {
                log.error("❌ Incorrect OTP entered for email: {}", email);
                return false;
            }
    
            if (user.getOtpExpiryTime() == null || LocalDateTime.now().isAfter(user.getOtpExpiryTime())) {
                log.error("❌ OTP for email {} has expired", email);
                return false;
            }
    
            // ✅ Clear OTP after successful validation
            user.setOtp(null);
            user.setOtpExpiryTime(null);
            userRepository.save(user);
    
            log.info("✅ OTP verification successful for: {}", email);
            return true;
        }
    
        log.error("❌ User not found for email: {}", email);
        return false;
    }
    public boolean resendOtp(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            
            // Generate new OTP
            String otp = otpGenerator.generateOtp();
            
            log.info("📌 Resending OTP for email: {}", email);
            log.info("📌 New OTP: {} | Expiry Time: {}", otp, LocalDateTime.now().plusMinutes(OTP_VALIDITY_MINUTES));
            
            // Update user with new OTP
            user.setOtp(otp);
            user.setOtpExpiryTime(LocalDateTime.now().plusMinutes(OTP_VALIDITY_MINUTES));
            
            userRepository.save(user);
            
            // Send the new OTP via email
            emailService.sendOtpEmail(email, otp);
            
            log.info("✅ OTP resent successfully for: {}", email);
            return true;
        }
        
        log.error("❌ Failed to resend OTP: User not found for email: {}", email);
        return false;
    }

}
