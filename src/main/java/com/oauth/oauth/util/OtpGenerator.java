package com.oauth.oauth.util;

import org.springframework.stereotype.Component;
import java.security.SecureRandom;

@Component
public class OtpGenerator {
    
    private static final int OTP_LENGTH = 6;
    private static final String OTP_CHARS = "0123456789";
    private SecureRandom random = new SecureRandom();
    
    public String generateOtp() {
        StringBuilder otp = new StringBuilder(OTP_LENGTH);
        
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(OTP_CHARS.charAt(random.nextInt(OTP_CHARS.length())));
        }
        
        return otp.toString();
    }
}

