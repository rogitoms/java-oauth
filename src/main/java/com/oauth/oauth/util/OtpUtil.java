package com.oauth.oauth.util;

import java.security.SecureRandom;
import java.time.LocalDateTime;

public class OtpUtil {
    private static final SecureRandom random = new SecureRandom();

    public static String generateOtp() {
        int otp = 100000 + random.nextInt(900000); // Generate 6-digit OTP
        return String.valueOf(otp);
    }

    public static LocalDateTime generateExpiryTime() {
        return LocalDateTime.now().plusMinutes(60); // OTP valid for 60 minutes
    }
}
