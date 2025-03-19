package com.oauth.oauth.util;

import java.security.SecureRandom;
import java.util.Base64;

public class JwtSecretGenerator {
    public static void main(String[] args) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[64];
        secureRandom.nextBytes(key);
        String jwtSecret = Base64.getEncoder().encodeToString(key);
        System.out.println("Your JWT secret:");
        System.out.println(jwtSecret);
    }
}