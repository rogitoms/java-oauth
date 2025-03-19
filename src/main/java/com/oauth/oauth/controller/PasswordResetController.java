package com.oauth.oauth.controller;

import com.oauth.oauth.service.PasswordResetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class PasswordResetController {
@Autowired
private PasswordResetService passwordResetService;

@GetMapping("/forgot-password")
public String showForgotPasswordForm() {
    return "password/forgot-password";
}

@PostMapping("/forgot-password")
public String processForgotPassword(@RequestParam("email") String email, Model model) {
    boolean emailSent = passwordResetService.requestPasswordReset(email);
    
    if (emailSent) {
        model.addAttribute("message", "We have sent a reset code to your email. Please check.");
    } else {
        model.addAttribute("error", "Email not found.");
    }
    
    return "password/reset-password";
}

@GetMapping("/reset-password")
public String showResetPasswordForm(@RequestParam("email") String email, Model model) {
    model.addAttribute("email", email);
    return "password/reset-password";
}

@PostMapping("/validate-otp")
public String validateOTP(@RequestParam("email") String email, 
                          @RequestParam("token") String token, 
                          Model model) {
    boolean isValid = passwordResetService.validateOTP(email, token);
    
    if (isValid) {
        model.addAttribute("email", email);
        model.addAttribute("token", token);
        return "password/new-password";
    } else {
        model.addAttribute("error", "Invalid or expired code.");
        model.addAttribute("email", email);
        return "password/reset-password";
    }
}

@PostMapping("/reset-password")
public String resetPassword(@RequestParam("email") String email,
                            @RequestParam("token") String token,
                            @RequestParam("password") String password,
                            @RequestParam("confirmPassword") String confirmPassword,
                            Model model) {
    
    if (!password.equals(confirmPassword)) {
        model.addAttribute("error", "Passwords do not match.");
        model.addAttribute("email", email);
        model.addAttribute("token", token);
        return "password/new-password";
    }
    
    boolean success = passwordResetService.resetPassword(email, token, password);
    
    if (success) {
        model.addAttribute("message", "Password has been reset successfully. You can now login with your new password.");
        return "password/reset-success";
    } else {
        model.addAttribute("error", "Failed to reset password. Please try again.");
        model.addAttribute("email", email);
        return "password/reset-password";
    }
}
}
