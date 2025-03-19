package com.oauth.oauth.controller;

import com.oauth.oauth.model.User;
import com.oauth.oauth.service.UserService;
import com.oauth.oauth.security.JwtUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping; 
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CookieValue;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
@RequestMapping("/api")
public class ApiController {

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private static final Logger log = LoggerFactory.getLogger(ApiController.class);

    public ApiController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

@GetMapping("/dashboard")
public String dashboard(
        @CookieValue(name = "access_token", required = false) String token, 
        Model model, HttpServletResponse response) {

    // Prevent browser caching
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response.setHeader("Pragma", "no-cache");
    response.setHeader("Expires", "0");

    if (token == null || token.isEmpty()) {
        return "redirect:/auth/login";  // Redirect if no token found
    }

    try {
        String userEmail = jwtUtil.extractEmail(token);
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        model.addAttribute("user", user);
        return "dashboard";  // ✅ Load dashboard page (Thymeleaf)
    } catch (Exception e) {
        log.error("Error verifying access token: {}", e.getMessage());
        return "redirect:/auth/login";  // Redirect on failure
    }
}

   // @GetMapping("/userinfo")
   @GetMapping("/userinfo")
public ResponseEntity<?> getUserInfo(@CookieValue(name = "access_token", required = false) String token) {
    if (token == null || token.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Missing access token"));
    }

    try {
        String userEmail = jwtUtil.extractEmail(token);
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(Map.of(
            "firstName", user.getFirstName(),
            "lastName", user.getLastName(),
            "email", user.getEmail()
           
        ));

    } catch (Exception e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid token"));
    }
}

}
