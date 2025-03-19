package com.oauth.oauth.controller;

import com.oauth.oauth.model.User;
import com.oauth.oauth.model.Client;
import com.oauth.oauth.repository.ClientRepository;
import com.oauth.oauth.repository.UserRepository;
import com.oauth.oauth.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie; 
import java.net.URI;
import com.oauth.oauth.service.OtpService;


@Controller
@RequestMapping("/auth")
public class UserController {
    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    
    public UserController(UserRepository userRepository, 
                          ClientRepository clientRepository, 
                          JwtUtil jwtUtil, 
                          PasswordEncoder passwordEncoder,
                          OtpService otpService) {
        this.userRepository = userRepository;
        this.clientRepository = clientRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.otpService = otpService;
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

   @PostMapping("/register")
    public String register(@ModelAttribute User user, 
                       RedirectAttributes redirectAttributes) {
    if (userRepository.findByEmail(user.getEmail()).isPresent()) {
        redirectAttributes.addFlashAttribute("error", "Email already registered");
        return "redirect:/auth/register";
    }

    user.setRole("user");//set default role to USER
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    userRepository.save(user);
    
    redirectAttributes.addFlashAttribute("message", "Registration successful");
    return "redirect:/auth/login";
}

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

@PostMapping("/login")
public String login(@RequestParam String email, 
                    @RequestParam String password, 
                    HttpServletRequest request, 
                    RedirectAttributes redirectAttributes) {
    log.info("Login attempt for email: {}", email);

    if (email == null || password == null) {
        redirectAttributes.addFlashAttribute("error", "Email and password are required");
        return "redirect:/auth/login";
    }

    try {
        // ✅ Authenticate User
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            redirectAttributes.addFlashAttribute("error", "Invalid credentials");
            return "redirect:/auth/login";
        }

        // ✅ Generate and Send OTP
        otpService.generateAndSendOtp(email);

        // ✅ Store user in session temporarily (without full authentication yet)
        HttpSession session = request.getSession();
        session.setAttribute("pendingUserEmail", email);

        log.info("OTP sent to user: {}", email);

        // ✅ Redirect to OTP verification page
        return "redirect:/auth/verify-otp";
    } catch (Exception e) {
        log.error("Login failed: {}", e.getMessage());
        redirectAttributes.addFlashAttribute("error", "Login failed: " + e.getMessage());
        return "redirect:/auth/login";
    }
}
    @GetMapping("/verify-otp")
    public String verifyOtpPage() {
        return "otp/otp";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam(required = false) String email, 
                            @RequestParam String otp, 
                            HttpServletRequest request, 
                            RedirectAttributes redirectAttributes) {
        if (email == null || email.isEmpty()) {
            email = (String) request.getSession().getAttribute("pendingUserEmail");
            if (email == null || email.isEmpty()) {
                log.error("❌ Email is missing from OTP verification request.");
                redirectAttributes.addFlashAttribute("error", "Session expired. Please log in again.");
                return "redirect:/auth/login";
            }
        }
        
        log.info("Verifying OTP for email: {}", email);
    

    boolean isValid = otpService.validateOtp(email, otp);

    if (!isValid) {
        redirectAttributes.addFlashAttribute("error", "Invalid OTP");
        return "redirect:/auth/verify-otp";
    }

    Optional<User> userOptional = userRepository.findByEmail(email);
    if (userOptional.isEmpty()) {
        log.error("❌ User not found in verifyOtp for email: {}", email);
        redirectAttributes.addFlashAttribute("error", "User session expired. Please log in again.");
        return "redirect:/auth/login";
    }
    User user = userOptional.get();


    HttpSession session = request.getSession();
    session.setAttribute("authenticatedUser", user.getEmail());

    // ✅ Check if the user is an Admin
    boolean isAdmin = user.getRoles().stream()
        .anyMatch(role -> role.getName().equalsIgnoreCase("ROLE_ADMIN") 
                       || role.getName().equalsIgnoreCase("ADMIN"));

    if (isAdmin) {
        log.info("Admin login successful, redirecting to dashboard");
        return "redirect:/admin/dashboard";
    }

    // ✅ Check if user has a registered client
    Optional<Client> firstClientOpt = clientRepository.findAll().stream().findFirst();

    if (firstClientOpt.isPresent()) {
        Client client = firstClientOpt.get();
        String redirectUri = client.getRedirectUris().iterator().next();

        log.info("Redirecting user to OAuth authorization with client: {}", client.getClientId());

        return "redirect:/auth/authorize?client_id=" + client.getClientId()
             + "&response_type=code&redirect_uri=" + redirectUri;
    } else {
        log.info("No clients exist, redirecting to client registration");
        return "redirect:/client/register";
    }
}


    @PostMapping("/resend-otp")
    public String resendOtp(HttpServletRequest request, RedirectAttributes redirectAttributes) {
        String email = (String) request.getSession().getAttribute("pendingUserEmail");
        
        if (email == null || email.isEmpty()) {
            log.error("❌ Email is missing for OTP resend request");
            redirectAttributes.addFlashAttribute("error", "Session expired. Please log in again.");
            return "redirect:/auth/login";
        }
        
        log.info("Resending OTP for email: {}", email);
        
        boolean success = otpService.resendOtp(email);
        
        if (success) {
            redirectAttributes.addFlashAttribute("message", "OTP has been resent to your email");
        } else {
            redirectAttributes.addFlashAttribute("error", "Failed to resend OTP. Please try logging in again.");
        }
        
        return "redirect:/auth/verify-otp";
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session != null) {
        session.invalidate();  // ❌ Destroy session
        log.info("User logged out successfully.");
    }

    // ❌ Expire the access token cookie
    ResponseCookie deleteCookie = ResponseCookie.from("access_token", "")
            .httpOnly(true)
            .secure(true)  // Enable only for HTTPS
            .path("/")
            .maxAge(0)  // Expire immediately
            .build();

    return ResponseEntity.status(HttpStatus.FOUND)
            .header(HttpHeaders.SET_COOKIE, deleteCookie.toString())  // ❌ Remove access token
            .location(URI.create("http://localhost:8080/auth/login"))  // ✅ Redirect to landing page
            .build();
}
}
