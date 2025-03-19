package com.oauth.oauth.controller;

import com.oauth.oauth.model.User;
import com.oauth.oauth.model.AuthCode;
import com.oauth.oauth.model.Client;
import com.oauth.oauth.repository.ClientRepository;
import com.oauth.oauth.repository.UserRepository;
import com.oauth.oauth.service.AuthService;
import com.oauth.oauth.service.UserService;
import com.oauth.oauth.security.JwtUtil;
import com.oauth.oauth.exception.AuthenticationException;
import com.oauth.oauth.exception.InvalidRequestException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import java.util.List;


import java.util.Map;
import java.util.Optional;
import java.net.URI;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.util.UriComponentsBuilder;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;

import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;

import java.time.Duration;
import org.springframework.http.ResponseCookie;


@Controller
@RequestMapping("/auth")
public class AuthController {
    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String INVALID_REQUEST = "Invalid request parameters";
    private static final int MAX_AUTHORIZATION_ATTEMPTS = 5;
    
    private final AuthService authService;
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    
    public AuthController(
            AuthService authService, 
            UserRepository userRepository, 
            ClientRepository clientRepository, 
            JwtUtil jwtUtil,
            PasswordEncoder passwordEncoder,
            UserService userService) {
        this.authService = authService;
        this.userRepository = userRepository;
        this.clientRepository = clientRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
         this.userService = userService;
    }
    
    @GetMapping("/authorize")
    public ResponseEntity<?> authorizeClient(
            @RequestParam String client_id,
            @RequestParam String response_type,
            @RequestParam String redirect_uri,
            @RequestParam(required = false) String state,
            HttpServletRequest request,
            HttpSession session) {
    
        try {
            if (!"code".equals(response_type)) {
                throw new InvalidRequestException("Unsupported response type: " + response_type);
            }
    
            // ✅ Generate and store CSRF protection state
            String generatedState = UUID.randomUUID().toString();
            session.setAttribute("oauth_state", generatedState);
    
            Client client = validateClient(client_id, redirect_uri);
            User user = userRepository.findByEmail(
                    (String) session.getAttribute("authenticatedUser"))
                    .orElseThrow(() -> new AuthenticationException("User not found"));
    
            // ✅ Check if user has already given consent
            boolean hasGivenConsent = authService.hasUserGivenConsent(user, client);
            if (!hasGivenConsent) {
                String consentHtml = """
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Authorization Request</title>
                        <style>
                            body {
                                font-family: Arial, sans-serif;
                                max-width: 600px;
                                margin: 2rem auto;
                                padding: 2rem;
                                border-radius: 8px;
                                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                                line-height: 1.6;
                                background-color: #ffffff;
                            }
                            h2 {
                                color: #333;
                                margin-top: 0;
                                border-bottom: 1px solid #eee;
                                padding-bottom: 0.5rem;
                            }
                            .app-info {
                                background-color: #f8f9fa;
                                padding: 1rem;
                                border-radius: 4px;
                                margin-bottom: 1.5rem;
                            }
                            .scope-list {
                                margin: 1rem 0;
                                padding-left: 0;
                            }
                            .scope-list li {
                                list-style: none;
                                padding: 0.3rem 0;
                                background-color: #e9ecef;
                                padding: 8px;
                                border-radius: 5px;
                                margin-bottom: 5px;
                            }
                            .buttons {
                                display: flex;
                                gap: 1rem;
                                margin-top: 1.5rem;
                            }
                            .btn {
                                padding: 0.5rem 1.5rem;
                                border-radius: 4px;
                                border: none;
                                cursor: pointer;
                                font-weight: bold;
                            }
                            .btn-approve {
                                background-color: #4CAF50;
                                color: white;
                            }
                            .btn-deny {
                                background-color: #f44336;
                                color: white;
                            }
                            .btn:hover {
                                opacity: 0.9;
                            }
                        </style>
                    </head>
                    <body>
                        <h2>Authorization Request</h2>
                        
                        <div class="app-info">
                            <p><strong>%s</strong> is requesting access to your account.</p>
                        </div>
                        
                        <p><strong>Requested Permissions:</strong></p>
                        <ul class="scope-list">%s</ul>

                        <form action='/auth/consent' method='post'>
                            <input type='hidden' name='client_id' value='%s' />
                            <input type='hidden' name='state' value='%s' />
                            <input type='hidden' name='redirect_uri' value='%s' />

                            <div class="buttons">
                                <button type='submit' name='consent' value='approve' class="btn btn-approve">Approve</button>
                                <button type='submit' name='consent' value='deny' class="btn btn-deny">Deny</button>
                            </div>
                        </form>
                    </body>
                    </html>
                    """.formatted(
                        client.getClientName(),
                        client.getScope().replace(" ", "</li><li>"),
                        client.getClientId(),
                        generatedState,
                        redirect_uri
                    );
    
                return ResponseEntity.ok()
                        .contentType(MediaType.TEXT_HTML)
                        .body(consentHtml);
            }
    
            // ✅ Generate authorization code if consent already given
            String authCode = authService.generateAuthCode(user, client, redirect_uri);
    
            log.info("Generated auth code: {} for user: {}, redirecting to: {}", authCode, user.getEmail(), redirect_uri);
    
            // ✅ Redirect to Client Callback with state
            URI redirectLocation = UriComponentsBuilder.fromUriString(redirect_uri)
                    .queryParam("code", authCode)
                    .queryParam("state", generatedState)
                    .build()
                    .toUri();
    
            return ResponseEntity.status(HttpStatus.FOUND).location(redirectLocation).build();
    
        } catch (Exception e) {
            log.error("Authorization error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Authorization failed"));
        }
    }
    
    @PostMapping("/consent")
    public ResponseEntity<?> handleConsent(
            @RequestParam String client_id,
            @RequestParam String state,
            @RequestParam String redirect_uri,
            @RequestParam String consent,
            HttpSession session) {

        String userEmail = (String) session.getAttribute("authenticatedUser");
        if (userEmail == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated"));
        }

        Optional<User> userOpt = userRepository.findByEmail(userEmail);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not found"));
        }
        User user = userOpt.get();

        Client client = validateClient(client_id, redirect_uri);

        if ("deny".equals(consent)) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create("http://localhost:5000"))
                    .build();
        }
        
        // ✅ Store consent in the database
        authService.storeUserConsent(user, client);

        // ✅ Generate authorization code
        String authCode = authService.generateAuthCode(user, client, redirect_uri);

        log.info("User consented, issuing auth code: {}", authCode);

        // ✅ Redirect with auth code
        URI redirectLocation = UriComponentsBuilder.fromUriString(redirect_uri)
                .queryParam("code", authCode)
                .queryParam("state", state)
                .build()
                .toUri();

        return ResponseEntity.status(HttpStatus.FOUND).location(redirectLocation).build();
    }

@GetMapping("/redirect")
public ResponseEntity<?> handleRedirect(
    @RequestParam String code,
    @RequestParam(required = false) String state,
    HttpSession session) {

    log.info("Received authorization code: {}", code);

    // Validate state parameter (prevent CSRF attacks)
    String storedState = (String) session.getAttribute("oauth_state");
    if (storedState == null || !storedState.equals(state)) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid state parameter"));
    }
    session.removeAttribute("oauth_state");

    // Check if user is authenticated
    String userEmail = (String) session.getAttribute("authenticatedUser");
    if (userEmail == null) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "User not authenticated"));
    }

    // Fetch user
    Optional<User> userOpt = userRepository.findByEmail(userEmail);
    if (userOpt.isEmpty()) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "User not found"));
    }
    User user = userOpt.get();

    // Fetch OAuth client
    List<Client> clients = clientRepository.findAll(); // Fetch all clients
    if (clients.isEmpty()) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "No clients available in the database"));
    }
    
    Client client = clients.get(0); // Pick the first available client
    
    Set<String> redirectUris = client.getRedirectUris();
    if (redirectUris.isEmpty()) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "No valid redirect URI for this client"));
    }
    
    String redirectUri = redirectUris.iterator().next(); // Pick the first redirect URI
    

    // Exchange authorization code for access token
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    params.add("grant_type", "authorization_code");
    params.add("code", code);
    params.add("redirect_uri", redirectUri);
    params.add("client_id", client.getClientId());
    params.add("client_secret", client.getClientSecret());

    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

    try {
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:8080/auth/token", request, Map.class);

        Map<String, Object> responseBody = response.getBody();
        if (responseBody != null && responseBody.containsKey("access_token")) {
            String accessToken = (String) responseBody.get("access_token");

            // Store token in an HTTP-only secure cookie
            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", accessToken)
                    .httpOnly(true)  // Prevent JavaScript access
                    .secure(true)    // Enable for HTTPS (set to false for local development)
                    .path("/")       // Available for the whole application
                    .maxAge(Duration.ofHours(1)) // Expiration time
                    .build();

            log.info("User authenticated, redirecting to dashboard...");

            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.SET_COOKIE, accessTokenCookie.toString())  // Set the secure cookie
                    .location(URI.create("http://localhost:5000/dashboard"))  // Redirect without token in URL
                    .build();
        }
    } catch (Exception e) {
        log.error("Token exchange failed: {}", e.getMessage());
    }

    return ResponseEntity.status(HttpStatus.FOUND)
            .location(URI.create("/auth/login"))
            .build();
}

  
   @PostMapping("/token")  
    public ResponseEntity<?> exchangeToken(
    @RequestParam String grant_type,
    @RequestParam String code,
    @RequestParam String redirect_uri,
    @RequestParam String client_id,
    @RequestParam String client_secret,
    HttpSession session) {

    try {
        if (!"authorization_code".equals(grant_type)) {
            throw new InvalidRequestException("Unsupported grant type");
        }

        // ✅ Validate the authorization code
        Optional<AuthCode> authCodeOpt = authService.validateAuthCode(code);
        if (authCodeOpt.isEmpty()) {
            log.error("Invalid or expired authorization code: {}", code);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid or expired authorization code"));
        }

        AuthCode authCode = authCodeOpt.get();

        // ✅ Validate client
        Client client = validateClient(client_id, redirect_uri);
        if (!authCode.getClient().getClientId().equals(client_id)) {
            throw new InvalidRequestException("Authorization code was not issued to this client");
        }

        if (!authCode.getRedirectUri().equals(redirect_uri)) {
            throw new InvalidRequestException("Redirect URI mismatch");
        }

        // ✅ Generate access token
        String accessToken = jwtUtil.generateToken(authCode.getUser());

        // ✅ Mark the authorization code as used
        authService.markAuthCodeAsUsed(code);

        // ✅ Store token in session
        session.setAttribute("accessToken", accessToken);

        log.info("Token exchanged successfully for user {}", authCode.getUser().getEmail());

           // ✅ Check if the user is an Admin and redirect
        /**boolean isAdmin = authCode.getUser().getRoles().stream()
           .anyMatch(role -> role.getName().equalsIgnoreCase("ROLE_ADMIN") 
                          || role.getName().equalsIgnoreCase("ADMIN"));

       if (isAdmin) {
           log.info("Admin login detected, redirecting to admin dashboard");
           return ResponseEntity.status(HttpStatus.FOUND)
                   .location(URI.create("/admin/dashboard"))
                   .build();
       }*/

        return ResponseEntity.ok(Map.of(
                "access_token", accessToken,
                "token_type", "Bearer",
                "expires_in", 3600
        ));

    } catch (Exception e) {
        log.error("Token exchange error: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Token exchange failed"));
    }
}

    /**private Client validateClient(String clientId, String redirectUri) {
        Client client = clientRepository.findByClientId(clientId);
        if (client == null) {
            throw new InvalidRequestException("Invalid client_id");
        }
        
        if (!client.getRedirectUris().contains(redirectUri)) {
            throw new InvalidRequestException("Invalid redirect_uri");
        }
        
        return client;
    }*/
    private Client validateClient(String clientId, String redirectUri) {
        return clientRepository.findByClientId(clientId)
            .filter(client -> client.getRedirectUris().contains(redirectUri))
            .orElseThrow(() -> new InvalidRequestException("Invalid client_id or redirect_uri"));
    }
    
    
    private ResponseEntity<?> createErrorResponse(
            HttpStatus status, 
            String error, 
            String description) {
        return ResponseEntity
            .status(status)
            .body(Map.of(
                "error", error,
                "error_description", description
            ));
    }
}