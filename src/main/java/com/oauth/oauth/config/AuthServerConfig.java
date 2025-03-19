/**package com.oauth.oauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;


import java.util.UUID;

@Configuration
public class AuthServerConfig {

        @Bean
        public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
            OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
            
            http
                .csrf(csrf -> csrf.disable()) // ✅ CSRF is disabled explicitly
                .apply(authorizationServerConfigurer);
        
            http
                .securityMatcher("/auth/**")
                .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/auth/register", "/auth/login", "/auth/token", "/auth/authorize",
                                     "/auth/jwks", "/auth/revoke", "/auth/introspect")
                    .permitAll()
                    .anyRequest().authenticated()
                );
        
            return http.build();
        }
        

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080") // 🔹 Change in production
                .authorizationEndpoint("/auth/authorize")
                .tokenEndpoint("/auth/token")
                .jwkSetEndpoint("/auth/jwks")
                .tokenRevocationEndpoint("/auth/revoke")
                .tokenIntrospectionEndpoint("/auth/introspect")
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-id")
                .clientSecret("{noop}client-secret") // 🔹 FIX: Encode client secret properly
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/login/oauth2/code/custom-client")
                .scope(OidcScopes.OPENID)
                .scope("profile")
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }
}*/




/** @GetMapping("/authorize")
    public ResponseEntity<?> authorizeClient(
        @RequestParam String client_id,
        @RequestParam String response_type,
        @RequestParam String redirect_uri,
        @RequestParam(required = false) String state,
        HttpServletRequest request) {

    try {
        if (!"code".equals(response_type)) {
            throw new InvalidRequestException("Unsupported response type: " + response_type);
        }

        HttpSession session = request.getSession();

        // ✅ Generate and Store a Random CSRF Protection State
        String generatedState = UUID.randomUUID().toString();
        session.setAttribute("oauth_state", generatedState);

        Client client = validateClient(client_id, redirect_uri);
        User user = userRepository.findByEmail(
                (String) session.getAttribute("authenticatedUser"))
                .orElseThrow(() -> new AuthenticationException("User not found"));

        // ✅ Generate Authorization Code
        String authCode = authService.generateAuthCode(user, client, redirect_uri);

        log.info("Generated auth code: {} for user: {}, redirecting to: {}", authCode, user.getEmail(), redirect_uri);

        // ✅ Redirect to Client Callback with state
        URI redirectLocation = UriComponentsBuilder.fromUriString(redirect_uri)
                .queryParam("code", authCode)
                .queryParam("state", generatedState)  // Include the generated state
                .build()
                .toUri();

        return ResponseEntity.status(HttpStatus.FOUND).location(redirectLocation).build();

    } catch (Exception e) {
        log.error("Authorization error: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Authorization failed"));
    }
}*/