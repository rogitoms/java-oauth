package com.oauth.oauth.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final String secretKey = "zj6K/Q9o1pzusfg9JiBZXURli2OmUCxsQaiEypOqNWU="; // Change to env variable

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        HttpSession session = request.getSession(false);
        if (session != null) {
            String accessToken = (String) session.getAttribute("accessToken");
            
            if (accessToken != null) {
                // Validate token and create authentication
                try {
                    Claims claims = Jwts.parser()
                            .setSigningKey(secretKey) 
                            .parseClaimsJws(accessToken)
                            .getBody();
                    
                    String username = claims.getSubject();
                    
                    // Create authentication object
                    UsernamePasswordAuthenticationToken authentication = 
                            new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
                    
                    // Set authentication in context
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } catch (Exception e) {
                    logger.error("Token validation failed", e);
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
