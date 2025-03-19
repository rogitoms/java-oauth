package com.oauth.oauth.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "auth_codes")
public class AuthCode {
    @Id
    private String code;
    
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private Client client;
    
    @Column(nullable = false)
    private String redirectUri;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "auth_code_scopes", joinColumns = @JoinColumn(name = "code"))
    @Column(name = "scope")
    private Set<String> scopes = new HashSet<>();
    
    @Column(nullable = false)
    private Instant createdAt;
    
    @Column(nullable = false)
    private Instant expiresAt;
    
    private boolean used;
    
    // Constructor
    public AuthCode() {
        this.code = UUID.randomUUID().toString(); // Ensure ID is set
        this.createdAt = Instant.now();
    }
    
    
    // Getters and Setters
    public String getCode() { return code; }
    
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    
    public Client getClient() { return client; }
    public void setClient(Client client) { this.client = client; }
    
    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
    
    public Set<String> getScopes() { return scopes; }
    public void setScopes(Set<String> scopes) { this.scopes = scopes; }
    
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    
    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }
    
    @Override
    public String toString() {
        return "AuthCode{" +
                "code='" + code + '\'' +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                ", used=" + used +
                '}';
    }
}