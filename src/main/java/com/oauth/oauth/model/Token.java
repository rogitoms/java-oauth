package com.oauth.oauth.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "tokens")
public class Token {
    
    @Id  // <-- Add primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "access_token", nullable = false, unique = true)
    private String accessToken;

    @Column(name = "access_token_expiry", nullable = false)
    private LocalDateTime accessTokenExpiry;

    @ManyToOne  // Many tokens belong to one user
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    // Builder pattern
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String accessToken;
        private LocalDateTime accessTokenExpiry;
        private User user;
        private boolean revoked;

        public Builder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public Builder accessTokenExpiry(LocalDateTime accessTokenExpiry) {
            this.accessTokenExpiry = accessTokenExpiry;
            return this;
        }

        public Builder user(User user) {
            this.user = user;
            return this;
        }

        public Builder revoked(boolean revoked) {
            this.revoked = revoked;
            return this;
        }

        public Token build() {
            Token token = new Token();
            token.accessToken = this.accessToken;
            token.accessTokenExpiry = this.accessTokenExpiry;
            token.user = this.user;
            token.revoked = this.revoked;
            return token;
        }
    }
}
