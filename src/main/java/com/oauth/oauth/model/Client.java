package com.oauth.oauth.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "clients")
public class Client {
    @Id
    @Column(name = "client_id")
    private String clientId;
    //name
    @Column(nullable = false)
    private String clientName;
    
    private String ownerEmail;
    
    public String getOwnerEmail() {
        return ownerEmail;
    }
    
    public void setOwnerEmail(String ownerEmail) {
        this.ownerEmail = ownerEmail;
    }

    @Column(nullable = false)
    private String clientSecret;

    /**@ElementCollection
    private Set<String> redirectUris;*/
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_redirect_uris", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uris")
    private Set<String> redirectUris = new HashSet<>();

    @Column(nullable = false)
    private String grantTypes; // E.g., "authorization_code,password,refresh_token"

    @Column(nullable = false)
    private String scope; // E.g., "read,write"
    
    @ManyToMany(mappedBy = "clients") 
    private Set<User> users;

    public String getClientId() { return clientId; }
    public String getClientSecret() { return clientSecret; }
    public Set<String> getRedirectUris() { return redirectUris; }

    public void setClientId(String clientId) { this.clientId = clientId; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public void setRedirectUris(Set<String> redirectUris) { this.redirectUris = redirectUris; }
    public void setGrantTypes(String grantTypes) { this.grantTypes = grantTypes; }
    public void setScope(String scope) { this.scope = scope; }

    public Client(String clientName, String clientId, String clientSecret) {
        this.clientName = clientName;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUris = new HashSet<>();
    }

    public String getRedirectUri() {
    if (redirectUris == null || redirectUris.isEmpty()) {
        return null; // or return a default value like "N/A"
    }
    return redirectUris.iterator().next();
}

}

