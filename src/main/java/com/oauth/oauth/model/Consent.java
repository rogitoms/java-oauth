package com.oauth.oauth.model;

import jakarta.persistence.*;

@Entity
@Table(name = "user_consent")
public class Consent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne
    @JoinColumn(name = "client_id", nullable = false)
    private Client client;

    // ✅ Add missing setter and getter for User
    public void setUser(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    // ✅ Add missing setter and getter for Client
    public void setClient(Client client) {
        this.client = client;
    }

    public Client getClient() {
        return client;
    }
}
