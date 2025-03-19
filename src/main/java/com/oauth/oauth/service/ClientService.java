package com.oauth.oauth.service;

import com.oauth.oauth.model.Client;
import com.oauth.oauth.repository.ClientRepository;
import com.oauth.oauth.repository.AuthCodeRepository;
import com.oauth.oauth.repository.ConsentRepository;
import org.springframework.stereotype.Service;
import java.util.UUID;
import java.util.Set;
import java.util.HashSet;
import java.util.Optional;

import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.jpa.repository.Modifying;

@Service
public class ClientService {
    private final ClientRepository clientRepository;
    private final AuthCodeRepository authCodeRepository;
    private final ConsentRepository ConsentRepository;

    public ClientService(ClientRepository clientRepository, 
                        AuthCodeRepository authCodeRepository,
                        ConsentRepository ConsentRepository) {
        this.clientRepository = clientRepository;
        this.authCodeRepository = authCodeRepository;
        this.ConsentRepository = ConsentRepository;
    }

    public Client registerClient(String clientName, String redirectUri, String ownerEmail) {
        if (clientRepository.existsByOwnerEmail(ownerEmail)) {
            throw new RuntimeException("Client with this email already exists");
        }

        Client client = new Client();
        
        // Generate client ID and secret
        client.setClientId(UUID.randomUUID().toString());
        client.setClientSecret(UUID.randomUUID().toString());
        
        // Set properties correctly
        client.setClientName(clientName); // ✅ Correct setter method
        client.setOwnerEmail(ownerEmail); // ✅ Set owner email
        
        // Fix redirectUris handling
        Set<String> redirectUriSet = new HashSet<>();
        redirectUriSet.add(redirectUri);
        client.setRedirectUris(redirectUriSet);
        
        client.setGrantTypes("authorization_code");
        client.setScope("read,write");
        
        return clientRepository.save(client); // ✅ Ensure save() is called
    }
    @Transactional
    public void deleteClientById(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new RuntimeException("Client not found"));

        authCodeRepository.deleteByClient(client); 
        ConsentRepository.deleteByClient(client);
        clientRepository.delete(client); 
    }

    
    @Transactional
    public Client registerClientByAdmin(String clientName, String redirectUri) {
        // Generate unique clientId and clientSecret
        String clientId = UUID.randomUUID().toString();
        String clientSecret = UUID.randomUUID().toString();

        Client client = new Client();
        client.setClientId(clientId);
        client.setClientSecret(clientSecret);
        client.setClientName(clientName);

        // Set the redirect URI
        Set<String> redirectUris = new HashSet<>();
        redirectUris.add(redirectUri);
        client.setRedirectUris(redirectUris);

        // Set default values
        client.setGrantTypes("authorization_code");
        client.setScope("read,write");

        return clientRepository.save(client);
    }

    @Transactional
    public void updateClient(String clientId, String clientName, String redirectUri, String scope,String grantTypes) {
        Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new RuntimeException("Client not found"));

        client.setClientName(clientName);

        Set<String> redirectUris = new HashSet<>();
        redirectUris.add(redirectUri);
        client.setRedirectUris(redirectUris);

        client.setScope(scope);

        clientRepository.save(client);
    }
   

}
