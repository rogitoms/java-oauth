/**package com.oauth.oauth.config;

import com.oauth.oauth.model.User;
import com.oauth.oauth.model.Role;
import com.oauth.oauth.repository.UserRepository;
import com.oauth.oauth.repository.RoleRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;
import java.util.Optional;
import java.util.Set;

@Component
public class AdminUserInitializer {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public AdminUserInitializer(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void createAdminUser() {
        // Ensure the ADMIN role exists
        Role adminRole = roleRepository.findByName("ADMIN").orElseGet(() -> {
            Role newRole = new Role();
            newRole.setName("ADMIN");
            return roleRepository.save(newRole); // Create and save ADMIN role if not found
        });

        // Check if an admin user already exists
        if (!userRepository.existsByEmail("admin1@gmail.com")) {
            User admin = new User();
            admin.setEmail("admin1@gmail.com");
            admin.setPassword(passwordEncoder.encode("admin123")); // Hash password
            admin.setRoles(Set.of(adminRole)); // Assign ADMIN role correctly

            userRepository.save(admin);
            System.out.println("✅ Admin user created: admin@example.com / admin123");
        } else {
            System.out.println("ℹ️ Admin user already exists.");
        }
    }
}*/
