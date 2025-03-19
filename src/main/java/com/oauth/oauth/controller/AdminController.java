package com.oauth.oauth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

import com.oauth.oauth.repository.ClientRepository;
import com.oauth.oauth.repository.UserRepository;
import com.oauth.oauth.model.User;
import com.oauth.oauth.model.Client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import com.oauth.oauth.service.UserService;
import com.oauth.oauth.service.AdminService;
import com.oauth.oauth.service.ClientService;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);

    private final AdminService adminService;
    private final ClientService clientService;
    private final UserService userService;
    private final UserRepository userRepository; 
    private final ClientRepository clientRepository;

    public AdminController(AdminService adminService, ClientService clientService, 
                            UserService userService, UserRepository userRepository,
                             ClientRepository clientRepository) {
                                
        this.adminService = adminService;
        this.clientService = clientService;
        this.userService = userService;
        this.userRepository = userRepository; 
        this.clientRepository = clientRepository; 
    }

    @GetMapping("/dashboard")
    public String getAdminDashboard(HttpServletRequest request, Model model) {
        log.info("Admin dashboard accessed.");

        HttpSession session = request.getSession(false);

        if (session == null) {
            log.warn("Session is null, redirecting to login.");
            return "redirect:/auth/login";
        }

        Object emailObj = session.getAttribute("authenticatedUser");

        if (emailObj == null) {
            log.warn("Session attribute 'authenticatedUser' is missing, redirecting to login.");
            return "redirect:/auth/login";
        }

        String userEmail = emailObj.toString();
        log.info("Authenticated user found in session: {}", userEmail);

        // Check if the user is an admin
        User user = userRepository.findByEmail(userEmail)
            .orElseThrow(() -> {
                log.error("User not found in database: {}", userEmail);
                return new RuntimeException("User not found");
            });

        // Instead of checking user.getRole(), check the roles collection
        if (user.getRoles().stream()
        .noneMatch(role -> "ADMIN".equalsIgnoreCase(role.getName()) || 
                        "ROLE_ADMIN".equalsIgnoreCase(role.getName()))) {
        log.warn("User {} is not an ADMIN, redirecting to login.", userEmail);
        return "redirect:/auth/login";
        }

        log.info("Fetching users and clients from database.");
        List<User> users = userRepository.findAll();
        List<Client> clients = clientRepository.findAll();

        log.info("Fetched {} users and {} clients.", users.size(), clients.size());

        model.addAttribute("users", users);
        model.addAttribute("clients", clients);

        log.info("Rendering admin dashboard view.");
        return "admin/dashboard";  // ✅ Ensure `dashboard.html` exists
    }


    @GetMapping("/users")
    public String showUsers(HttpServletRequest request, Model model) {
        log.info("Users management page accessed.");
       

        List<User> users = userRepository.findAll();
        model.addAttribute("users", users);

        log.info("Rendering users management view.");
        return "admin/users"; // Ensure `users.html` exists
    }

    @GetMapping("/clients")
    public String showClients(HttpServletRequest request, Model model) {
        log.info("Clients management page accessed.");

        List<Client> clients = clientRepository.findAll();
        model.addAttribute("clients", clients);

        log.info("Rendering clients management view.");
        return "admin/clients"; // Ensure `clients.html` exists
    }

   

    @PostMapping("/addUser")
    public String addUser(@RequestParam String firstName, 
                          @RequestParam String lastName, 
                          @RequestParam String email, 
                          @RequestParam String role) {
        User newUser = new User(firstName, lastName, email, role);
        userService.addUser(firstName, lastName, email, role);
        log.info("User added: {}", email);
        return "redirect:/admin/users";
    }
    @PostMapping("/deleteUser")
    public String deleteUser(@RequestParam String email) {
        adminService.deleteUserByEmail(email);
        log.info("User deleted with Email: {}", email);
        return "redirect:/admin/users";
    }

    @PostMapping("/editUser")
    public String editUser(
                           @RequestParam Long userId, 
                           @RequestParam String firstName, 
                           @RequestParam String lastName, 
                           @RequestParam String email, 
                           @RequestParam String role) {
        userService.updateUser(userId, firstName, lastName, email, role);
        log.info("User updated: {}", email);
        return "redirect:/admin/users";
    }

    @PostMapping("/addClient")
    public String createClientByAdmin(@RequestParam String clientName,
                                      @RequestParam String redirectUris,
                                      RedirectAttributes redirectAttributes) {
        try {
            Client newClient = clientService.registerClientByAdmin(clientName, redirectUris);

            // Store generated client ID and secret in redirect attributes
            redirectAttributes.addFlashAttribute("clientId", newClient.getClientId());
            redirectAttributes.addFlashAttribute("clientSecret", newClient.getClientSecret());
            redirectAttributes.addFlashAttribute("success", "Client created successfully!");

            return "redirect:/admin/clients";

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to create client: " + e.getMessage());
            return "redirect:/admin/clients";
        }
    }

    @PostMapping("/deleteClient")
    public String deleteClient(@RequestParam String clientId) {
        clientService.deleteClientById(clientId);
        log.info("Client deleted with Client ID: {}", clientId);
        return "redirect:/admin/clients";
    }
    @PostMapping("/editClient")
    public String editClient(@RequestParam String clientId, 
                             @RequestParam String clientName, 
                             //@RequestParam String redirectUris,
                             @RequestParam String scope,
                             @RequestParam String grantTypes,
                             @RequestParam(value = "redirectUris", required = false) String redirectUris) {
    
    if (redirectUris == null) {
        log.warn("Redirect URIs parameter is missing in the request!");
            return "error";
            }
        clientService.updateClient(clientId, clientName,redirectUris, scope, grantTypes);
        log.info("Client updated with ID: {}", clientId);
        return "redirect:/admin/clients";
    }
}


