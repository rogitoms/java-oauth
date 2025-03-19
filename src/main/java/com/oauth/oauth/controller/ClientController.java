package com.oauth.oauth.controller;

import com.oauth.oauth.model.Client;
import com.oauth.oauth.service.ClientService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
@RequestMapping("/client")
public class ClientController {
    private final ClientService clientService;
    
    public ClientController(ClientService clientService) {
        this.clientService = clientService;
    }

    @GetMapping("/register")
    public String registerPage(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("authenticatedUser") == null) {
            return "redirect:/auth/login";
        }
        
        model.addAttribute("client", new Client());
        return "client/register";
    }

    @PostMapping("/register")
    public String registerClientApi(@RequestParam("clientName") String clientName,
                                    @RequestParam("redirectUri") String redirectUri,
                                    HttpServletRequest httpRequest,
                                    RedirectAttributes redirectAttributes) {
        String ownerEmail = (String) httpRequest.getSession().getAttribute("authenticatedUser");

        if (clientName.isEmpty() || redirectUri.isEmpty() || ownerEmail == null) {
            redirectAttributes.addFlashAttribute("error", "All fields are required.");
            return "redirect:/client/register";
        }

        try {
            Client client = clientService.registerClient(clientName, redirectUri, ownerEmail);
            
            HttpSession session = httpRequest.getSession();
            session.setAttribute("clientId", client.getClientId());
            session.setAttribute("clientSecret", client.getClientSecret());

            redirectAttributes.addFlashAttribute("success", "Client Registered Successfully!");
            return "redirect:/client/credentials";

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Registration failed: " + e.getMessage());
            return "redirect:/client/register";
        }
    }

    @GetMapping("/credentials")
    public String showClientCredentials(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession(false);

        if (session == null || session.getAttribute("clientId") == null) {
            return "redirect:/client/register";
        }

        model.addAttribute("clientId", session.getAttribute("clientId"));
        model.addAttribute("clientSecret", session.getAttribute("clientSecret"));

        return "client/credentials";
    }
}
