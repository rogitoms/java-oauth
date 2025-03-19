package com.oauth.oauth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/public/hello")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("This is a public endpoint!");
    }

    @GetMapping("/private/hello")
    public ResponseEntity<String> privateEndpoint() {
        return ResponseEntity.ok("This is a protected endpoint!");
    }
}