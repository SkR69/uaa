package com.titan.uaa.controller;

import com.titan.uaa.dto.AuthResponse;
import com.titan.uaa.dto.LoginRequest;
import com.titan.uaa.dto.RegisterRequest;
import com.titan.uaa.model.User;
import com.titan.uaa.service.JwtService;
import com.titan.uaa.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private JwtService jwtService;
    
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
            
            User user = (User) authentication.getPrincipal();
            String jwt = jwtService.generateToken(user);
            
            return ResponseEntity.ok(new AuthResponse(jwt, "Bearer", user.getUsername(), user.getEmail()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }
    
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest registerRequest) {
        try {
            User user = userService.registerUser(registerRequest);
            String jwt = jwtService.generateToken(user);
            
            return ResponseEntity.ok(new AuthResponse(jwt,"Bearer", user.getUsername(), user.getEmail()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }
    
    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(@RequestHeader("Authorization") String token) {
        try {
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            String username = jwtService.extractUsername(token);
            User user = (User) userService.loadUserByUsername(username);
            
            if (jwtService.isTokenValid(token, user)) {
                return ResponseEntity.ok("Token is valid");
            } else {
                return ResponseEntity.badRequest().body("Invalid token");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid token");
        }
    }
}
