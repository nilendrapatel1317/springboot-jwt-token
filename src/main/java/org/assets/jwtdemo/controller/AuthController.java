package org.assets.jwtdemo.controller;

import org.assets.jwtdemo.utils.JwtUtil;
import org.assets.jwtdemo.model.User;
import org.assets.jwtdemo.dao.*;
import org.assets.jwtdemo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthRequest authRequest,HttpServletRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );

            // Blacklist all previous tokens for this user
            jwtUtil.blacklistAllUserTokens(authRequest.getUsername());

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtUtil.generateToken(userDetails.getUsername(), userDetails.getAuthorities());
            // Store the new token as active for this user
            jwtUtil.storeUserToken(userDetails.getUsername(), token);
            
            User user = userService.getUserByUsername(userDetails.getUsername());
            
            return ResponseEntity.ok(new AuthResponse(token, user.getUsername(), user.getRole().name()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new AuthResponse("Invalid username or password"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        try {
            User user = userService.registerUser(
                    registerRequest.getUsername(),
                    registerRequest.getPassword(),
                    registerRequest.getEmail(),
                    registerRequest.getRole()
            );
            // Generate JWT token for the newly registered user
            String token = jwtUtil.generateToken(user.getUsername(), user.getAuthorities());
            
            return ResponseEntity.ok(new AuthResponse(token, user.getUsername(), user.getRole().name()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new AuthResponse(e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            jwtUtil.addToBlacklist(token);
        }
        SecurityContextHolder.clearContext();
        AuthResponse response = new AuthResponse();
        response.setMessage("Logged out successfully");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            
            boolean success = userService.changePassword(username, request.getCurrentPassword(), request.getNewPassword());
            
            if (success) {
                AuthResponse response = new AuthResponse();
                response.setMessage("Password changed successfully");
                return ResponseEntity.ok(response);
            } else {
                AuthResponse response = new AuthResponse();
                response.setMessage("Current password is incorrect");
                return ResponseEntity.badRequest().body(response);
            }
        } catch (Exception e) {
            AuthResponse response = new AuthResponse();
            response.setMessage("Error changing password");
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/home")
    public ResponseEntity<?> home() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to the Home Page!");
        response.put("username", username);
        response.put("authorities", authentication.getAuthorities());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user/profile")
    public ResponseEntity<?> userProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        
        User user = userService.getUserByUsername(username);
        
        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("role", user.getRole().name());
        response.put("enabled", user.isEnabled());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/admin/dashboard")
    public ResponseEntity<?> adminDashboard() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to Admin Dashboard!");
        response.put("adminFeatures", "User management, System settings, Analytics");
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/public/info")
    public ResponseEntity<?> publicInfo() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "This is public information");
        response.put("version", "1.0.0");
        response.put("status", "running");
        
        return ResponseEntity.ok(response);
    }
}
