package org.assets.jwtdemo.dto;

public class UserDetailsResponse {
    private String token;
    private String username;
    private String role;
    private String message;
    
    public UserDetailsResponse() {}
    
    public UserDetailsResponse(String token, String username, String role) {
        this.token = token;
        this.username = username;
        this.role = role;
        this.message = "Authentication successful";
    }
    
    public UserDetailsResponse(String message) {
        this.message = message;
    }
    
    public String getToken() {
        return token;
    }
    
    public void setToken(String token) {
        this.token = token;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getRole() {
        return role;
    }
    
    public void setRole(String role) {
        this.role = role;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
}