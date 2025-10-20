package com.shirzad.springSecurity.jwt;

import java.util.List;

public class LoginResponse {

    // in the response body of a successful login request. It contains the JWT token, the username of the
    // authenticated user, and a list of roles assigned to that user.
    private String jwtToken;
    private String username;
    private List<String> roles;

    // No-arg constructor required by Jackson
    public LoginResponse() {
    }

    public LoginResponse(String username, String jwtToken, List<String> roles) {
        this.username = username;
        this.jwtToken = jwtToken;
        this.roles = roles;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
}
