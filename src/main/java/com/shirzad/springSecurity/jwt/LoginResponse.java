package com.shirzad.springSecurity.jwt;

import java.util.List;

public class LoginResponse {

    // in the response body of a successful login request. It contains the JWT token, the username of the
    // authenticated user, and a list of roles assigned to that user.
    private String jwtToken;
    private String username;
    private List<String> roles;
    public LoginResponse(String username, String jwtToken, List<String> roles) {
        this.username = username;
        this.jwtToken = jwtToken;
        this.roles = roles;
    }
}
