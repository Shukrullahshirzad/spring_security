package com.shirzad.springSecurity;


import com.shirzad.springSecurity.jwt.JwtUtils;
import com.shirzad.springSecurity.jwt.LoginRequest;
import com.shirzad.springSecurity.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class GreetingsController {

    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/greet")
    public String greet() {
        return "Hello, World!";
    }
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String user(){
        return "hello user";
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String admin(){
        return "hello admin";
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        // LoginRequest contains username and password, stored in JSON format
        // ResponseEntity<?> is a generic type that can represent any type of response body.
        // it allows you to return different types of responses based on the outcome of the authentication process.
        // the use of <?> indicates that the response body can be of any type, providing flexibility in handling various scenarios.
        // this method is responsible for authenticating a user based on the provided login credentials.
        // it generates a JWT token upon successful authentication and returns it in the response.
        // the method handles authentication failures by returning an appropriate error message and status code.
        // the method takes a LoginRequest object as input, which contains the username and password provided by the user.
        // it returns a ResponseEntity containing either a JWT token and user details upon successful authentication
        // or an error message in case of authentication failure.

        // perform authentication. The Authentication object contains the authenticated user's details if successful.
        // if authentication fails, an AuthenticationException is thrown.
        Authentication authentication;
        try {
            // this line attempts to authenticate the user using the provided username and password.
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()));
        }catch (AuthenticationException e) {
            Map<String, Object> map = new HashMap<>();
            map.put("msg", "Incorrect username or password");
            map.put("status", 401);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }
        // if authentication is successful, set the authentication object in the SecurityContext
        // this allows Spring Security to recognize the user as authenticated for the current request.
        // security context is a container that holds security-related information for the current execution thread.
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // retrieve user details from the authentication object
        // authentication object has different methods to access user information like username, password, roles, etc.
        // the methods as are as follows:
        // getPrincipal(): returns the principal (user details) associated with the authentication.
        // getCredentials(): returns the credentials (usually password) associated with the authentication.
        // getAuthorities(): returns the authorities (roles/permissions) granted to the user.
        // isAuthenticated(): returns whether the user is authenticated or not.
        // setAuthenticated(boolean isAuthenticated): sets the authentication status of the user.
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // generate a JWT token for the authenticated user using the user details
        // the generated token is used for subsequent requests to authenticate the user without requiring them to log in again.
        // the token contains encoded information about the user and is signed to ensure its integrity and authenticity.
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // extract user roles from the user details
        // the roles are used to determine the user's permissions and access levels within the application.
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(java.util.stream.Collectors.toList());

        // create a LoginResponse object containing the username, JWT token, and user roles
        LoginResponse response = new LoginResponse((userDetails.getUsername()), jwtToken, roles);

        return  ResponseEntity.ok(response);
    }



}
