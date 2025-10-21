package com.shirzad.springSecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    DataSource dataSource;

    @Autowired
    PasswordEncoder passwordEncoder;

    @PostMapping("/users")
    public String createUser(
            // creating user with username, password, role
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String role) {
        // JdbcUserDetailsManager is a class that implements UserDetailsService and provides methods to manage
        // user details in a JDBC data source. It allows you to create, update, delete, and retrieve user information
        // from a relational database using SQL queries.
        // It is commonly used in Spring Security applications to handle user authentication and authorization
        // by storing user credentials and roles in a database.
        // this class provides a convenient way to manage user details in a database-backed application.
        // it contains methods such as createUser, updateUser, deleteUser, changePassword, userExists, loadUserByUsername, etc.
        // these methods allow you to perform various operations related to user management in a database.
        JdbcUserDetailsManager jdbcUserDetailsManager
                = new JdbcUserDetailsManager(dataSource);

        if (jdbcUserDetailsManager.userExists(username)) {
            return "User already exists!";
        }

        // create a new user with the provided username, password, and role
        // UserDetails is an interface that represents a user in the Spring Security framework.
        // it contains methods to retrieve user information such as username, password, authorities
        // (roles/permissions), account status, etc.
        // User is a class that implements the UserDetails interface and provides a concrete implementation of a user.
        // it is commonly used to create user objects for authentication and authorization purposes in Spring Security.
        // User class provides a builder pattern to create user instances with various attributes such as username, password, roles, etc.
        //
        UserDetails user = User.withUsername(username)
                .password(passwordEncoder.encode(password))
                .roles(role)
                .build();
        jdbcUserDetailsManager.createUser(user);
        return "User created successfully!";
    }

}
