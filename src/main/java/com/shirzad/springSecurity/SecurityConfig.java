package com.shirzad.springSecurity;

import com.fasterxml.jackson.databind.annotation.JsonAppend;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity // to enable Spring Security's web security support
@EnableMethodSecurity // to enable method-level security annotations like @PreAuthorize
public class SecurityConfig {

    @Autowired
    DataSource dataSource; // to inject the DataSource bean for database connectivity
    // securityFiterChain explained:

    // SecurityFilterChain bean defines the security filter chain for the application and configures security settings.
    // it customizes the HttpSecurity object to specify how requests should be authorized and how authentication should be handled.
    // it contains methods like authorizeHttpRequests, formLogin, and httpBasic to set up security rules and authentication mechanisms.
    // additionally, it uses withDefaults() to apply default configurations for form-based login and HTTP Basic authentication.
    // it is customizable and can be modified to fit specific security requirements. like permitting certain endpoints or using different authentication methods.
    // for example if you want to allow public access to a home page while securing other endpoints, you can modify the authorizeHttpRequests method accordingly.
    // to allow unrestricted access to the home page ("/") while requiring authentication for all other requests, you can modify the authorizeHttpRequests method as follows:
    // http.authorizeHttpRequests(
    //         (requests) -> requests
    //                 .requestMatchers("/").permitAll() // Allow unrestricted access to the home page
    //                 .anyRequest().authenticated() // Require authentication for all other requests
    // );
    // this configuration allows anyone to access the home page without authentication, while all other endpoints will require the user to be authenticated.
    // this is a basic setup and can be further customized based on the application's security needs.
    // the SecurityFilterChain bean is essential for defining how security is applied to incoming HTTP requests.
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                (requests) -> requests.requestMatchers("/springSecurity-console/**").permitAll().anyRequest().authenticated()
        );
        // make the session stateless means that the server does not store any session information about the client between requests.
        // each request from the client must contain all the information needed for the server to understand and process it.
        // this is commonly used in RESTful APIs where each request is independent and self-contained.
        // stateless sessions can improve scalability and performance since the server does not need to manage session data.
        // however, it also means that the client must handle authentication and state management, often through tokens (like JWT) or other mechanisms.
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
        // build the SecurityFilterChain object
        // build will configure the HttpSecurity object and return a SecurityFilterChain instance
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername( "user1")
                .password(passwordEncoder().encode("user1")) // {noop} indicates that no encoding is applied to the password
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername( "admin")
                .password(passwordEncoder().encode("admin")) // {noop} indicates that no encoding is applied to the password
                .roles("ADMIN")
                .build();
        // JdbcUserDetailsManager explained:

        // JdbcUserDetailsManager is a class provided by Spring Security that implements the UserDetailsService interface.
        // it is used to retrieve user details (like username, password, roles, etc.) from a relational database using JDBC (Java Database Connectivity).
        // it allows you to manage user authentication and authorization by storing user information in database tables.
        // it provides methods to create, update, delete, and retrieve user details from the database.
        // it is commonly used in applications that require persistent user storage and management.
        // to use JdbcUserDetailsManager, you typically need to configure a DataSource that connects to your database and set up the necessary database schema (tables) to store user information. the .properties file contains the database connection details. it will be treated as data source bean. then you can create an instance of JdbcUserDetailsManager and use it as your UserDetailsService implementation.
        JdbcUserDetailsManager jdbcUserDetailsManager
                = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user1); // this line adds the user1 to the database
        jdbcUserDetailsManager.createUser(admin);
        return jdbcUserDetailsManager;
        //return new InMemoryUserDetailsManager(user1, admin);
    }

    @Bean
    PasswordEncoder passwordEncoder(){ // PasswordEncoder bean is used to encode and verify passwords in a secure manner.
        
        return new BCryptPasswordEncoder();
    }

}
