package com.shirzad.springSecurity;

import com.shirzad.springSecurity.jwt.AuthEntryPointJwt;
import com.shirzad.springSecurity.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity // to enable Spring Security's web security support
@EnableMethodSecurity // to enable method-level security annotations like @PreAuthorize
public class SecurityConfig {

    @Autowired
    DataSource dataSource; // to inject the DataSource bean for database connectivity

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    // NOTE: removed the field-level injection of AuthTokenFilter to avoid a circular dependency.
    // The filter will be injected as a parameter into the SecurityFilterChain bean method.

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
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, AuthTokenFilter authTokenFilter) throws Exception {
        http.authorizeHttpRequests(
                (requests) ->
                        requests.requestMatchers("/signin").permitAll() // allow unrestricted access to the signin endpoint
                                .anyRequest().authenticated() // require authentication for any other request
        );
        // make the session stateless means that the server does not store any session information about the client between requests.
        // each request from the client must contain all the information needed for the server to understand and process it.
        // this is commonly used in RESTful APIs where each request is independent and self-contained.
        // stateless sessions can improve scalability and performance since the server does not need to manage session data.
        // however, it also means that the client must handle authentication and state management, often through tokens (like JWT) or other mechanisms.

        http.sessionManagement((
                session) ->
                    session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS)
        );

        http.exceptionHandling(
                exception ->
                        exception.authenticationEntryPoint(unauthorizedHandler));

        // http.formLogin(withDefaults());

        // http.header explained:
        // http.headers() is a method used to configure HTTP headers in a Spring Security application.
        // it allows you to customize various security-related headers that are included in HTTP responses.
        // these headers help enhance the security of web applications by providing protection against common vulnerabilities.
        // one of the common configurations is setting the X-Frame-Options header to control whether the application can
        // be embedded in an iframe. in this case, we are setting the frame options to "sameOrigin", which means
        // that the application can only be embedded in an iframe if the parent page is from the same origin (domain)
        // as the application itself. this helps prevent clickjacking attacks.
        // you can customize other headers as well, such as Content-Security-Policy, X-Content-Type-Options, etc.
        // clickjacking is a malicious technique where an attacker tricks a user into clicking on something different
        // from what the user perceives, potentially revealing confidential information or allowing unauthorized actions.
        // by setting the X-Frame-Options header to "sameOrigin", we ensure that our application cannot be embedded
        // in an iframe on a different domain, thereby mitigating the risk of clickjacking attacks
        http.headers(
                headers -> headers.frameOptions(
                        HeadersConfigurer.FrameOptionsConfig::sameOrigin
                )
        );

        // disable CSRF protection. CSRF protection is a security measure that helps prevent unauthorized
        // commands from being transmitted from a user that the web application trusts.
        // in stateless applications that use tokens (like JWT) for authentication, CSRF protection is often unnecessary.
        http.csrf(AbstractHttpConfigurer::disable);

        // add the custom JWT authentication filter before the default UsernamePasswordAuthenticationFilter
        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
        // build the SecurityFilterChain object
        // build will configure the HttpSecurity object and return a SecurityFilterChain instance
    }

    // AuthenticationManager bean is responsible for managing authentication processes in a Spring Security application.
    // here we define a bean for AuthenticationManager using the AuthenticationConfiguration provided by Spring Security.
    // the AuthenticationManager is a core component that handles the authentication of users based on their credentials.
    // it is used to verify user credentials (like username and password) during the authentication process.
    // by defining this bean, we make the AuthenticationManager available for injection into other components of the application,
    // such as controllers or services that require authentication functionality.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }


}
