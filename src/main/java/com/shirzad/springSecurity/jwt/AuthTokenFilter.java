package com.shirzad.springSecurity.jwt;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    // OncePerRequestFilter ensures that the filter is executed only once per request.
    // this is important for filters that should not be applied multiple times during the processing of a single request.
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter: Processing request to extract and validate JWT - {}", request.getRequestURI());

        // Skip JWT authentication for public endpoints (signin)
        String path = request.getServletPath();
        if ("/signin".equals(path) || path.startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // 1. Parse the JWT from the request header
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {

                // 2. Extract username from the JWT
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // 3. Load user details using the extracted username
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 4. Create an authentication token using the user details
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                // 5. Set additional details for the authentication token from the request
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 6. Set the authenticated user in the SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authentication);

            }
        }
        catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);

    }

    // Helper method to parse JWT from the request header
    // this method extracts the JWT token from the Authorization header of the HTTP request
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter: Parsing JWT: {}", jwt);
        return jwt;
    }
}
