package com.shirzad.springSecurity.jwt;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {


    private static  final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);
    @Override
    // this method is triggered whenever an unauthenticated user tries to access a secured resource
    // and an AuthenticationException is thrown.
    // it handles the unauthorized access attempt by sending an appropriate HTTP response.
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage());

        // here, we send a 401 Unauthorized response to the client
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Error: Unauthorized");
        System.out.println(authException.getMessage());

        // Set the response content type to JSON and status to 401 Unauthorized
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);


        // Hashmap is a part of Java's collection framework and is used to store data in key-value pairs like a dictionary.
        // here we create a response body containing details about the error: status, error message, exception message, and the request path.
        // this information is useful for the client to understand the nature of the error.
        final Map<String,Object> body = new HashMap<>();

        // A map is used to store key-value pairs, where each key is unique and maps to a specific value.
        // In this case, the map is used to structure the JSON response that will be sent to the client.
        // body.put method is used to add key-value pairs to the map.
        body.put("status",HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error","Unauthorized");
        body.put("message",authException.getMessage());
        body.put("path",request.getServletPath());

        // ObjectMapper is a class from the Jackson library that is used for converting Java objects to JSON and vice versa.
        // here we use ObjectMapper to write the response body as a JSON object to the response output stream.
        // ObjectMapper is responsible for serializing the Java Map into a JSON format that can be sent back to the client.
        // this allows the client to receive a structured JSON response containing the error details.
        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);

    }
}
