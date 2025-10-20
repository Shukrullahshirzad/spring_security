package com.shirzad.springSecurity.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtSecret}")
    // to inject the value of the jwtSecret property
    // from the application properties file into the jwtSecret field.
    // this allows you to externalize configuration and easily change the secret key without modifying the code.
    // the jwtSecret is used to sign and verify JSON Web Tokens (JWTs) for authentication and authorization purposes.
    // make sure to keep this secret key secure and not expose it in public repositories or client-side code.
    // you can set the value of jwtSecret in your application.properties or application.yml file like this:
    // application.properties:
    // spring.app.jwtSecret=your_secret_key_here
    // application.yml:
    // spring:
    //   app:
    //     jwtSecret: your_secret_key_here
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    // to inject the value of the jwtExpirationMs property from the application
    // properties file into the jwtExpirationMs field.
    // this allows you to externalize configuration and easily change the expiration time without modifying the code.
    // the jwtExpirationMs is used to specify the expiration time (in milliseconds) for JSON Web Tokens (JWTs).
    // setting an appropriate expiration time is important for security, as it limits the validity of the token and reduces the risk of misuse if the token is compromised.
    // you can set the value of jwtExpirationMs in your application.properties or application.yml file like this:
    // application.properties:
    // spring.app.jwtExpirationMs=3600000  # 1 hour in milliseconds
    // application.yml:
    // spring:
    //   app:
    //     jwtExpirationMs: 3600000  # 1 hour in milliseconds
    private int jwtExpirationMs;


    // HttpServletRequest is used to represent the HTTP request received by the server.
    // it provides methods to access request parameters, headers, attributes, and other information related to the request.
    // these methods are as follows:
    // getHeader(String name): retrieves the value of the specified request header. Header contains metadata about the
    // request, such as authorization tokens, content type, user agent, etc.
    // getParameter(String name): retrieves the value of the specified request parameter.
    // getMethod(): returns the HTTP method (e.g., GET, POST) of the request.
    // getRequestURI(): returns the URI of the request.
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder() // to create a new JWT token
                .subject(username) // to set the subject (typically the user identifier) of the token
                .issuedAt(new Date()) // to set the issuance time of the token to the current date and time
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs)) // to set the expiration time of the token by adding the configured expiration duration (jwtExpirationMs) to the current time
                .signWith(key()) // to sign the token using the specified secret key (key())
                .compact(); // to build and serialize the JWT token into a compact, URL-safe string format
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser() // Jwts.parser is a method that creates a new JwtParser instance. parser instance means an object that is used to parse and validate JWT tokens.
                .verifyWith((SecretKey) key()) // to specify the secret key that will be used to verify the signature of the JWT token.
                .build() // to build the JwtParser instance with the specified verification key.
                .parseSignedClaims(token)// to parse the provided JWT token and extract its signed claims.
                .getPayload() // to retrieve the payload (claims) of the parsed JWT token.
                .getSubject(); // to extract the subject (typically the user identifier) from the JWT claims.
    }

    private Key key() {

        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)); // to decode the Base64-encoded secret key (jwtSecret) and create an HMAC-SHA key for signing and verifying JWT tokens.
    }

    public boolean validateJwtToken(String authToken) { // to validate the provided JWT token (authToken) and check its integrity and authenticity.
        try {
            System.out.println("validate JWT Token");
            Jwts.parser()
                    .verifyWith((SecretKey) key()) // to specify the secret key that will be used to verify the signature of the JWT token.
                    .build()// to build the JwtParser instance with the specified verification key.
                    .parseSignedClaims(authToken); // to parse the provided JWT token and extract its signed claims.
            return true;
        }catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("JWT token is expired: {}", e.getMessage());
        }catch (UnsupportedJwtException e){
            logger.error("JWT token is not supported: {}", e.getMessage());
        }catch (IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

}
