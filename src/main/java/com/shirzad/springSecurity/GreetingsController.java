package com.shirzad.springSecurity;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

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
}
