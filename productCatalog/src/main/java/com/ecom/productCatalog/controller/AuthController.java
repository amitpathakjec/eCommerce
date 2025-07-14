package com.ecom.productCatalog.controller;

import com.ecom.productCatalog.model.User;
import com.ecom.productCatalog.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import com.ecom.productCatalog.utils.JwtUtil;
import com.ecom.productCatalog.service.CustomUserDetailsServiceImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;
import java.util.Map;

@Controller
public class AuthController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private CustomUserDetailsServiceImpl userDetailsService;
    @Autowired
    private JwtUtil jwtUtil;

    // Show single login form for all roles
    @GetMapping("/login")
    public String showLoginForm() {
        return "login";
    }

    @ResponseBody
    @PostMapping("/api/login")
    public Map<String, Object> login(@RequestBody Map<String, String> loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.get("username"), loginRequest.get("password"))
        );
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtUtil.generateToken(userDetails.getUsername());

        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        return response;
    }

    // Show registration form (buyer or seller)
    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        model.addAttribute("roles", new String[]{"BUYER", "SELLER"});
        return "register";
    }

    // Handle registration
    @PostMapping("/register")
    public String registerUser(@ModelAttribute("user") User user, Model model, @RequestParam("role") String role) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            model.addAttribute("error", "Username already exists!");
            model.addAttribute("roles", new String[]{"BUYER", "SELLER"});
            return "register";
        }
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            model.addAttribute("error", "Email already registered!");
            model.addAttribute("roles", new String[]{"BUYER", "SELLER"});
            return "register";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(User.Role.valueOf(role)); // Set role as BUYER or SELLER
        userRepository.save(user);
        return "redirect:/login?registered";
    }
}