package com.JwtSecurity.Jwt.controller;

import com.JwtSecurity.Jwt.Configuration.JwtUtils;
import com.JwtSecurity.Jwt.Exception.PersonNotFoundException;
import com.JwtSecurity.Jwt.entity.User;
import com.JwtSecurity.Jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {


    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<?>register(@RequestBody User user) {
        if(userRepository.findByUsername(user.getUsername()) != null) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        user.setRole(user.getRole()== null ? "ROLE_USER" : user.getRole());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);

        return ResponseEntity.ok(userRepository.save(user));
    }

    //pour tester les exceptions
    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable Long id) {
        User user = userRepository.findById(id).orElseThrow(() -> new PersonNotFoundException("utilisateur non trouvé"));
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
                    if(authentication.isAuthenticated()) {
                        Map<String, Object> authData = new HashMap<>();
                        authData.put("token", jwtUtils.generateToken(user.getUsername(),user.getRole()));
                        authData.put("type", "Bearer");
                        return ResponseEntity.ok(authData);
                    }
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid username or password");

        }catch (AuthenticationException e) {
            System.out.println(e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }
    }
}
