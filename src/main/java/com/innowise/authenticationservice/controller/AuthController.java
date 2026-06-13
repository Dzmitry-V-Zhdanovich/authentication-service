package com.innowise.authenticationservice.controller;

import com.innowise.authenticationservice.dto.request.LoginRequest;
import com.innowise.authenticationservice.dto.request.RefreshTokenRequest;
import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.dto.request.TokenValidateRequest;
import com.innowise.authenticationservice.dto.response.LoginResponse;
import com.innowise.authenticationservice.dto.response.MessageResponse;
import com.innowise.authenticationservice.dto.response.TokenValidateResponse;
import com.innowise.authenticationservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(@Valid @RequestBody RegisterUserRequest request) {
        log.info("Received registration request for login: {}", request.getLogin());

        authService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new MessageResponse("User registered successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Received login request for: {}", request.getLogin());

        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<TokenValidateResponse> validate(@Valid @RequestBody TokenValidateRequest request) {
        log.info("Token validation request received");

        return ResponseEntity.ok(authService.validateToken(request.getToken()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh request received");

        LoginResponse response = authService.refreshTokens(request.getRefreshToken());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "AuthenticationService"));
    }
}
