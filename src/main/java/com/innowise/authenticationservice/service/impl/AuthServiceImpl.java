package com.innowise.authenticationservice.service.impl;

import com.innowise.authenticationservice.dto.request.CreateUserInUserServiceRequest;
import com.innowise.authenticationservice.dto.request.LoginRequest;
import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.dto.response.CreateUserInUserServiceResponse;
import com.innowise.authenticationservice.dto.response.LoginResponse;
import com.innowise.authenticationservice.dto.response.TokenValidateResponse;
import com.innowise.authenticationservice.exception.CustomSecurityException;
import com.innowise.authenticationservice.exception.UserAlreadyExistsException;
import com.innowise.authenticationservice.exception.UserServiceException;
import com.innowise.authenticationservice.mapper.UserMapper;
import com.innowise.authenticationservice.model.Credential;
import com.innowise.authenticationservice.repository.CredentialRepository;
import com.innowise.authenticationservice.service.AuthService;
import com.innowise.authenticationservice.service.CredentialService;
import com.innowise.authenticationservice.service.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class AuthServiceImpl implements AuthService {

    private final CredentialRepository credentialRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RestTemplate restTemplate;
    private final UserMapper userMapper;
    private final CredentialService credentialService;

    @Value("${user.service.url}")
    private String userServiceUrl;

    @Override
    @Transactional
    public void register(RegisterUserRequest request) {
        log.info("Processing registration for login: {}", request.getLogin());

        if (credentialRepository.existsByLogin(request.getLogin())) {
            throw new UserAlreadyExistsException("Login already exists: " + request.getLogin());
        }

        CreateUserInUserServiceResponse userServiceResponse = callUserService(request);
        UUID createdUserId = userServiceResponse.getUserId();
        log.info("User created in UserService with ID: {}", createdUserId);

        try {
            credentialService.saveCredential(request, createdUserId);
        } catch (Exception e) {
            log.error("Local DB save failed for userId: {}. Initiating compensation...", createdUserId, e);

            rollbackUserServiceCreation(createdUserId);

            throw new UserServiceException("Registration failed due to internal error. Registration rolled back.", e);
        }
    }

    private CreateUserInUserServiceResponse callUserService(RegisterUserRequest request) {
        CreateUserInUserServiceRequest createUserRequest = userMapper.toCreateUserRequest(request);
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/json");
            HttpEntity<CreateUserInUserServiceRequest> entity = new HttpEntity<>(createUserRequest, headers);

            ResponseEntity<CreateUserInUserServiceResponse> response = restTemplate.exchange(
                    userServiceUrl + "/api/v1/users",
                    HttpMethod.POST,
                    entity,
                    CreateUserInUserServiceResponse.class
            );

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                throw new UserServiceException("Failed to create user in UserService");
            }
            return response.getBody();
        } catch (RestClientException e) {
            log.error("Error calling UserService: {}", e.getMessage());
            throw new UserServiceException("UserService is unavailable: " + e.getMessage());
        }
    }

    private void rollbackUserServiceCreation(UUID userId) {
        try {
            String deleteUrl = userServiceUrl + "/api/v1/users/" + userId;
            log.info("Sending compensating DELETE request to: {}", deleteUrl);

            restTemplate.exchange(
                    deleteUrl,
                    HttpMethod.DELETE,
                    HttpEntity.EMPTY,
                    Void.class
            );

            log.info("Successfully rolled back user creation in UserService for ID: {}", userId);
        } catch (RestClientException e) {
            log.error("CRITICAL: Failed to rollback user creation for ID: {} in UserService! " +
                    "Data inconsistency detected. Error: {}", userId, e.getMessage(), e);
        }
    }

    @Override
    public LoginResponse login(LoginRequest request) {
        log.info("Processing login for: {}", request.getLogin());

        Credential credential = credentialRepository.findByLogin(request.getLogin())
                .orElseThrow(() -> new CustomSecurityException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
            throw new CustomSecurityException("Invalid credentials");
        }

        String accessToken = jwtService.generateAccessToken(
                credential.getLogin(),
                credential.getUserId(),
                credential.getRole()
        );
        String refreshToken = jwtService.generateRefreshToken(credential.getLogin());

        log.info("Login successful for user: {}", request.getLogin());
        return new LoginResponse(accessToken, refreshToken);
    }

    @Override
    public TokenValidateResponse validateToken(String token) {
        try {
            Claims claims = jwtService.validateToken(token);
            return new TokenValidateResponse(
                    true,
                    claims.get("userId", UUID.class),
                    claims.get("role", String.class),
                    "Token is valid"
            );
        } catch (CustomSecurityException e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return new TokenValidateResponse(false, null, null, e.getMessage());
        }
    }

    @Override
    public LoginResponse refreshTokens(String refreshToken) {
        log.info("Refreshing access and refresh tokens");

        Claims claims = jwtService.validateToken(refreshToken);
        String login = claims.getSubject();

        Credential credential = credentialRepository.findByLogin(login)
                .orElseThrow(() -> new CustomSecurityException("User not found"));

        String newAccessToken = jwtService.generateAccessToken(
                credential.getLogin(),
                credential.getUserId(),
                credential.getRole()
        );

        String newRefreshToken = jwtService.generateRefreshToken(credential.getLogin());

        log.info("Tokens refreshed successfully for user: {}", login);
        return new LoginResponse(newAccessToken, newRefreshToken);
    }

    @Override
    public Claims getClaimsFromToken(String token) {
        return jwtService.validateToken(token);
    }
}
