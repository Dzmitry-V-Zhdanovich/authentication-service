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
import com.innowise.authenticationservice.model.Role;
import com.innowise.authenticationservice.repository.CredentialRepository;
import com.innowise.authenticationservice.service.AuthService;
import com.innowise.authenticationservice.service.CredentialService;
import com.innowise.authenticationservice.service.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class AuthServiceImpl implements AuthService {

    private final CredentialRepository credentialRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RestClient restClient;
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
            String serviceToken = jwtService.generateServiceToken();

            return restClient.post()
                    .uri(userServiceUrl + "/api/v1/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .headers(headers -> headers.setBearerAuth(serviceToken))
                    .body(createUserRequest)
                    .retrieve()
                    .body(CreateUserInUserServiceResponse.class);
        } catch (RestClientException e) {
            log.error("Error calling UserService: {}", e.getMessage());
            throw new UserServiceException("UserService is unavailable: " + e.getMessage());
        }
    }

    private void rollbackUserServiceCreation(UUID userId) {
        try {
            String deleteUrl = userServiceUrl + "/api/v1/users/" + userId;
            log.info("Sending compensating DELETE request to: {}", deleteUrl);

            String serviceToken = jwtService.generateServiceToken();

            restClient.method(org.springframework.http.HttpMethod.DELETE)
                    .uri(deleteUrl)
                    .headers(headers -> headers.setBearerAuth(serviceToken))
                    .retrieve()
                    .toBodilessEntity();

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
        String refreshToken = jwtService.generateRefreshToken(
                credential.getLogin(),
                credential.getUserId(),
                credential.getRole()
        );

        log.info("Login successful for user: {}", request.getLogin());
        return new LoginResponse(accessToken, refreshToken);
    }

    @Override
    public TokenValidateResponse validateToken(String token) {
        Claims claims = jwtService.validateToken(token);

        log.info("Token validation successful for user ID: {}", claims.get("userId"));

        UUID userId = UUID.fromString(claims.get("userId", String.class));
        String role = claims.get("role", String.class);

        return new TokenValidateResponse(
                true,
                userId,
                role,
                "Token is valid"
        );
    }

    @Override
    public LoginResponse refreshTokens(String refreshToken) {
        log.info("Refreshing access and refresh tokens");

        Claims claims = jwtService.validateToken(refreshToken);
        String login = claims.getSubject();

        UUID userId = UUID.fromString(claims.get("userId", String.class));
        String roleString = claims.get("role", String.class);
        Role role = Role.valueOf(roleString);

        String newAccessToken = jwtService.generateAccessToken(login, userId, role);
        String newRefreshToken = jwtService.generateRefreshToken(login, userId, role);

        log.info("Tokens refreshed successfully for user: {}", login);
        return new LoginResponse(newAccessToken, newRefreshToken);
    }
}
