package com.innowise.authenticationservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authenticationservice.dto.request.LoginRequest;
import com.innowise.authenticationservice.dto.request.RefreshTokenRequest;
import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.dto.request.TokenValidateRequest;
import com.innowise.authenticationservice.dto.response.CreateUserInUserServiceResponse;
import com.innowise.authenticationservice.dto.response.LoginResponse;
import com.innowise.authenticationservice.model.Credential;
import com.innowise.authenticationservice.model.Role;
import com.innowise.authenticationservice.repository.CredentialRepository;
import com.innowise.authenticationservice.service.JwtService;
import com.innowise.authenticationservice.service.impl.AuthServiceImpl;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.test.web.client.response.MockRestResponseCreators;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.client.RestClient;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@Import(BaseIntegrationTest.JacksonTestConfig.class)
@DisplayName("AuthController Integration Tests")
public class AuthControllerIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthServiceImpl authService;

    private MockRestServiceServer mockServer;

    @BeforeEach
    void setUp() {
        credentialRepository.deleteAll();

        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();

        ReflectionTestUtils.setField(authService, "restClient", builder.build());
    }

    @Test
    @DisplayName("POST /api/auth/login - Should return tokens with valid claims and check BCrypt match")
    void shouldLoginSuccessfullyAndReturnValidJwtClaims() throws Exception {

        String rawPassword = "securePassword123";
        String encodedPassword = passwordEncoder.encode(rawPassword);
        UUID mockUserId = UUID.randomUUID();

        Credential credential = new Credential();
        credential.setLogin("active_user");
        credential.setPasswordHash(encodedPassword);
        credential.setUserId(mockUserId);
        credential.setRole(Role.ROLE_USER);
        credentialRepository.save(credential);

        Credential savedCred = credentialRepository.findByLogin("active_user").orElseThrow();
        assertThat(savedCred.getPasswordHash()).startsWith("$2a$");
        assertThat(passwordEncoder.matches(rawPassword, savedCred.getPasswordHash())).isTrue();

        LoginRequest loginRequest = new LoginRequest("active_user", rawPassword);

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        LoginResponse loginResponse = objectMapper.readValue(responseBody, LoginResponse.class);

        assertThat(loginResponse.getAccessToken()).isNotNull();
        assertThat(loginResponse.getRefreshToken()).isNotNull();

        Claims claims = jwtService.validateToken(loginResponse.getAccessToken());

        assertThat(claims.getSubject()).isEqualTo("active_user");
        assertThat(claims.get("userId", String.class)).isEqualTo(mockUserId.toString());
        assertThat(claims.get("role", String.class)).isEqualTo("ROLE_USER");
    }

    @Test
    @DisplayName("POST /api/auth/validate - Should validate token accurately")
    void shouldValidateCorrectToken() throws Exception {
        // GIVEN
        UUID userId = UUID.randomUUID();
        String token = jwtService.generateAccessToken("test_subject", userId, Role.ROLE_USER);

        TokenValidateRequest validateRequest = new TokenValidateRequest(token);

        // WHEN & THEN
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validateRequest)))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /api/auth/refresh - Should refresh tokens successfully when refresh token is valid")
    void shouldRefreshTokensSuccessfully() throws Exception {
        // GIVEN
        UUID userId = UUID.randomUUID();
        String username = "refresh_user";
        String oldRefreshToken = jwtService.generateRefreshToken(username, userId, Role.ROLE_USER);

        RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
        refreshRequest.setRefreshToken(oldRefreshToken);

        // WHEN
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andReturn();

        // THEN
        String responseBody = result.getResponse().getContentAsString();
        LoginResponse loginResponse = objectMapper.readValue(responseBody, LoginResponse.class);

        assertThat(loginResponse.getAccessToken()).isNotNull();
        assertThat(loginResponse.getRefreshToken()).isNotNull();
        assertThat(loginResponse.getAccessToken()).isNotEqualTo(oldRefreshToken);

        Claims newClaims = jwtService.validateToken(loginResponse.getAccessToken());
        assertThat(newClaims.getSubject()).isEqualTo(username);
        assertThat(newClaims.get("userId", String.class)).isEqualTo(userId.toString());
        assertThat(newClaims.get("role", String.class)).isEqualTo("ROLE_USER");
    }

    @Test
    @DisplayName("POST /api/auth/register - Should register user in local DB and call UserService")
    void shouldRegisterUserSuccessfully() throws Exception {
        // GIVEN
        UUID mockUserId = UUID.randomUUID();
        String targetUrl = "http://localhost:8081/api/v1/users";

        CreateUserInUserServiceResponse mockResponse = new CreateUserInUserServiceResponse();
        mockResponse.setUserId(mockUserId);
        String mockResponseJson = objectMapper.writeValueAsString(mockResponse);

        mockServer.expect(MockRestRequestMatchers.requestTo(targetUrl))
                .andExpect(MockRestRequestMatchers.method(HttpMethod.POST))
                .andRespond(MockRestResponseCreators.withSuccess(mockResponseJson, MediaType.APPLICATION_JSON));

        RegisterUserRequest registerRequest = RegisterUserRequest.builder()
                .login("new_api_user")
                .password("password123")
                .firstName("John")
                .lastName("Doe")
                .birthDate(LocalDate.of(2000, 1, 1))
                .email("john.api@example.com")
                .role(Role.ROLE_USER)
                .build();

        // WHEN
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isCreated());

        // THEN
        Optional<Credential> savedCredentialOpt = credentialRepository.findByLogin("new_api_user");
        assertThat(savedCredentialOpt).isPresent();

        Credential savedCredential = savedCredentialOpt.get();
        assertThat(savedCredential.getUserId()).isEqualTo(mockUserId);

        assertThat(savedCredential.getPasswordHash()).startsWith("$2a$");
        assertThat(passwordEncoder.matches("password123", savedCredential.getPasswordHash())).isTrue();

        mockServer.verify();
    }
}
