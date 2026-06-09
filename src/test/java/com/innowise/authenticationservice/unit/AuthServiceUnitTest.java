package com.innowise.authenticationservice.unit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authenticationservice.dto.request.CreateUserInUserServiceRequest;
import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.dto.response.CreateUserInUserServiceResponse;
import com.innowise.authenticationservice.exception.UserServiceException;
import com.innowise.authenticationservice.mapper.UserMapper;
import com.innowise.authenticationservice.model.Role;
import com.innowise.authenticationservice.repository.CredentialRepository;
import com.innowise.authenticationservice.service.CredentialService;
import com.innowise.authenticationservice.service.JwtService;
import com.innowise.authenticationservice.service.impl.AuthServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.LocalDate;
import java.util.UUID;


import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Unit Tests")
public class AuthServiceUnitTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private UserMapper userMapper;

    @Mock
    private CredentialService credentialService;

    @InjectMocks
    private AuthServiceImpl authService;

    private MockRestServiceServer mockServer;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private RegisterUserRequest validRequest;
    private CreateUserInUserServiceRequest mockUserRequest;
    private String userServiceUrl;

    @BeforeEach
    void setUp() {
        userServiceUrl = "http://localhost:8081";
        ReflectionTestUtils.setField(authService, "userServiceUrl", userServiceUrl);

        RestClient.Builder restClientBuilder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(restClientBuilder).build();
        ReflectionTestUtils.setField(authService, "restClient", restClientBuilder.build());

        validRequest = RegisterUserRequest.builder()
                .login("testuser")
                .password("password123")
                .firstName("John")
                .lastName("Doe")
                .birthDate(LocalDate.of(2000, 1, 1))
                .email("john.doe@example.com")
                .role(Role.ROLE_USER)
                .build();

        mockUserRequest = new CreateUserInUserServiceRequest();
    }

    @Test
    @DisplayName("Should generate service token and send authorized DELETE request when local DB save fails")
    void shouldRollbackUserServiceCreationWithTokenWhenLocalDbFails() throws Exception {
        // Given
        UUID expectedUserId = UUID.randomUUID();
        String expectedToken = "mock-service-jwt-token";

        when(credentialRepository.existsByLogin(validRequest.getLogin())).thenReturn(false);
        when(userMapper.toCreateUserRequest(validRequest)).thenReturn(mockUserRequest);
        when(jwtService.generateServiceToken()).thenReturn(expectedToken);

        CreateUserInUserServiceResponse mockResponse = new CreateUserInUserServiceResponse();
        mockResponse.setUserId(expectedUserId);
        String mockResponseJson = objectMapper.writeValueAsString(mockResponse);

        mockServer.expect(requestTo(userServiceUrl + "/api/v1/users"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + expectedToken))
                .andRespond(withSuccess(mockResponseJson, MediaType.APPLICATION_JSON));

        doThrow(new RuntimeException("Database connection timeout"))
                .when(credentialService).saveCredential(validRequest, expectedUserId);

        mockServer.expect(requestTo(userServiceUrl + "/api/v1/users/" + expectedUserId))
                .andExpect(method(HttpMethod.DELETE))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer " + expectedToken))
                .andRespond(withSuccess());

        // When & Then
        assertThatThrownBy(() -> authService.register(validRequest))
                .isInstanceOf(UserServiceException.class)
                .hasMessageContaining("Registration failed due to internal error");

        verify(jwtService, times(2)).generateServiceToken();

        mockServer.verify();
    }
}
