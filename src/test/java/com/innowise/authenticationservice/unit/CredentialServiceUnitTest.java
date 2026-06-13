package com.innowise.authenticationservice.unit;

import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.mapper.CredentialMapper;
import com.innowise.authenticationservice.model.Credential;
import com.innowise.authenticationservice.model.Role;
import com.innowise.authenticationservice.repository.CredentialRepository;
import com.innowise.authenticationservice.service.impl.CredentialServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("CredentialService Unit Tests")
public class CredentialServiceUnitTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private CredentialMapper credentialMapper;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private CredentialServiceImpl credentialService;

    private RegisterUserRequest validRequest;
    private UUID testUserId;
    private String encodedPassword;
    private Credential testCredential;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();
        encodedPassword = "$2a$10$encodedPasswordHash";

        validRequest = RegisterUserRequest.builder()
                .login("testuser")
                .password("password123")
                .firstName("John")
                .lastName("Doe")
                .birthDate(LocalDate.of(2000, 1, 1))
                .email("john.doe@example.com")
                .role(Role.ROLE_USER)
                .build();
        testCredential = Credential.builder()
                .login(validRequest.getLogin())
                .passwordHash(encodedPassword)
                .role(Role.ROLE_USER)
                .userId(testUserId)
                .build();
    }

    @Test
    @DisplayName("Should save credential successfully")
    void shouldSaveCredentialSuccessfully() {
        // Given
        when(passwordEncoder.encode(validRequest.getPassword())).thenReturn(encodedPassword);
        when(credentialMapper.toEntity(
                validRequest,
                testUserId,
                encodedPassword,
                Role.ROLE_USER
        )).thenReturn(testCredential);
        when(credentialRepository.save(testCredential)).thenReturn(testCredential);

        // When
        credentialService.saveCredential(validRequest, testUserId);

        // Then
        verify(passwordEncoder).encode(validRequest.getPassword());
        verify(credentialMapper).toEntity(
                validRequest,
                testUserId,
                encodedPassword,
                Role.ROLE_USER
        );
        verify(credentialRepository).save(testCredential);
    }
}
