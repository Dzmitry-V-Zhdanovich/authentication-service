package com.innowise.authenticationservice.service.impl;

import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.mapper.CredentialMapper;
import com.innowise.authenticationservice.model.Credential;
import com.innowise.authenticationservice.model.Role;
import com.innowise.authenticationservice.repository.CredentialRepository;
import com.innowise.authenticationservice.service.CredentialService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialServiceImpl implements CredentialService {

    private final CredentialRepository credentialRepository;
    private final CredentialMapper credentialMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void saveCredential(RegisterUserRequest request, UUID userId) {
        log.info("Saving credentials for login: {}", request.getLogin());

        Role role = request.getRole();
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        Credential credential = credentialMapper.toEntity(request, userId, encodedPassword, role);

        credentialRepository.save(credential);
        log.info("Credentials saved successfully for user: {}", request.getLogin());
    }
}
