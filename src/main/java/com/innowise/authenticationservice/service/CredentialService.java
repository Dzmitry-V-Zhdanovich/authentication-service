package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.dto.request.RegisterUserRequest;

import java.util.UUID;

public interface CredentialService {

    void saveCredential(RegisterUserRequest request, UUID userId);
}
