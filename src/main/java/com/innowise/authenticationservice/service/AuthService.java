package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.dto.request.LoginRequest;
import com.innowise.authenticationservice.dto.request.RegisterUserRequest;
import com.innowise.authenticationservice.dto.response.LoginResponse;
import com.innowise.authenticationservice.dto.response.TokenValidateResponse;

public interface AuthService {

    void register(RegisterUserRequest request);
    LoginResponse login(LoginRequest request);
    TokenValidateResponse validateToken(String token);
    LoginResponse refreshTokens(String refreshToken);
}
