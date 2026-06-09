package com.innowise.authenticationservice.service;

import com.innowise.authenticationservice.model.Role;
import io.jsonwebtoken.Claims;

import java.util.UUID;

public interface JwtService {

    String generateAccessToken(String login, UUID userId, Role role);
    String generateServiceToken();
    String generateRefreshToken(String login, UUID userId, Role role);
    Claims validateToken(String token);
    UUID getUserIdFromToken(String token);
    String getRoleFromToken(String token);
}
