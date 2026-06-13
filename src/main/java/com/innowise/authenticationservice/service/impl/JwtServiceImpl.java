package com.innowise.authenticationservice.service.impl;

import com.innowise.authenticationservice.config.JwtConfig;
import com.innowise.authenticationservice.exception.CustomSecurityException;
import com.innowise.authenticationservice.model.Role;
import com.innowise.authenticationservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final JwtConfig jwtConfig;
    private SecretKey signKey;

    @PostConstruct
    public void init() {
        this.signKey = Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String generateAccessToken(String login, UUID userId, Role role) {
        return Jwts.builder()
                .subject(login)
                .claim("userId", userId)
                .claim("role", role.name())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(jwtConfig.getAccess().getExpiration())))
                .signWith(signKey)
                .compact();
    }

    @Override
    public String generateServiceToken() {
        return Jwts.builder()
                .subject("AuthService")
                .claim("role", "ROLE_SERVICE")
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(60000)))
                .signWith(signKey)
                .compact();
    }

    @Override
    public String generateRefreshToken(String login, UUID userId, Role role) {
        return Jwts.builder()
                .subject(login)
                .claim("userId", userId)
                .claim("role", role.name())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(jwtConfig.getRefresh().getExpiration())))
                .signWith(signKey)
                .compact();
    }

    @Override
    public Claims validateToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            log.error("JWT validation failed: {}", e.getMessage());
            throw new CustomSecurityException("Invalid or expired JWT token: " + e.getMessage());
        }
    }

    @Override
    public UUID getUserIdFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.get("userId", UUID.class);
    }

    @Override
    public String getRoleFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.get("role", String.class);
    }
}
