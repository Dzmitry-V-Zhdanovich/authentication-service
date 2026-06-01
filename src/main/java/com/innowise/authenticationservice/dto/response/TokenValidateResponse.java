package com.innowise.authenticationservice.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidateResponse {

    private boolean valid;
    private UUID userId;
    private String role;
    private String message;
}
