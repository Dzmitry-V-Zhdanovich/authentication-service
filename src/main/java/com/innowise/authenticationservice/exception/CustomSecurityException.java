package com.innowise.authenticationservice.exception;

public class CustomSecurityException extends RuntimeException {
    public CustomSecurityException(String message) {
        super(message);
    }

    public CustomSecurityException(String message, Throwable cause) {
        super(message, cause);
    }
}
