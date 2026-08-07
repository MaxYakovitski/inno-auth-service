package com.innowise.authservice.exception;


public class UserServiceIntegrationException extends RuntimeException {

    public UserServiceIntegrationException(String message,  Throwable cause) {
        super(message, cause);
    }
}
