package com.innowise.authservice.exception;


public class UsernameAlreadyInUseException extends RuntimeException {

    public UsernameAlreadyInUseException(String username) {
        super("Username already in use: " +  username);
    }
}
