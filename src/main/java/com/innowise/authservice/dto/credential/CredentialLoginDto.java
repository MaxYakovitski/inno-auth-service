package com.innowise.authservice.dto.credential;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CredentialLoginDto(
        @NotBlank @Size(max = 50) String username,
        @NotBlank String password
) {}
