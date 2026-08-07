package com.innowise.authservice.dto.credential;


import jakarta.validation.constraints.NotBlank;

public record CredentialRefreshDto(
        @NotBlank String refreshToken
) {}
