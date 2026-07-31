package com.innowise.authservice.dto.credential;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record CredentialCreateDto(
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(min = 8, max = 100) String password,
        @NotBlank @Size(max = 128) String name,
        @NotBlank @Size(max = 128) String surname,
        @NotNull LocalDate birthDate
        ) {}
