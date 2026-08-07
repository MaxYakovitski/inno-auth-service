package com.innowise.authservice.dto.user;


import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record UserResponseDto(
        UUID id,
        String name,
        String surname,
        LocalDate birthDate,
        String email,
        Boolean active,
        Instant createdAt,
        Instant updatedAt
) {}
