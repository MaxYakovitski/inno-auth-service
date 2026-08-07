package com.innowise.authservice.dto.credential;


import com.innowise.authservice.entity.Role;

import java.time.Instant;
import java.util.UUID;

public record CredentialResponseDto(
        UUID id,
        UUID userId,
        String username,
        Role role,
        boolean active,
        Instant createdAt,
        Instant updatedAt
) {
}
