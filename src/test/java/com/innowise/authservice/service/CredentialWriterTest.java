package com.innowise.authservice.service;

import com.innowise.authservice.dto.credential.CredentialCreateDto;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDate;
import java.time.Month;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialWriterTest {

    @Mock
    private CredentialRepository credentialRepository;
    @Mock
    private CredentialMapper credentialMapper;
    @Mock
    private PasswordEncoder passwordEncoder;

    private CredentialWriter credentialWriter;

    @BeforeEach
    void setUp() {
        credentialWriter = new CredentialWriter(credentialRepository, credentialMapper, passwordEncoder);
    }

    @Test
    void save_hashesPasswordAndPersistsMappedEntity() {
        UUID userId = UUID.randomUUID();
        CredentialCreateDto dto = new CredentialCreateDto(
                "m@test.com",
                "testPassword",
                "Maxim",
                "Maximov",
                LocalDate.of(1995, Month.JANUARY, 1));

        Credential mapped = Credential.builder()
                .username("m@test.com")
                .userId(userId)
                .passwordHash("hashPassword")
                .role(Role.USER)
                .build();
        Credential saved = Credential.builder()
                .id(UUID.randomUUID())
                .username("m@test.com")
                .userId(userId)
                .passwordHash("hashPassword")
                .role(Role.USER)
                .build();

        when(passwordEncoder.encode("testPassword")).thenReturn("hashPassword");
        when(credentialMapper.toEntity(dto, userId, "hashPassword")).thenReturn(mapped);
        when(credentialRepository.save(mapped)).thenReturn(saved);

        Credential result = credentialWriter.save(dto, userId);

        assertThat(result).isEqualTo(saved);
        verify(passwordEncoder).encode("testPassword");
        verify(credentialRepository, times(1)).save(mapped);
    }
}