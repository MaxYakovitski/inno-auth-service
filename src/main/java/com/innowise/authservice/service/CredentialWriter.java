package com.innowise.authservice.service;

import com.innowise.authservice.dto.credential.CredentialCreateDto;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.repository.CredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CredentialWriter {

    private final CredentialRepository credentialRepository;
    private final CredentialMapper credentialMapper;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public Credential save(CredentialCreateDto dto, UUID userId) {
        var hashedPassword = passwordEncoder.encode(dto.password());
        var saved = credentialMapper.toEntity(dto, userId, hashedPassword);
        return credentialRepository.save(saved);
    }
}
