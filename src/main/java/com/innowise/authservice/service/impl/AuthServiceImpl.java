package com.innowise.authservice.service.impl;

import com.innowise.authservice.dto.credential.*;
import com.innowise.authservice.dto.credential.TokenDto;
import com.innowise.authservice.dto.user.UserCreateDto;
import com.innowise.authservice.exception.CredentialPersistenceException;
import com.innowise.authservice.exception.UsernameAlreadyInUseException;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.service.AuthService;
import com.innowise.authservice.service.CredentialWriter;
import com.innowise.authservice.service.JwtService;
import com.innowise.authservice.service.UserServiceClient;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final CredentialRepository credentialRepository;
    private final CredentialMapper credentialMapper;
    private final UserServiceClient userServiceClient;
    private final CredentialWriter credentialWriter;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public CredentialResponseDto register(CredentialCreateDto dto) {
        if (credentialRepository.existsByUsername(dto.email())) {
            throw new UsernameAlreadyInUseException(dto.email());
        }

        var profile = userServiceClient
                .createUser(new UserCreateDto(
                        dto.name(),
                        dto.surname(),
                        dto.birthDate(),
                        dto.email())
                );

        try {
            var saved = credentialWriter.save(dto, profile.id());
            return credentialMapper.toDto(saved);
        } catch (Exception e) {
            compensate(profile.id());
            throw new CredentialPersistenceException(
                    "Local credential save failed for user_id: " + profile.id() + "; remote profile rolled back", e);
        }
    }

    private void compensate(UUID userId) {
        try {
            userServiceClient.deleteUser(userId);
            log.info("Compensating transaction: deleted user_id: {}", userId);
        } catch (Exception e) {
            log.error("Compensating transaction FAILED, user_id:{}", userId, e);
        }
    }

    @Override
    public TokenDto login(CredentialLoginDto dto) {
        var credential = credentialRepository.findByUsername(dto.username())
                .orElseThrow(() -> new BadCredentialsException("Invalid username or password"));
        if (!credential.isActive()) {
            throw new BadCredentialsException("Account is not active.");
        }
        if (!passwordEncoder.matches(dto.password(), credential.getPasswordHash())) {
            throw new BadCredentialsException("Invalid username or password.");
        }
        var accessToken = jwtService.generateAccessToken(credential);
        var refreshToken = jwtService.generateRefreshToken(credential);
        return TokenDto.of(accessToken, refreshToken);
    }

    @Override
    public TokenDto refresh(CredentialRefreshDto dto) {
        var claims = jwtService.parseAndValidate(dto.refreshToken());
        jwtService.requireTokenType(claims, JwtService.REFRESH_TOKEN_TYPE);
        var credential = credentialRepository.findByUserId(parseSubject(claims))
                .orElseThrow(() -> new BadCredentialsException("Credential not found"));
        if (!credential.isActive()) {
            throw new BadCredentialsException("Account is not active.");
        }
        var newAccessToken = jwtService.generateAccessToken(credential);
        return TokenDto.of(newAccessToken, dto.refreshToken());
    }

    private UUID parseSubject(JWTClaimsSet claims) {
        try {
            return UUID.fromString(claims.getSubject());
        } catch (IllegalArgumentException | NullPointerException _) {
            throw new BadCredentialsException("Token is incorrect.");
        }
    }
}
