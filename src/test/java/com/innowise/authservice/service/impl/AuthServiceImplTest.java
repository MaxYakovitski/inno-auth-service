package com.innowise.authservice.service.impl;

import com.innowise.authservice.dto.credential.*;
import com.innowise.authservice.dto.user.UserCreateDto;
import com.innowise.authservice.dto.user.UserResponseDto;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.CredentialPersistenceException;
import com.innowise.authservice.exception.UsernameAlreadyInUseException;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.service.CredentialWriter;
import com.innowise.authservice.service.JwtService;
import com.innowise.authservice.service.UserServiceClient;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.LocalDate;
import java.time.Month;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private CredentialMapper credentialMapper;

    @Mock
    private UserServiceClient userServiceClient;

    @Mock
    private CredentialWriter credentialWriter;

    @Mock
    private JwtService jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    private AuthServiceImpl authService;

    UUID userId = UUID.randomUUID();
    Instant now = Instant.now();

    CredentialCreateDto createdCredentialDto = new CredentialCreateDto(
            "m@test.com",
            "password",
            "Maxim",
            "Maximov",
            LocalDate.of(1995, Month.JANUARY, 1)
            );

    UserResponseDto savedUserDto = new UserResponseDto(
            userId,
            "Maxim",
            "Maximov",
            createdCredentialDto.birthDate(),
            createdCredentialDto.email(),
            true,
            now,
            now);

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl(credentialRepository,
                credentialMapper, userServiceClient,
                credentialWriter, jwtService, passwordEncoder);
    }

    @Test
    void register_returns_CredentialResponseDto() {
        var createdUserDto = new UserCreateDto(
                createdCredentialDto.name(),
                createdCredentialDto.surname(),
                createdCredentialDto.birthDate(),
                createdCredentialDto.email()
        );

        var savedCredential = Credential.builder()
                .id(UUID.randomUUID())
                .userId(userId)
                .username(createdCredentialDto.email())
                .role(Role.USER)
                .build();

        var savedCredentialDto = new CredentialResponseDto(
                savedCredential.getId(),
                userId,
                createdCredentialDto.email(),
                Role.USER,
                true,
                now,
                now);

        when(credentialRepository.existsByUsername(createdCredentialDto.email())).thenReturn(false);
        when(userServiceClient.createUser(createdUserDto)).thenReturn(savedUserDto);
        when(credentialWriter.save(createdCredentialDto, userId)).thenReturn(savedCredential);
        when(credentialMapper.toDto(savedCredential)).thenReturn(savedCredentialDto);

        var result = authService.register(createdCredentialDto);

        assertThat(result).isEqualTo(savedCredentialDto);
        verify(userServiceClient, never()).deleteUser(any());
    }

    @Test
    void register_duplicateUsername_throws_UsernameAlreadyInUseException() {
        when(credentialRepository.existsByUsername(createdCredentialDto.email())).thenReturn(true);
        assertThatThrownBy(() -> authService.register(createdCredentialDto)).isInstanceOf(UsernameAlreadyInUseException.class);
        verifyNoInteractions(userServiceClient);
    }

    @Test
    void register_fails_and_throws_CredentialPersistenceException() {
        when(credentialRepository.existsByUsername(createdCredentialDto.email())).thenReturn(false);
        when(userServiceClient.createUser(any())).thenReturn(savedUserDto);
        when(credentialWriter.save(createdCredentialDto, userId)).thenThrow(new RuntimeException("database doesn't work"));

        assertThatThrownBy(() -> authService.register(createdCredentialDto)).isInstanceOf(CredentialPersistenceException.class);
        verify(userServiceClient).deleteUser(userId);
    }



    @Test
    void login_validCredentials_returns_Tokens() {
        var dto = new CredentialLoginDto("m@test.com", "testPassword");
        var credential = Credential.builder()
                .username("m@example.com")
                .passwordHash("hashPassword")
                .active(true)
                .build();

        when(credentialRepository.findByUsername("m@test.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("testPassword", "hashPassword")).thenReturn(true);
        when(jwtService.generateAccessToken(credential)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(credential)).thenReturn("refresh-token");

        var result = authService.login(dto);

        assertThat(result.accessToken()).isEqualTo("access-token");
        assertThat(result.refreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void login_unknownEmail_throws_BadCredentials() {
        var dto = new CredentialLoginDto("unknown@test.com", "testPassword");
        when(credentialRepository.findByUsername("unknown@test.com")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> authService.login(dto))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void login_inactiveAccount_throws_BadCredentials() {
        var credential = Credential.builder().username("m@test.com").active(false).build();
        when(credentialRepository.findByUsername("m@test.com")).thenReturn(Optional.of(credential));
        var credentialLoginDto = new CredentialLoginDto("m@test.com", "testPassword");
        assertThatThrownBy(() -> authService.login(credentialLoginDto))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void login_wrongPassword_throws_BadCredentials() {
        var credential = Credential.builder().username("m@test.com").passwordHash("hash").active(true).build();
        when(credentialRepository.findByUsername("m@test.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("wrongPassword", "hash")).thenReturn(false);

        var credentialLoginDto = new CredentialLoginDto("m@test.com", "wrongPassword");
        assertThatThrownBy(() -> authService.login(credentialLoginDto))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void refresh_inactiveAccount_throws_BadCredentials() {
        var claims = mock(Claims.class);
        var credential = Credential.builder().userId(userId).active(false).build();

        when(jwtService.parseAndValidate("refresh-token")).thenReturn(claims);
        when(claims.getSubject()).thenReturn(userId.toString());
        when(credentialRepository.findByUserId(userId)).thenReturn(Optional.of(credential));

        var credentialRefreshDto = new CredentialRefreshDto("refresh-token");
        assertThatThrownBy(() -> authService.refresh(credentialRefreshDto))
                .isInstanceOf(BadCredentialsException.class);
    }
}