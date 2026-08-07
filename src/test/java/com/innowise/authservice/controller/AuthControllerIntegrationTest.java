package com.innowise.authservice.controller;

import com.innowise.authservice.dto.credential.CredentialCreateDto;
import com.innowise.authservice.dto.credential.CredentialLoginDto;
import com.innowise.authservice.dto.credential.CredentialResponseDto;
import com.innowise.authservice.dto.user.UserResponseDto;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.service.UserServiceClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Instant;
import java.time.LocalDate;
import java.time.Month;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    private static final String BASE_URL = "http://localhost:";

    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:16");

    static {
        postgres.start();
    }

    @LocalServerPort
    private int port;

    private RestClient restClient;

    @MockitoBean
    private UserServiceClient userServiceClient;

    @Autowired
    private CredentialRepository credentialRepository;

    UUID userId;
    Instant now ;
    UserResponseDto userResponseDto;
    CredentialCreateDto credentialCreateDto;

    @BeforeEach
    void setUp() {
        restClient = RestClient.builder().baseUrl(BASE_URL + port).build();
        credentialRepository.deleteAll();

        userId = UUID.randomUUID();
        now = Instant.now();
        userResponseDto = new UserResponseDto(
                userId,
                "Maxim",
                "Maximov",
                LocalDate.of(1990, Month.JANUARY, 1),
                "m@test.com",
                true,
                now,
                now);

        credentialCreateDto = new CredentialCreateDto(
                "m@test.com",
                "testPassword",
                "Maxim",
                "Maximov",
                LocalDate.of(1990, Month.JANUARY, 1));
    }

    @Test
    void register_returns201() {
        when(userServiceClient.createUser(any())).thenReturn(userResponseDto);
        var response = restClient.post()
                .uri("/api/auth/register")
                .body(credentialCreateDto)
                .retrieve()
                .toEntity(CredentialResponseDto.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    @Test
    void register_duplicateUserName_returns409() {
        when(userServiceClient.createUser(any())).thenReturn(userResponseDto);
        restClient.post().uri("/api/auth/register").body(credentialCreateDto).retrieve().toBodilessEntity();

        var responseSpec = restClient.post().uri("/api/auth/register").body(credentialCreateDto).retrieve();

        assertThatThrownBy(responseSpec::toBodilessEntity)
                .isInstanceOf(HttpStatusCodeException.class)
                .satisfies(ex -> assertThat(((HttpStatusCodeException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.CONFLICT));
    }

    @Test
    void login_with_wrongPassword_returns401() {
        when(userServiceClient.createUser(any())).thenReturn(userResponseDto);
        restClient.post().uri("/api/auth/register").body(credentialCreateDto).retrieve().toBodilessEntity();

        var bodilessEntity = restClient.post()
                .uri("/api/auth/login")
                .body(new CredentialLoginDto("m@test.com", "wrongPassword"))
                .retrieve();

        assertThatThrownBy(bodilessEntity::toBodilessEntity)
                .isInstanceOf(HttpStatusCodeException.class)
                .satisfies(ex -> assertThat(((HttpStatusCodeException) ex).getStatusCode())
                        .isEqualTo(HttpStatus.UNAUTHORIZED));
    }
}