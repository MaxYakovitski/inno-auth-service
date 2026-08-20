package com.innowise.authservice.service.impl;

import com.innowise.authservice.dto.user.UserCreateDto;
import com.innowise.authservice.exception.UserServiceIntegrationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.LocalDate;
import java.time.Month;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;


class UserServiceClientImplTest {

    private static  final String BASE_URL = "http://user-service";
    private static final String USER_PATH = "/api/v1/users";

    private MockRestServiceServer mockServer;
    private UserServiceClientImpl client;

    UserCreateDto createDto = new UserCreateDto(
            "Maxim",
            "Maximov",
            LocalDate.of(1995, Month.JANUARY, 1),
            "m@test.com");

    UUID userId = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        var builder = RestClient.builder().baseUrl(BASE_URL);
        mockServer = MockRestServiceServer.bindTo(builder).build();
        client = new UserServiceClientImpl(builder.build(), USER_PATH);
    }

    @Test
    void createUser_returns_Response() {
        mockServer.expect(requestTo(BASE_URL + USER_PATH))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.CREATED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("""
                                {"id":"%s", "name":"Maxim", "surname":"Maximov","birthDate":"1995-01-01","email":"m@test.com","active":true}
                                """.formatted(userId)));

        var responseDto = client.createUser(createDto);
        assertThat(responseDto.id()).isEqualTo(userId);
        mockServer.verify();
    }

    @Test
    void createUser_returns_failure_with_IntegrationException() {
        mockServer.expect(requestTo(BASE_URL + USER_PATH))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));

        assertThatThrownBy(() -> client.createUser(createDto))
                .isInstanceOf(UserServiceIntegrationException.class);
    }

    @Test
    void deleteUser_sendsDeleteRequest() {
        mockServer.expect(requestTo(BASE_URL + USER_PATH + "/" + userId))
                .andExpect(method(HttpMethod.DELETE))
                .andRespond(withStatus(HttpStatus.NO_CONTENT));

        client.deleteUser(userId);

        mockServer.verify();
    }

    @Test
    void deleteUser_remoteFailure_throwsIntegrationException() {
        mockServer.expect(requestTo(BASE_URL + USER_PATH + "/" + userId))
                .andExpect(method(HttpMethod.DELETE))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));

        assertThatThrownBy(() -> client.deleteUser(userId))
                .isInstanceOf(UserServiceIntegrationException.class);
    }
}