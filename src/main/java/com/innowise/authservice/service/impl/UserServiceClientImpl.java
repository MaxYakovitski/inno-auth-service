package com.innowise.authservice.service.impl;


import com.innowise.authservice.dto.user.UserCreateDto;
import com.innowise.authservice.dto.user.UserResponseDto;
import com.innowise.authservice.exception.UserServiceIntegrationException;
import com.innowise.authservice.service.UserServiceClient;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.UUID;

@Service
public class UserServiceClientImpl implements UserServiceClient {

    private final RestClient restClient;
    private final String usersPath;

    public UserServiceClientImpl(
            RestClient restClient, @Value("${user-service.users-path}") String usersPath) {
        this.restClient = restClient;
        this.usersPath = usersPath;
    }

    @Override
    public UserResponseDto createUser(UserCreateDto request) {
        try {
            return restClient.post()
                    .uri(usersPath)
                    .body(request)
                    .retrieve()
                    .body(UserResponseDto.class);
        } catch (RestClientException e) {
            throw new UserServiceIntegrationException("Failed to create user", e);
        }
    }

    @Override
    public void deleteUser(UUID userId) {
        try {
            restClient.delete()
                    .uri(usersPath + "/{id}", userId)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException e) {
            throw new UserServiceIntegrationException("Failed to delete user with id: " + userId, e);
        }
    }
}
