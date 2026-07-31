package com.innowise.authservice.service.impl;


import com.innowise.authservice.dto.user.UserCreateDto;
import com.innowise.authservice.dto.user.UserResponseDto;
import com.innowise.authservice.exception.UserServiceIntegrationException;
import com.innowise.authservice.service.UserServiceClient;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceClientImpl implements UserServiceClient {

    private final RestClient restClient;

    @Override
    public UserResponseDto createUser(UserCreateDto request) {
        try {
            return restClient.post()
                    .uri("/api/users")
                    .body(request)
                    .retrieve()
                    .body(UserResponseDto.class);
        } catch (RestClientException e) {
            throw new UserServiceIntegrationException("Failed to create user: ", e);
        }
    }

    @Override
    public void deleteUser(UUID userId) {
        try {
            restClient.delete()
                    .uri("/api/users/{id}", userId)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException e) {
            throw new UserServiceIntegrationException("Failed to delete user with id: " + userId, e);
        }
    }
}
