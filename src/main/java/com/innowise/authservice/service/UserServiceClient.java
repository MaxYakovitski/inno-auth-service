package com.innowise.authservice.service;


import com.innowise.authservice.dto.user.UserCreateDto;
import com.innowise.authservice.dto.user.UserResponseDto;

import java.util.UUID;

public interface UserServiceClient {

    UserResponseDto createUser(UserCreateDto request);
    void deleteUser(UUID userId);
}
