package com.innowise.authservice.repository;

import com.innowise.authservice.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {

    Optional<Credential> findByUserId(UUID userId);

    Optional<Credential> findByUsername(String username);
    boolean existsByUsername(String username);

}
