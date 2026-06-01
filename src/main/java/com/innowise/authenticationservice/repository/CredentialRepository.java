package com.innowise.authenticationservice.repository;

import com.innowise.authenticationservice.model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {

    Optional<Credential> findByLogin(String login);

    boolean existsByLogin(String login);

    Optional<Credential> findByUserId(Long userId);
}
