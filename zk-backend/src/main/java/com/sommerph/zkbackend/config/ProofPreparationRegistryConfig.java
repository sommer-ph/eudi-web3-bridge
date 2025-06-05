package com.sommerph.zkbackend.config;

import com.sommerph.zkbackend.repository.proofPreparation.ProofPreparationRegistry;
import com.sommerph.zkbackend.repository.proofPreparation.InMemoryProofPreparationRegistry;
import com.sommerph.zkbackend.repository.proofPreparation.JsonFileProofPreparationRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
public class ProofPreparationRegistryConfig {

    @Value("${proof.preparation.registry.type}")
    private String registryType;

    @Value("${proof.preparation.storage.path}")
    private String storagePath;

    @Bean
    public ProofPreparationRegistry proofPreparationRegistry() throws IOException {
        return switch (registryType.toLowerCase()) {
            case "json" -> new JsonFileProofPreparationRegistry(storagePath);
            case "memory" -> new InMemoryProofPreparationRegistry();
            default -> throw new IllegalArgumentException("Unsupported proof preparation registry type: " + registryType);
        };
    }

}
