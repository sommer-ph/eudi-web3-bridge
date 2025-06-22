package com.sommerph.zkbackend.config;

import com.sommerph.zkbackend.repository.proofPreparation.ProofPreparationRegistry;
import com.sommerph.zkbackend.repository.proofPreparation.InMemoryProofPreparationRegistry;
import com.sommerph.zkbackend.repository.proofPreparation.JsonFileProofPreparationRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
public class ProofPreparationRegistryConfig {

    private final ProofPreparationProperties properties;

    public ProofPreparationRegistryConfig(ProofPreparationProperties properties) {
        this.properties = properties;
    }

    @Bean
    public ProofPreparationRegistry proofPreparationRegistry() throws IOException {
        return switch (properties.getRegistry().getType().toLowerCase()) {
            case "json" -> new JsonFileProofPreparationRegistry(properties.getStorage().getPath());
            case "memory" -> new InMemoryProofPreparationRegistry();
            default -> throw new IllegalArgumentException("Unsupported proof preparation registry type: " + properties.getRegistry().getType());
        };
    }

}
