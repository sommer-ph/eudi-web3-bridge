package com.sommerph.zkbackend.config;

import com.sommerph.zkbackend.repository.eudi.EudiWalletRegistry;
import com.sommerph.zkbackend.repository.eudi.InMemoryEudiWalletRegistry;
import com.sommerph.zkbackend.repository.eudi.JsonFileEudiWalletRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
public class EudiWalletRegistryConfig {

    @Value("${eudi.wallet.registry.type}")
    private String registryType;

    @Value("${eudi.wallet.storage.path}")
    private String storagePath;

    @Bean
    public EudiWalletRegistry eudiWalletRegistry() throws IOException {
        return switch (registryType.toLowerCase()) {
            case "json" -> new JsonFileEudiWalletRegistry(storagePath);
            case "memory" -> new InMemoryEudiWalletRegistry();
            default -> throw new IllegalArgumentException("Unsupported registry type: " + registryType);
        };
    }

}

