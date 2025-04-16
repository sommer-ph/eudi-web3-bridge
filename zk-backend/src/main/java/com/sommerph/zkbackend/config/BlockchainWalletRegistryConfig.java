package com.sommerph.zkbackend.config;

import com.sommerph.zkbackend.repository.blockchain.BlockchainWalletRegistry;
import com.sommerph.zkbackend.repository.blockchain.InMemoryBlockchainWalletRegistry;
import com.sommerph.zkbackend.repository.blockchain.JsonFileBlockchainWalletRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

@Configuration
public class BlockchainWalletRegistryConfig {

    @Value("${blockchain.wallet.registry.type}")
    private String registryType;

    @Value("${blockchain.wallet.storage.path}")
    private String storagePath;

    @Bean
    public BlockchainWalletRegistry blockchainWalletRegistry() throws IOException {
        return switch (registryType.toLowerCase()) {
            case "json" -> new JsonFileBlockchainWalletRegistry(storagePath);
            case "memory" -> new InMemoryBlockchainWalletRegistry();
            default -> throw new IllegalArgumentException("Unsupported registry type: " + registryType);
        };
    }

}

