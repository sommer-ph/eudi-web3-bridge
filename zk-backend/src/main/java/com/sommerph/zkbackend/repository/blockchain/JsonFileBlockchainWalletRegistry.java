package com.sommerph.zkbackend.repository.blockchain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sommerph.zkbackend.model.blockchain.BlockchainWallet;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.*;

@Slf4j
public class JsonFileBlockchainWalletRegistry implements BlockchainWalletRegistry {

    private final Path storageDir;
    private final ObjectMapper mapper;

    public JsonFileBlockchainWalletRegistry(String path) throws IOException {
        this.storageDir = Paths.get(path);
        Files.createDirectories(storageDir);
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public void save(BlockchainWallet wallet) {
        log.info("Save blockchain wallet for user {}", wallet.getUserId());
        Path filePath = storageDir.resolve(wallet.getUserId() + "-blockchain-wallet.json");
        try {
            mapper.writeValue(filePath.toFile(), wallet);
        } catch (IOException e) {
            log.error("Failed to save blockchain wallet for user: {}", wallet.getUserId(), e);
            throw new RuntimeException("Failed to save blockchain wallet for user: " + wallet.getUserId(), e);
        }
    }

    @Override
    public BlockchainWallet load(String userId) {
        log.info("Load blockchain wallet for user {}", userId);
        Path filePath = storageDir.resolve(userId + "-blockchain-wallet.json");
        try {
            return mapper.readValue(filePath.toFile(), BlockchainWallet.class);
        } catch (IOException e) {
            log.error("Failed to load blockchain wallet for user: {}", userId, e);
            throw new RuntimeException("Failed to load blockchain wallet for user: " + userId, e);
        }
    }

    @Override
    public boolean exists(String userId) {
        return Files.exists(storageDir.resolve(userId + "-blockchain-wallet.json"));
    }
}
