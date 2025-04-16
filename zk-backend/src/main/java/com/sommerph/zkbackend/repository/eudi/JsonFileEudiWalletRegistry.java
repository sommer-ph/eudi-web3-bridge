package com.sommerph.zkbackend.repository.eudi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sommerph.zkbackend.model.eudi.EudiWallet;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.*;

@Slf4j
public class JsonFileEudiWalletRegistry implements EudiWalletRegistry {

    private final Path storageDir;
    private final ObjectMapper mapper;

    public JsonFileEudiWalletRegistry(String storagePath) throws IOException {
        this.storageDir = Paths.get(storagePath);
        Files.createDirectories(storageDir);
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public void save(EudiWallet wallet) {
        log.info("Save eudi wallet for user {}", wallet.getUserId());
        Path filePath = storageDir.resolve(wallet.getUserId() + ".json");
        try {
            mapper.writeValue(filePath.toFile(), wallet);
        } catch (IOException e) {
            log.error("Failed to save eudi wallet for user: {}", wallet.getUserId(), e);
            throw new RuntimeException("Failed to save eudi wallet for user: " + wallet.getUserId(), e);
        }
    }

    @Override
    public EudiWallet load(String userId) {
        log.info("Load eudi wallet for user {} ", userId);
        Path filePath = storageDir.resolve(userId + ".json");
        try {
            return mapper.readValue(filePath.toFile(), EudiWallet.class);
        } catch (IOException e) {
            log.error("Failed to load eudi wallet for user: {}", userId, e);
            throw new RuntimeException("Failed to load eudi wallet for user: " + userId, e);
        }
    }

    @Override
    public boolean exists(String userId) {
        return Files.exists(storageDir.resolve(userId + ".json"));
    }

}
