// com.sommerph.zkbackend.repository.proofPreparation.JsonFileProofPreparationRegistry.java
package com.sommerph.zkbackend.repository.proofPreparation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sommerph.zkbackend.model.proofPreparation.EudiCredentialVerification;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.*;

@Slf4j
public class JsonFileProofPreparationRegistry implements ProofPreparationRegistry {

    private final Path storageDir;
    private final ObjectMapper mapper;

    public JsonFileProofPreparationRegistry(String storagePath) throws IOException {
        this.storageDir = Paths.get(storagePath);
        Files.createDirectories(storageDir);
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public void saveEudiCredentialVerification(EudiCredentialVerification data) {
        log.info("Save EUDI credential verification data for user {}", data.getUserId());
        Path path = storageDir.resolve(data.getUserId() + "-eudi-credential-verification.json");
        try {
            mapper.writeValue(path.toFile(), data);
        } catch (IOException e) {
            log.error("Failed to save EUDI credential verification data for user {}", data.getUserId(), e);
            throw new RuntimeException("Failed to save EUDI credential verification data for user: " + data.getUserId(), e);
        }
    }

    @Override
    public EudiCredentialVerification loadEudiCredentialVerification(String userId) {
        log.info("Load EUDI credential verification data for user {} ", userId);
        Path path = storageDir.resolve(userId + "-eudi-credential-verification.json");
        try {
            return mapper.readValue(path.toFile(), EudiCredentialVerification.class);
        } catch (IOException e) {
            log.error("Failed to load EUDI credential verification data for user {}", userId, e);
            throw new RuntimeException("Failed to load EUDI credential verification data for user: " + userId, e);
        }
    }

    @Override
    public boolean existsEudiCredentialVerification(String userId) {
        return Files.exists(storageDir.resolve(userId + ".json"));
    }

    // For every new model in proofPreparation, implement methods for save, load, and exists as specified in interface.
    // Note: File naming convention is <userId>-<modelName>.json

}
