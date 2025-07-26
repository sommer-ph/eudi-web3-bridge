package com.sommerph.zkbackend.repository.proofPreparation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sommerph.zkbackend.model.proofPreparation.monolithic.*;
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

    // C1
    @Override
    public void saveEudiWalletKeyDerivation(EudiKeyDerivation data) {
        writeToFile(data.getUserId() + "-eudi-wallet-key-derivation.json", data);
    }

    @Override
    public EudiKeyDerivation loadEudiWalletKeyDerivation(String userId) {
        return readFromFile(userId + "-eudi-wallet-key-derivation.json", EudiKeyDerivation.class);
    }

    @Override
    public boolean existsEudiWalletKeyDerivation(String userId) {
        return fileExists(userId + "-eudi-wallet-key-derivation.json");
    }

    // C2
    @Override
    public void saveCredentialPKCheck(EudiCredentialPublicKeyCheck data) {
        writeToFile(data.getUserId() + "-eudi-credential-public-key-check.json", data);
    }

    @Override
    public EudiCredentialPublicKeyCheck loadCredentialPKCheck(String userId) {
        return readFromFile(userId + "-eudi-credential-public-key-check.json", EudiCredentialPublicKeyCheck.class);
    }

    @Override
    public boolean existsCredentialPKCheck(String userId) {
        return fileExists(userId + "-eudi-credential-public-key-check.json");
    }

    // C3
    @Override
    public void saveCredentialSignatureVerification(EudiCredentialVerification data) {
        writeToFile(data.getUserId() + "-eudi-credential-verification.json", data);
    }

    @Override
    public EudiCredentialVerification loadCredentialSignatureVerification(String userId) {
        return readFromFile(userId + "-eudi-credential-verification.json", EudiCredentialVerification.class);
    }

    @Override
    public boolean existsCredentialSignatureVerification(String userId) {
        return fileExists(userId + "-eudi-credential-verification.json");
    }

    // C4
    @Override
    public void saveBlockchainWalletKeyDerivation(BlockchainKeyDerivation data) {
        writeToFile(data.getUserId() + "-blockchain-key-derivation.json", data);
    }

    @Override
    public BlockchainKeyDerivation loadBlockchainWalletKeyDerivation(String userId) {
        return readFromFile(userId + "-blockchain-key-derivation.json", BlockchainKeyDerivation.class);
    }

    @Override
    public boolean existsBlockchainWalletKeyDerivation(String userId) {
        return fileExists(userId + "-blockchain-key-derivation.json");
    }

    // File IO Helpers
    private <T> void writeToFile(String filename, T data) {
        Path path = storageDir.resolve(filename);
        try {
            mapper.writeValue(path.toFile(), data);
            log.info("Successfully wrote file: {}", path);
        } catch (IOException e) {
            log.error("Failed to write file: {}", path, e);
            throw new RuntimeException("Failed to write file: " + path, e);
        }
    }

    private <T> T readFromFile(String filename, Class<T> clazz) {
        Path path = storageDir.resolve(filename);
        try {
            return mapper.readValue(path.toFile(), clazz);
        } catch (IOException e) {
            log.error("Failed to read file: {}", path, e);
            throw new RuntimeException("Failed to read file: " + path, e);
        }
    }

    private boolean fileExists(String filename) {
        return Files.exists(storageDir.resolve(filename));
    }

    // For every new model in proofPreparation, implement methods for save, load, and exists as specified in interface.
    // Note: File naming convention is <userId>-<modelName>.json
}
