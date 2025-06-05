package com.sommerph.zkbackend.repository.proofPreparation;

import com.sommerph.zkbackend.model.proofPreparation.EudiCredentialVerification;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class InMemoryProofPreparationRegistry implements ProofPreparationRegistry {

    private final Map<String, EudiCredentialVerification> eudiCredentialVerifyStore = new ConcurrentHashMap<>();

    @Override
    public void saveEudiCredentialVerification(EudiCredentialVerification data) {
        log.info("Save data required for EUDI credential verification for user {}", data.getUserId());
        try {
            eudiCredentialVerifyStore.put(data.getUserId(), data);
        } catch (Exception e) {
            log.error("Failed to save EUDI credential verification data for user: {}", data.getUserId(), e);
            throw new RuntimeException("Failed to save EUDI credential verification data for user: " + data.getUserId(), e);
        }
    }

    @Override
    public EudiCredentialVerification loadEudiCredentialVerification(String userId) {
        log.info("Load EUDI credential verification data for user {} ", userId);
        try {
            return eudiCredentialVerifyStore.get(userId);
        } catch (Exception e) {
            log.error("Failed to load EUDI credential verification data for user: {}", userId, e);
            throw new RuntimeException("Failed to load EUDI credential verification data for user: " + userId, e);
        }
    }

    @Override
    public boolean existsEudiCredentialVerification(String userId) {
        return eudiCredentialVerifyStore.containsKey(userId);
    }

    // For every new model in proofPreparation, implement methods for save, load, and exists as specified in interface.
    // Note: File naming convention is <userId>-<modelName>.json

}
