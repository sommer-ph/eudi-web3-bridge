package com.sommerph.zkbackend.service;

import com.sommerph.zkbackend.model.proofPreparation.EudiCredentialVerification;
import com.sommerph.zkbackend.repository.proofPreparation.ProofPreparationRegistry;
import com.sommerph.zkbackend.service.eudi.EudiKeyManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProofPreparationService {

    private final EudiKeyManagementService eudiKeyManagementService;
    private final ProofPreparationRegistry proofPreparationRegistry;

    // cred-bind proof preparation

    public void prepareCredBindProof(String userId) {
        log.info("Prepare data for cred-bind proof for user: {}", userId);
        try {
            prepareEudiKeyDerivationProof(userId);
            prepareEudiCredentialVerificationProof(userId);
            prepareEudiCredentailPubKeyProof(userId);
            prepareBlockchainMasterKeyDerivationProof(userId);
        } catch (Exception e) {
            log.error("Failed to prepare data for cred-bind proof for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for cred-bind proof for user: " + userId, e);
        }
    }

    public void prepareEudiKeyDerivationProof(String userId) {
        log.info("Prepare data for EUDI key derivation proof for user: {}", userId);
        try {
            // TODO: Implement the actual logic for preparing EUDI key derivation proof
        } catch (Exception e) {
            log.error("Failed to prepare data for EUDI key derivation proof for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for EUDI key derivation proof for user: " + userId, e);
        }
    }

    public void prepareEudiCredentailPubKeyProof(String userId) {
        log.info("Prepare data for EUDI credential public key inclusion proof for user: {}", userId);
        try {
            // TODO: Implement the actual logic for preparing EUDI credential public key inclusion proof
        } catch (Exception e) {
            log.error("Failed to prepare data for EUDI credential public key inclusion proof for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for EUDI credential public key inclusion proof for user: " + userId, e);
        }
    }

    public void prepareEudiCredentialVerificationProof(String userId) {
        log.info("Prepare data for EUDI credential verification proof for user: {}", userId);
        try {
            Map<String, String> coords = eudiKeyManagementService.getIssuerPublicKeyAffineCoordinates();
            EudiCredentialVerification data = new EudiCredentialVerification(
                    userId,
                    new EudiCredentialVerification.IssuerPublicKey(coords.get("x"), coords.get("y"))
            );
            proofPreparationRegistry.saveEudiCredentialVerification(data);
            log.info("Successfully saved EUDI credential verification data for user: {}", userId);
        } catch (Exception e) {
            log.error("Failed to prepare data for EUDI credential verification for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for EUDI credential verification for user: " + userId, e);
        }
    }

    public void prepareBlockchainMasterKeyDerivationProof(String userId) {
        log.info("Prepare data for Blockchain master key derivation proof for user: {}", userId);
        try {
            // TODO: Implement the actual logic for preparing Blockchain master key derivation proof
        } catch (Exception e) {
            log.error("Failed to prepare data for Blockchain master key derivation proof for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for Blockchain master key derivation proof for user: " + userId, e);
        }
    }

    // key-bind proof preparation

    public void prepareBlockchainChildKeyDerivationProof(String userId) {
        log.info("Prepare data for Blockchain child key derivation proof for user: {}", userId);
        try {
            // TODO: Implement the actual logic for preparing Blockchain child key derivation proof
        } catch (Exception e) {
            log.error("Failed to prepare data for Blockchain child key derivation proof for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for Blockchain child key derivation proof for user: " + userId, e);
        }
    }

    // Monolithic composition proof preparation

    public void prepareMonolithicProof(String userId) {
        log.info("Prepare data for monolithic proof composition for user: {}", userId);
        try {
            prepareCredBindProof(userId);
            prepareBlockchainChildKeyDerivationProof(userId);
        } catch (Exception e) {
            log.error("Failed to prepare data for monolithic proof composition for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for monolithic proof composition for user: " + userId, e);
        }
    }

    // Recursive composition proof preparation

    public void prepareRecursiveProof(String userId) {
        log.info("Prepare data for recursive proof composition for user: {}", userId);
        try {
            prepareCredBindProof(userId);
        } catch (Exception e) {
            log.error("Failed to prepare data for recursive proof composition for user: {}", userId, e);
            throw new RuntimeException("Could not prepare data for recursive proof composition for user: " + userId, e);
        }
    }

}
