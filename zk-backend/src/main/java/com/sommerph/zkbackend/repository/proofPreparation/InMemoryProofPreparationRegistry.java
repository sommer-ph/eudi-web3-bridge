package com.sommerph.zkbackend.repository.proofPreparation;

import com.sommerph.zkbackend.model.proofPreparation.monolithic.*;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class InMemoryProofPreparationRegistry implements ProofPreparationRegistry {

    // Separate stores for each model
    private final Map<String, EudiKeyDerivation> eudiWalletKeyStore = new ConcurrentHashMap<>();
    private final Map<String, EudiCredentialPublicKeyCheck> credentialPKStore = new ConcurrentHashMap<>();
    private final Map<String, EudiCredentialVerification> credentialVerificationStore = new ConcurrentHashMap<>();
    private final Map<String, BlockchainKeyDerivation> blockchainWalletStore = new ConcurrentHashMap<>();

    // C1
    @Override
    public void saveEudiWalletKeyDerivation(EudiKeyDerivation data) {
        eudiWalletKeyStore.put(data.getUserId(), data);
    }

    @Override
    public EudiKeyDerivation loadEudiWalletKeyDerivation(String userId) {
        return eudiWalletKeyStore.get(userId);
    }

    @Override
    public boolean existsEudiWalletKeyDerivation(String userId) {
        return eudiWalletKeyStore.containsKey(userId);
    }

    // C2
    @Override
    public void saveCredentialPKCheck(EudiCredentialPublicKeyCheck data) {
        credentialPKStore.put(data.getUserId(), data);
    }

    @Override
    public EudiCredentialPublicKeyCheck loadCredentialPKCheck(String userId) {
        return credentialPKStore.get(userId);
    }

    @Override
    public boolean existsCredentialPKCheck(String userId) {
        return credentialPKStore.containsKey(userId);
    }

    // C3
    @Override
    public void saveCredentialSignatureVerification(EudiCredentialVerification data) {
        credentialVerificationStore.put(data.getUserId(), data);
    }

    @Override
    public EudiCredentialVerification loadCredentialSignatureVerification(String userId) {
        return credentialVerificationStore.get(userId);
    }

    @Override
    public boolean existsCredentialSignatureVerification(String userId) {
        return credentialVerificationStore.containsKey(userId);
    }

    // C4
    @Override
    public void saveBlockchainWalletKeyDerivation(BlockchainKeyDerivation data) {
        blockchainWalletStore.put(data.getUserId(), data);
    }

    @Override
    public BlockchainKeyDerivation loadBlockchainWalletKeyDerivation(String userId) {
        return blockchainWalletStore.get(userId);
    }

    @Override
    public boolean existsBlockchainWalletKeyDerivation(String userId) {
        return blockchainWalletStore.containsKey(userId);
    }

    // For every new model in proofPreparation that represent a high-level constraint, implement methods for save, load, and exists as specified in interface.

}
