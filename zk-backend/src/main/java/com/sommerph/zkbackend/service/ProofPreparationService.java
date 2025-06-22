package com.sommerph.zkbackend.service;

import com.sommerph.zkbackend.model.eudi.EudiWallet;
import com.sommerph.zkbackend.model.eudi.EudiCredential;
import com.sommerph.zkbackend.model.blockchain.BlockchainWallet;
import com.sommerph.zkbackend.model.proofPreparation.monolithic.*;
import com.sommerph.zkbackend.repository.proofPreparation.ProofPreparationRegistry;
import com.sommerph.zkbackend.service.eudi.EudiKeyManagementService;
import com.sommerph.zkbackend.service.eudi.EudiWalletService;
import com.sommerph.zkbackend.service.blockchain.BlockchainKeyManagementService;
import com.sommerph.zkbackend.service.blockchain.BlockchainWalletService;
import com.sommerph.zkbackend.util.ExportUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.crypto.DeterministicKey;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProofPreparationService {

    private final EudiWalletService eudiWalletService;
    private final BlockchainWalletService blockchainWalletService;
    private final EudiKeyManagementService eudiKeyManagementService;
    private final BlockchainKeyManagementService blockchainKeyManagementService;
    private final ProofPreparationRegistry proofPreparationRegistry;
    private final ExportUtils exportUtils;

    public void prepareCredBindProof(String userId) {
        log.info("Prepare data for cred-bind proof for user: {}", userId);
        prepareEudiWalletKeyDerivation(userId);
        prepareEudiCredentialPublicKeyCheck(userId);
        prepareEudiCredentialVerification(userId);
        // prepareBlockchainWalletMasterKeyDerivation(userId);
        prepareBlockchainWalletChildKeyDerivation(userId, 0);

        log.info("Export cred-bind proof data for user: {}", userId);
        try {
            CredentialWalletBinding binding = exportUtils.createCredentialWalletBinding(userId, proofPreparationRegistry);
            exportUtils.writeCredBindDataToFile(binding, userId);
        } catch (Exception e) {
            throw new RuntimeException("Failed to export cred-bind proof data for user: " + userId, e);
        }
    }

    // C1
    public void prepareEudiWalletKeyDerivation(String userId) {
        log.info("Prepare data for EUDI wallet key derivation for user: {}", userId);
        try {
            EudiWallet wallet = eudiWalletService.loadWallet(userId);
            String[] skLimbs = eudiKeyManagementService.getUserCredentialSecretKeyLimbs(wallet.getBase64SecretKey());

            EudiKeyDerivation data = new EudiKeyDerivation(
                    userId,
                    skLimbs
            );
            proofPreparationRegistry.saveEudiWalletKeyDerivation(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing EUDI wallet key derivation data for user: " + userId, e);
        }
    }

    // C2
    public void prepareEudiCredentialPublicKeyCheck(String userId) {
        log.info("Prepare data for EUDI credential public key check for user: {}", userId);
        try {
            EudiWallet wallet = eudiWalletService.loadWallet(userId);

            Object cnfObj = wallet.getCredentials().get(0).getPayload().get("cnf");
            if (!(cnfObj instanceof Map)) {
                throw new RuntimeException("CNF field is not a valid map");
            }
            Map<String, Object> cnfMap = (Map<String, Object>) cnfObj;
            Object jwkObj = cnfMap.get("jwk");
            if (!(jwkObj instanceof Map)) {
                throw new RuntimeException("JWK field is not a valid map");
            }
            Map<String, Object> jwkMap = (Map<String, Object>) jwkObj;
            String[][] pkLimbs = eudiKeyManagementService.getCredentialBindingKeyJwkLimbs(jwkMap);

            EudiCredentialPublicKeyCheck data = new EudiCredentialPublicKeyCheck(
                    userId,
                    pkLimbs
            );
            proofPreparationRegistry.saveCredentialPKCheck(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing credential public key check data for user: " + userId, e);
        }
    }

    // C3
    public void prepareEudiCredentialVerification(String userId) {
        log.info("Prepare data for EUDI credential verification for user: {}", userId);
        try {
            EudiWallet wallet = eudiWalletService.loadWallet(userId);
            EudiCredential credential = wallet.getCredentials().get(0);

            String[][] pkILimbs = eudiKeyManagementService.getIssuerPublicKeyLimbs();
            String[] msgHashLimbs = eudiKeyManagementService.computeCredentialMsgHashLimbs(
                    credential.getHeader().toString(),
                    credential.getPayload().toString()
            );
            Map<String, String[]> sigLimbs = eudiKeyManagementService.extractCredentialSignatureLimbs(
                    java.util.Base64.getUrlDecoder().decode(credential.getSignature())
            );

            EudiCredentialVerification data = new EudiCredentialVerification(
                    userId,
                    pkILimbs,
                    msgHashLimbs,
                    sigLimbs.get("r"),
                    sigLimbs.get("s")
            );
            proofPreparationRegistry.saveCredentialSignatureVerification(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing credential verification data for user: " + userId, e);
        }
    }

    // C4
    public void prepareBlockchainWalletMasterKeyDerivation(String userId) {
        prepareBlockchainWalletKeyDerivation(userId, false, 0);
    }

    public void prepareBlockchainWalletChildKeyDerivation(String userId, int index) {
        prepareBlockchainWalletKeyDerivation(userId, true, index);
    }

    private void prepareBlockchainWalletKeyDerivation(String userId, boolean useChild, int index) {
        log.info("Prepare data for blockchain wallet key derivation for user: {}, useChild: {}, index: {}", userId, useChild, index);
        try {
            BlockchainWallet wallet = blockchainWalletService.loadWallet(userId);
            DeterministicKey key;
            if (useChild) {
                key = blockchainKeyManagementService.deriveChildKey(wallet.getMnemonic(), index);
            } else {
                key = blockchainKeyManagementService.deriveMasterKey(wallet.getMnemonic());
            }
            String[] skLimbs = blockchainKeyManagementService.getSecretKeyLimbs(key);
            String[][] pkLimbs = blockchainKeyManagementService.getPublicKeyLimbs(key);
            BlockchainKeyDerivation data = new BlockchainKeyDerivation(
                    userId,
                    skLimbs,
                    pkLimbs
            );
            proofPreparationRegistry.saveBlockchainWalletKeyDerivation(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing blockchain key derivation for user: " + userId, e);
        }
    }

}
