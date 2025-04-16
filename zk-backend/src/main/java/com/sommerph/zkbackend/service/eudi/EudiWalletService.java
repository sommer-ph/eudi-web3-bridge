package com.sommerph.zkbackend.service.eudi;

import com.sommerph.zkbackend.model.eudi.EudiCredential;
import com.sommerph.zkbackend.model.eudi.EudiWallet;
import com.sommerph.zkbackend.repository.eudi.EudiWalletRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;

@Slf4j
@Service
@RequiredArgsConstructor
public class EudiWalletService {

    private final EudiKeyManagementService keyManagementService;
    private final EudiWalletRegistry walletRegistry;

    public void createWallet(String userId) {
        log.info("Create new eudi wallet for user: {}", userId);
        if (walletRegistry.exists(userId)) {
            throw new IllegalStateException("Eudi wallet already exists for user: " + userId);
        }
        try {
            KeyPair keyPair = keyManagementService.generateKeyPair();
            EudiWallet wallet = new EudiWallet(userId, keyPair);
            walletRegistry.save(wallet);
        } catch (Exception e) {
            log.error("Failed to create eudi wallet for user: {}", userId, e);
            throw new RuntimeException("Could not create eudi wallet for user: " + userId, e);
        }
    }

    public EudiWallet loadWallet(String userId) {
        log.info("Load eudi wallet for user: {}", userId);
        if (!walletRegistry.exists(userId)) {
            throw new IllegalStateException("No eudi wallet found for user: " + userId);
        }
        return walletRegistry.load(userId);
    }

    public boolean walletExists(String userId) {
        return walletRegistry.exists(userId);
    }

    public void addCredential(String userId, EudiCredential credential) {
        log.info("Add credential to wallet for user: {}", userId);
        EudiWallet wallet = loadWallet(userId);
        wallet.storeCredential(credential);
        walletRegistry.save(wallet);
    }

}
