package com.sommerph.zkbackend.service.blockchain;

import com.sommerph.zkbackend.model.blockchain.BlockchainWallet;
import com.sommerph.zkbackend.model.blockchain.ChildKey;
import com.sommerph.zkbackend.repository.blockchain.BlockchainWalletRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.crypto.DeterministicKey;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Slf4j
@Service
@RequiredArgsConstructor
public class BlockchainWalletService {

    private final BlockchainKeyManagementService keyManagementService;
    private final BlockchainWalletRegistry walletRegistry;

    public void createWallet(String userId) {
        log.info("Create new blockchain wallet for user: {}", userId);
        if (walletRegistry.exists(userId)) {
            throw new IllegalStateException("Blockchain wallet already exists for user: " + userId);
        }
        try {
            String mnemonic = keyManagementService.generateMnemonic();
            DeterministicKey masterKey = keyManagementService.deriveMasterKey(mnemonic);
            BlockchainWallet wallet = new BlockchainWallet(
                    userId,
                    mnemonic,
                    keyManagementService.encode(masterKey.getPubKey()),
                    keyManagementService.encode(masterKey.getPrivKeyBytes()),
                    new ArrayList<>()
            );
            walletRegistry.save(wallet);
        } catch (Exception e) {
            log.error("Failed to create blockchain wallet for user: {}", userId, e);
            throw new RuntimeException("Could not create blockchain wallet for user: " + userId, e);
        }
    }

    public BlockchainWallet loadWallet(String userId) {
        log.info("Load blockchain wallet for user: {}", userId);
        if (!walletRegistry.exists(userId)) {
            throw new IllegalStateException("No blockchain wallet found for user: " + userId);
        }
        return walletRegistry.load(userId);
    }

    public boolean walletExists(String userId) {
        return walletRegistry.exists(userId);
    }

    public BlockchainWallet recoverWallet(String userId, String mnemonic) {
        log.info("Recover blockchain wallet for user: {}", userId);
        try {
            DeterministicKey masterKey = keyManagementService.deriveMasterKey(mnemonic);
            BlockchainWallet wallet = new BlockchainWallet(
                    userId,
                    mnemonic,
                    keyManagementService.encode(masterKey.getPubKey()),
                    keyManagementService.encode(masterKey.getPrivKeyBytes()),
                    new ArrayList<>()
            );
            walletRegistry.save(wallet);
            return wallet;
        } catch (Exception e) {
            log.error("Failed to recover blockchain wallet for user: {}", userId, e);
            throw new RuntimeException("Blockchain wallet recovery failed for user: " + userId, e);
        }
    }

    public ChildKey deriveChildKey(String userId, int index) {
        log.info("Derive child key for user {} at index {}", userId, index);
        try {
            BlockchainWallet wallet = loadWallet(userId);
            DeterministicKey childKey = keyManagementService.deriveChildKey(wallet.getMnemonic(), index);
            ChildKey result = new ChildKey(keyManagementService.encode(childKey.getPubKey()), index);
            wallet.getChildKeys().add(result);
            walletRegistry.save(wallet);
            return result;
        } catch (Exception e) {
            log.error("Failed to derive child key for user: {}", userId, e);
            throw new RuntimeException("Child key derivation failed for user: " + userId, e);
        }
    }

}
