package com.sommerph.zkbackend.repository.blockchain;

import com.sommerph.zkbackend.model.blockchain.BlockchainWallet;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class InMemoryBlockchainWalletRegistry implements BlockchainWalletRegistry {

    private final Map<String, BlockchainWallet> walletStore = new ConcurrentHashMap<>();

    @Override
    public void save(BlockchainWallet wallet) {
        log.info("Save blockchain wallet for user {}", wallet.getUserId());
        try {
            walletStore.put(wallet.getUserId(), wallet);
        } catch (Exception e) {
            log.error("Failed to save blockchain wallet for user: {}", wallet.getUserId(), e);
            throw new RuntimeException("Failed to save blockchain wallet for user: " + wallet.getUserId(), e);
        }
    }

    @Override
    public BlockchainWallet load(String userId) {
        log.info("Load blockchain wallet for user {} ", userId);
        try {
            return walletStore.get(userId);
        } catch (Exception e) {
            log.error("Failed to load blockchain wallet for user: {}", userId, e);
            throw new RuntimeException("Failed to load blockchain wallet for user: " + userId, e);
        }
    }

    @Override
    public boolean exists(String userId) {
        return walletStore.containsKey(userId);
    }

}
