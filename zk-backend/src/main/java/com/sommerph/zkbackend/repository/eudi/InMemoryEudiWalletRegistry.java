package com.sommerph.zkbackend.repository.eudi;

import com.sommerph.zkbackend.model.eudi.EudiWallet;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class InMemoryEudiWalletRegistry implements EudiWalletRegistry {

    private final Map<String, EudiWallet> walletStore = new ConcurrentHashMap<>();

    @Override
    public void save(EudiWallet wallet) {
        log.info("Save wallet for user {}", wallet.getUserId());
        try {
            walletStore.put(wallet.getUserId(), wallet);
        } catch (Exception e) {
            log.error("Failed to save wallet for user: {}", wallet.getUserId(), e);
            throw new RuntimeException("Failed to save wallet for user: " + wallet.getUserId(), e);
        }
    }

    @Override
    public EudiWallet load(String userId) {
        log.info("Load wallet for user {} ", userId);
        try {
            return walletStore.get(userId);
        } catch (Exception e) {
            log.error("Failed to load wallet for user: {}", userId, e);
            throw new RuntimeException("Failed to load wallet for user: " + userId, e);
        }
    }

    @Override
    public boolean exists(String userId) {
        return walletStore.containsKey(userId);
    }

}
