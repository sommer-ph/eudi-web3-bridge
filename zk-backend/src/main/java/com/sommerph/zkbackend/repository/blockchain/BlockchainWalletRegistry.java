package com.sommerph.zkbackend.repository.blockchain;

import com.sommerph.zkbackend.model.blockchain.BlockchainWallet;

public interface BlockchainWalletRegistry {

    void save(BlockchainWallet wallet);

    BlockchainWallet load(String userId);

    boolean exists(String userId);

}
