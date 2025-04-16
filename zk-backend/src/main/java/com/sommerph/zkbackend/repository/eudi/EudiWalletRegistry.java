package com.sommerph.zkbackend.repository.eudi;

import com.sommerph.zkbackend.model.eudi.EudiWallet;

public interface EudiWalletRegistry {

    void save(EudiWallet wallet);

    EudiWallet load(String userId);

    boolean exists(String userId);

}
