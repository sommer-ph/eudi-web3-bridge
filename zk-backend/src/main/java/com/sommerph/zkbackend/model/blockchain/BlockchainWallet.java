package com.sommerph.zkbackend.model.blockchain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BlockchainWallet {

    private String userId;

    private String mnemonic;

    private String base64MasterPublicKey;
    private String base64MasterSecretKey;

    private List<ChildKey> childKeys = new ArrayList<>();

    public void addChildKey(ChildKey key) {
        this.childKeys.add(key);
    }

}
