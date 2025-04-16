package com.sommerph.zkbackend.model.eudi;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EudiWallet {

    private String userId;
    private String base64SecretKey;
    private String base64PublicKey;
    private List<EudiCredential> credentials;

    public EudiWallet(String userId, KeyPair keyPair) {
        this.userId = userId;
        this.base64SecretKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        this.base64PublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        this.credentials = new ArrayList<>();
    }

    public void storeCredential(EudiCredential credential) {
        this.credentials.add(credential);
    }

}
