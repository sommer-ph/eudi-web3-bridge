package com.sommerph.zkbackend.model.proofPreparation;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EudiCredentialVerification {

    private String userId;
    private IssuerPublicKey issuerPublicKey;
    // Additional attributes required for EUDI credential verification can be added here

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class IssuerPublicKey {
        private String x;
        private String y;
    }

}
