package com.sommerph.zkbackend.model.proofPreparation.monolithic;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class EudiCredentialVerification {

    private String userId;
    private String[][] pk_I;  // [2][6] -> 2 x 6 limbs á 43 bits due to x and y coordinates
    // SHA-256 hash of signing input = base64url(header) + "." + base64url(payload)
    private String[] msghash;  // [6] -> 6 limbs á 43 bits
    // Signature components
    private String[] r;        // [6] -> 6 limbs á 43 bits
    private String[] s;        // [6] -> 6 limbs á 43 bits

}
