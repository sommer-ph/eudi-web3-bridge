package com.sommerph.zkbackend.model.proofPreparation.monolithic;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class EudiCredentialPublicKeyCheck {

    private String userId;
    // Extracted public key from credential (cnf.jwk)
    private String[][] pk_cred;  // [2][6] -> 2 x 6 limbs á 43 bits due to x and y coordinates

}
