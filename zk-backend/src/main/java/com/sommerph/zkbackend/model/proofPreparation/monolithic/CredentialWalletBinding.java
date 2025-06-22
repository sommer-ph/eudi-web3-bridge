package com.sommerph.zkbackend.model.proofPreparation.monolithic;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class CredentialWalletBinding {

    // No user id specified as the resulting file is used by Circom
    // Public statements
    private BigInteger[][] pk_I;  // [2][6]
    private BigInteger[][] pk_0;  // [2][4]
    // Private witnesses
    private BigInteger[] sk_c;    // [6]
    private BigInteger[][] pk_c;  // [2][6]
    private BigInteger[] msghash; // [6]
    private BigInteger[] r;       // [6]
    private BigInteger[] s;       // [6]
    private BigInteger[] sk_0;    // [4]

}
