package com.sommerph.zkbackend.model.proofPreparation.monolithic;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class CredentialWalletBindingExtended {

    // No user id specified as the resulting file is used by Circom
    // Public statements
    private BigInteger[][] pk_I;  // [2][6] - shared with EUDI verification
    private BigInteger[][] pk_0;  // [2][4]
    // Private witnesses  
    private BigInteger[] sk_c;    // [6]
    private BigInteger[][] pk_c;  // [2][6]
    private BigInteger[] msghash; // [6] - shared with EUDI verification
    private BigInteger[] r;       // [6] - shared with EUDI verification
    private BigInteger[] s;       // [6] - shared with EUDI verification
    private BigInteger[] sk_0;    // [4]

    // Extended JWS fields for binding proof (Circom-compatible)
    private BigInteger[] headerB64;        // ASCII bytes as BigInteger array
    private BigInteger headerB64Length;    // actual length of header
    private BigInteger[] payloadB64;       // ASCII bytes as BigInteger array  
    private BigInteger payloadB64Length;   // actual length of payload
    
    // JWK extraction offsets/lengths for Circom
    private BigInteger offX;               // start offset of Base64url string of x in decoded payload
    private BigInteger lenX;               // length of x string in characters
    private BigInteger offY;               // start offset of Base64url string of y in decoded payload
    private BigInteger lenY;               // length of y string in characters

}