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

    // Extended JWS fields for binding proof
    private BigInteger[] headerB64;        // Base64url header as ASCII bytes (for SHA-256)
    private BigInteger headerB64Length;    // actual length of Base64url header
    private BigInteger[] payloadB64;       // Base64url payload as ASCII bytes (for SHA-256)
    private BigInteger payloadB64Length;   // actual length of Base64url payload
    
    // Aligned Base64url coordinate slice + inner selection
    private BigInteger offXB64;            // aligned start offset of x in Base64url payload
    private BigInteger lenXB64;            // aligned length (<=64)
    private BigInteger dropX;              // bytes to drop after outer decode
    private BigInteger lenXInner;          // inner Base64url ASCII length (43/44)
    private BigInteger offYB64;            // aligned start offset of y in Base64url payload
    private BigInteger lenYB64;            // aligned length (<=64)
    private BigInteger dropY;              // bytes to drop after outer decode
    private BigInteger lenYInner;          // inner Base64url ASCII length (43/44)

}
