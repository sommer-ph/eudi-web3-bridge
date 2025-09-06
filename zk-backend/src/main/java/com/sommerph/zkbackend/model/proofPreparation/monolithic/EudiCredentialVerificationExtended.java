package com.sommerph.zkbackend.model.proofPreparation.monolithic;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class EudiCredentialVerificationExtended {

    private String userId;
    private String[][] pk_I;  // [2][6] -> 2 x 6 limbs á 43 bits due to x and y coordinates
    // SHA-256 hash of signing input = base64url(header) + "." + base64url(payload)
    private String[] msghash;  // [6] -> 6 limbs á 43 bits
    // Signature components
    private String[] r;        // [6] -> 6 limbs á 43 bits
    private String[] s;        // [6] -> 6 limbs á 43 bits

    // Extended JWS fields for binding proof (Circom-compatible)
    private String[] headerB64;        // ASCII bytes as String array (for compatibility)
    private String headerB64Length;    // actual length of header
    private String[] payloadB64;       // ASCII bytes as String array (for compatibility)  
    private String payloadB64Length;   // actual length of payload
    
    // JWK extraction offsets/lengths
    private String offX;               // start offset of Base64url string of x in decoded payload
    private String lenX;               // length of x string in characters
    private String offY;               // start offset of Base64url string of y in decoded payload
    private String lenY;               // length of y string in characters

}