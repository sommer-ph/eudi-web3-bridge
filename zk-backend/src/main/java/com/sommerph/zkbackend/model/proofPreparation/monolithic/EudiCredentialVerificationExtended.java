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

    // Extended JWS fields for binding proof
    private String[] headerB64;        // Base64url header as ASCII bytes (for SHA-256)
    private String headerB64Length;    // actual length of Base64url header
    private String[] payloadB64;       // Base64url payload as ASCII bytes (for SHA-256)
    private String payloadB64Length;   // actual length of Base64url payload
    
    // Base64url coordinate offsets (for efficient circuit processing)
    private String offXB64;            // start offset of x coordinate in Base64url payload
    private String lenXB64;            // length of x coordinate Base64url string (44 chars)
    private String offYB64;            // start offset of y coordinate in Base64url payload
    private String lenYB64;            // length of y coordinate Base64url string (44 chars)

}