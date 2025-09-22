package com.sommerph.zkbackend.model.proofPreparation.recursive;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class RecursiveProofExtendedInput {

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    public static class PublicKeyPoint {
        private String x;
        private String y;
    }

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    public static class Signature {
        private String r;
        private String s;
    }

    private PublicKeyPoint pk_issuer;
    private String msg;
    private Signature signature;
    private PublicKeyPoint pk_c;
    private String sk_c;
    private String sk_0;
    private PublicKeyPoint pk_0;
    private String cc_0;
    private int derivation_index;
    private PublicKeyPoint pk_i;
    private String cc_i;

    // Extended JWS fields for binding proof
    private String[] headerB64;        // Base64url header as ASCII bytes (for SHA-256)
    private String headerB64Length;    // actual length of Base64url header
    private String[] payloadB64;       // Base64url payload as ASCII bytes (for SHA-256)
    private String payloadB64Length;   // actual length of Base64url payload

    // Base64url coordinate slice (aligned) + inner selection for efficient circuit processing
    private String offXB64;            // aligned start offset in Base64url payload
    private String lenXB64;            // aligned length (multiple of 4, <=64)
    private String dropX;              // bytes to drop from decoded outer before inner
    private String lenXInner;          // inner Base64url ASCII length (43 or 44)
    private String offYB64;            // aligned start offset in Base64url payload
    private String lenYB64;            // aligned length (multiple of 4, <=64)
    private String dropY;              // bytes to drop from decoded outer before inner
    private String lenYInner;          // inner Base64url ASCII length (43 or 44)

}
