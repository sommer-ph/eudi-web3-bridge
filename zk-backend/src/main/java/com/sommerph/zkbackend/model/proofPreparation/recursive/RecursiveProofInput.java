package com.sommerph.zkbackend.model.proofPreparation.recursive;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class RecursiveProofInput {

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

}