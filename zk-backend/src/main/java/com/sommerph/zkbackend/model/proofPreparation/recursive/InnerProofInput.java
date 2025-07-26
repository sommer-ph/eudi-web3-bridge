package com.sommerph.zkbackend.model.proofPreparation.recursive;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class InnerProofInput {
    private String userId;
    private String msg;
    private PublicKeyPoint pk_cred;
    private PublicKeyPoint pk_i;
    private Signature signature;
    private String sk_c;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PublicKeyPoint {
        private String x;
        private String y;
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Signature {
        private String r;
        private String s;
    }
}