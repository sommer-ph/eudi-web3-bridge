package com.sommerph.zkbackend.model.proofPreparation.recursive;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class OuterProofInput {
    private String userId;
    private String sk0;
    private PublicKeyPoint pk0;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PublicKeyPoint {
        private String x;
        private String y;
    }
}