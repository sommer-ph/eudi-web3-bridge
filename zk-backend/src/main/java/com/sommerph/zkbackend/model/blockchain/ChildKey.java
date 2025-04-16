package com.sommerph.zkbackend.model.blockchain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChildKey {
    private String publicKeyBase64;
    private int derivationIndex;
}
