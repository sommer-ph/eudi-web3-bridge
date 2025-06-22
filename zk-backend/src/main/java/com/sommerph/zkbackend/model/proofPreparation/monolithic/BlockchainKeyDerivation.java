package com.sommerph.zkbackend.model.proofPreparation.monolithic;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class BlockchainKeyDerivation {

    private String userId;
    private String[] sk_0;  // [4] -> 4 limbs á 64 bits
    private String[][] pk_0;  // [2][4] -> 2 x 4 limbs á 64 bits due to x and y coordinates

}
