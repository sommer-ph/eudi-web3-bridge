package com.sommerph.zkbackend.model.proofPreparation.monolithic;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class EudiKeyDerivation {

    private String userId;
    private String[] sk_c;  // [6] -> 6 limbs á 43 bits

}
