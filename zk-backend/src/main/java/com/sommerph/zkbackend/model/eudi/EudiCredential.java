package com.sommerph.zkbackend.model.eudi;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EudiCredential {

     // SD-JWT header
    private Map<String, Object> header;

    // SD-JWT payload
    private Map<String, Object> payload;

    // SD-JWT signature (from issuer)
    private String signature;

    // Disclosure list
    List<Map<String, String>> disclosures;

}
