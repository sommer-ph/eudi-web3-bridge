package com.sommerph.zkbackend.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "eudi.credential")
public class EudiCredentialConfigProperties {
    private List<String> claims;
    private boolean signingInputPadded = false; // Default to RFC-conform behavior
}
