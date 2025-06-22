package com.sommerph.zkbackend.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "proof.preparation")
public class ProofPreparationProperties {

    private RegistryProperties registry;
    private StorageProperties storage;

    @Data
    public static class RegistryProperties {
        private String type;
    }

    @Data
    public static class StorageProperties {
        private String path;
    }

}
