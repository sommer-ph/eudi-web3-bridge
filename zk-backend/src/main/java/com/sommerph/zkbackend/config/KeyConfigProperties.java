package com.sommerph.zkbackend.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "keys")
public class KeyConfigProperties {

    private String curve;
    private Issuer issuer;
    private Credential credential;

    @Data
    public static class Issuer {
        private String algorithm;
        private String source;
        private String keyId;
    }

    @Data
    public static class Credential {
        private Binding binding;

        @Data
        public static class Binding {
            private String algorithm;
            private boolean generatePerCredential;
        }
    }

}
