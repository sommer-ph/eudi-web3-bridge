package com.sommerph.zkbackend.config;

import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.info.Info;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI zkBackendOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("zk-SNARK Preparation API")
                        .version("1.0.0")
                        .description("API for managing wallets (EUDI and Blockchain) and preparing data for zk-SNARK proof generation."));
    }

    @Bean
    public GroupedOpenApi eudiGroup() {
        return GroupedOpenApi.builder()
                .group("eudi")
                .pathsToMatch("/api/eudi/**")
                .build();
    }

    @Bean
    public GroupedOpenApi blockchainGroup() {
        return GroupedOpenApi.builder()
                .group("blockchain")
                .pathsToMatch("/api/blockchain/**")
                .build();
    }

    @Bean
    public GroupedOpenApi proofPreparationGroup() {
        return GroupedOpenApi.builder()
                .group("proof-preparation")
                .pathsToMatch("/api/proof/preparation/**")
                .build();
    }

}
