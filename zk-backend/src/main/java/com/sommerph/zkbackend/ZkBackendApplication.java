package com.sommerph.zkbackend;

import com.sommerph.zkbackend.config.KeyConfigProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(KeyConfigProperties.class)
public class ZkBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(ZkBackendApplication.class, args);
	}

}
