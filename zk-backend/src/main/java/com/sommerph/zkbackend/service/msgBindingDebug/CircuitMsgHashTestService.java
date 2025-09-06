package com.sommerph.zkbackend.service.msgBindingDebug;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sommerph.zkbackend.model.eudi.EudiWallet;
import com.sommerph.zkbackend.model.eudi.EudiCredential;
import com.sommerph.zkbackend.util.msgBindingDebug.CircuitMsgHash;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Map;

/**
 * Service to test CircuitMsgHash utility on startup with test-eudi-wallet.json data.
 * This verifies that our Java implementation produces the same limbs as the circuit.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@org.springframework.context.annotation.Profile("debug")  // Only run in debug profile
public class CircuitMsgHashTestService implements CommandLineRunner {

    private final ObjectMapper objectMapper;

    @Override
    public void run(String... args) throws Exception {
        log.info("Testing CircuitMsgHash utility with test-eudi-wallet.json...");
        
        try {
            // Load test-eudi-wallet.json from data directory
            EudiWallet testWallet = loadTestWallet();
            EudiCredential testCredential = testWallet.getCredentials().get(0);
            
            // Extract header and payload
            Map<String, Object> header = testCredential.getHeader();
            Map<String, Object> payload = testCredential.getPayload();
            
            log.info("📄 Test credential header: {}", header);
            log.info("📄 Test credential payload keys: {}", payload.keySet());
            
            // Compute circuit-compatible message hash limbs
            String[] computedLimbs = CircuitMsgHash.computeMsgHashLimbs(header, payload);
            
            log.info("🧮 Computed {} limbs:", computedLimbs.length);
            for (int i = 0; i < computedLimbs.length; i++) {
                log.info("   Limb[{}] = {}", i, computedLimbs[i]);
            }
            
            // Validate against expected circuit values
            boolean matches = CircuitMsgHash.validateAgainstExpectedLimbs(computedLimbs);
            
            if (matches) {
                log.info("   SUCCESS: CircuitMsgHash produces EXACT same limbs as zk-monolithic-experiments circuit!");
                log.info("   Expected: [903983084076, 4228136620343, 8721219778381, 2472920564340, 4037971556771, 1395065035042]");
                log.info("   Computed: {}", Arrays.toString(computedLimbs));
            } else {
                log.error("   FAILURE: CircuitMsgHash limbs do NOT match circuit expectations!");
                log.error("   This means there's still a difference in hash calculation between Java backend and circuit.");
                log.error("   Expected: [903983084076, 4228136620343, 8721219778381, 2472920564340, 4037971556771, 1395065035042]");
                log.error("   Computed: {}", Arrays.toString(computedLimbs));
            }
            
        } catch (Exception e) {
            log.error("ERROR: Failed to test CircuitMsgHash utility", e);
        }
        
        log.info("CircuitMsgHash test completed.\n");
    }
    
    private EudiWallet loadTestWallet() throws Exception {
        // Try to load from file system first (data/eudi-wallets/test-eudi-wallet.json)
        try {
            java.io.File dataFile = new java.io.File("data/eudi-wallets/test-eudi-wallet.json");
            if (dataFile.exists()) {
                log.info("Loading test wallet from: {}", dataFile.getAbsolutePath());
                return objectMapper.readValue(dataFile, EudiWallet.class);
            }
        } catch (Exception e) {
            log.debug("Could not load from file system, trying classpath", e);
        }
        
        // Fallback: try to load from classpath
        try {
            ClassPathResource resource = new ClassPathResource("test-eudi-wallet.json");
            if (resource.exists()) {
                try (InputStream is = resource.getInputStream()) {
                    log.info("Loading test wallet from classpath");
                    return objectMapper.readValue(is, EudiWallet.class);
                }
            }
        } catch (Exception e) {
            log.debug("Could not load from classpath", e);
        }
        
        throw new RuntimeException("Could not find test-eudi-wallet.json in data/eudi-wallets/ or classpath");
    }
}