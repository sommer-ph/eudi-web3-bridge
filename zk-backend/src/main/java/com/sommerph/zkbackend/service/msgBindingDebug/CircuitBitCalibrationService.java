package com.sommerph.zkbackend.service.msgBindingDebug;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sommerph.zkbackend.model.eudi.EudiWallet;
import com.sommerph.zkbackend.model.eudi.EudiCredential;
import com.sommerph.zkbackend.util.msgBindingDebug.CircuitBitMappingCalibrator;
import com.sommerph.zkbackend.util.msgBindingDebug.ReverseEngineerCircuitBits;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.Map;

/**
 * Service to calibrate bit mapping between Java SHA-256 and Circuit SHA-256
 * using debug bits from circuit public output.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Order(1) // Run before the main test service
@org.springframework.context.annotation.Profile("debug")  // Only run in debug profile
public class CircuitBitCalibrationService implements CommandLineRunner {

    private final ObjectMapper objectMapper;

    @Override
    public void run(String... args) throws Exception {
        log.info("🔧 Running Circuit Bit Mapping Calibration...");
        
        try {
            // Circuit debug bits from build/jws-monolithic.public.json (indices 7-70)
            // These are the first 64 bits of sha.out[0..63] as seen by the circuit
            String circuitBitString = "0011010001001100111010011001110010010110000111011001000101100101";
            boolean[] circuitFirst64Bits = new boolean[64];
            for (int i = 0; i < 64; i++) {
                circuitFirst64Bits[i] = circuitBitString.charAt(i) == '1';
            }
            
            // Load test wallet and create same buffer as circuit
            EudiWallet testWallet = loadTestWallet();
            EudiCredential testCredential = testWallet.getCredentials().get(0);
            
            Map<String, Object> header = testCredential.getHeader();
            Map<String, Object> payload = testCredential.getPayload();
            
            // Create circuit buffer (same as in CircuitMsgHash.createCircuitBuffer)
            String headerJson = objectMapper.writeValueAsString(header);
            String payloadJson = objectMapper.writeValueAsString(payload);
            String headerB64 = base64UrlEncodeWithoutPadding(headerJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String payloadB64 = base64UrlEncodeWithoutPadding(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            
            byte[] buffer = createCircuitBuffer(headerB64, payloadB64);
            
            // Compute Java SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] javaDigest = digest.digest(buffer);
            
            log.info("Java SHA-256 digest: {}", CircuitBitMappingCalibrator.bytesToHex(javaDigest));
            log.info("Circuit first 64 bits: {}", circuitBitString);
            
            // Find correct bit mapping
            CircuitBitMappingCalibrator.BitVariant correctVariant = 
                CircuitBitMappingCalibrator.findBitMapping(javaDigest, circuitFirst64Bits);
            
            if (correctVariant != null) {
                log.info("Calibration complete! Correct bit variant: {}", correctVariant);
                
                // Test the complete limb extraction with this variant
                boolean[] allBits = CircuitBitMappingCalibrator.applyBitVariant(javaDigest, correctVariant);
                String[] testLimbs = extractLimbsFromBits(allBits);
                
                log.info("Test limbs with calibrated bit mapping:");
                for (int i = 0; i < testLimbs.length; i++) {
                    log.info("   Limb[{}] = {}", i, testLimbs[i]);
                }
                
                // Compare with expected
                String[] expected = {"903983084076", "4228136620343", "8721219778381", "2472920564340", "4037971556771", "1395065035042"};
                boolean allMatch = true;
                for (int i = 0; i < expected.length; i++) {
                    if (!expected[i].equals(testLimbs[i])) {
                        log.error("Limb {} mismatch: expected={}, computed={}", i, expected[i], testLimbs[i]);
                        allMatch = false;
                    }
                }
                
                if (allMatch) {
                    log.info("PERFECT! All limbs match with calibrated bit mapping!");
                } else {
                    log.error("Limbs still don't match - there may be another issue");
                }
                
                // Store the correct variant for use in CircuitMsgHash
                storeCorrectVariant(correctVariant);
                
            } else {
                log.error("Could not find correct bit mapping variant");
            }
            
            // Try reverse engineering approach
            log.info("\nTrying reverse engineering approach...");
            ReverseEngineerCircuitBits.reverseEngineerFromLimbs();
            
        } catch (Exception e) {
            log.error("Calibration failed", e);
        }
        
        log.info("Circuit Bit Mapping Calibration completed.\n");
    }
    
    private String base64UrlEncodeWithoutPadding(byte[] data) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
    
    private byte[] createCircuitBuffer(String headerB64, String payloadB64) {
        final int HEADER_BUFFER_SIZE = 64;
        final int PAYLOAD_BUFFER_SIZE = 1024;
        final int DOT_POSITION = 64;
        final int TOTAL_BUFFER_SIZE = HEADER_BUFFER_SIZE + 1 + PAYLOAD_BUFFER_SIZE;
        
        byte[] buffer = new byte[TOTAL_BUFFER_SIZE];
        
        byte[] headerBytes = headerB64.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] payloadBytes = payloadB64.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        
        System.arraycopy(headerBytes, 0, buffer, 0, headerBytes.length);
        buffer[DOT_POSITION] = 46; // ASCII dot
        System.arraycopy(payloadBytes, 0, buffer, DOT_POSITION + 1, payloadBytes.length);
        
        return buffer;
    }
    
    private String[] extractLimbsFromBits(boolean[] bits) {
        String[] limbs = new String[6];
        for (int i = 0; i < 6; i++) {
            long acc = 0L;
            for (int j = 0; j < 43; j++) {
                int pos = i * 43 + j;
                if (pos < 256 && bits[pos]) {
                    acc |= (1L << j);  // LSB-first weighting like Bits2Num(43)
                }
            }
            limbs[i] = Long.toString(acc);
        }
        return limbs;
    }
    
    private void storeCorrectVariant(CircuitBitMappingCalibrator.BitVariant variant) {
        // For now just log it - in production you might want to store it in a config
        log.info("📝 Store this bit variant configuration:");
        log.info("   msbFirstPerByte: {}", variant.msbFirstPerByte);
        log.info("   reverseWords: {}", variant.reverseWords);
        log.info("   reverseBytesInWord: {}", variant.reverseBytesInWord);
        log.info("   reverseWholeStream: {}", variant.reverseWholeStream);
    }
    
    private EudiWallet loadTestWallet() throws Exception {
        // Same logic as in CircuitMsgHashTestService
        try {
            java.io.File dataFile = new java.io.File("data/eudi-wallets/test-eudi-wallet.json");
            if (dataFile.exists()) {
                return objectMapper.readValue(dataFile, EudiWallet.class);
            }
        } catch (Exception e) {
            log.debug("Could not load from file system, trying classpath", e);
        }
        
        try {
            org.springframework.core.io.ClassPathResource resource = new org.springframework.core.io.ClassPathResource("test-eudi-wallet.json");
            if (resource.exists()) {
                try (java.io.InputStream is = resource.getInputStream()) {
                    return objectMapper.readValue(is, EudiWallet.class);
                }
            }
        } catch (Exception e) {
            log.debug("Could not load from classpath", e);
        }
        
        throw new RuntimeException("Could not find test-eudi-wallet.json");
    }
}