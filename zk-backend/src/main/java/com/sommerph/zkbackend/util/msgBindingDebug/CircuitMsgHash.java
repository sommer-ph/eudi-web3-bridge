package com.sommerph.zkbackend.util.msgBindingDebug;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * Circuit-compatible message hash calculation utility.
 * 
 * This utility implements the exact same hash calculation logic as the zk-monolithic-experiments circuit:
 * 1. Serialize header/payload JSON compactly (no spaces)
 * 2. Base64url encode without padding
 * 3. Pad to fixed buffer sizes (header: 64, payload: 1024 bytes)
 * 4. Insert dot separator at index 64
 * 5. Calculate SHA-256 over the complete buffer including null padding
 * 6. Interpret digest bits LSB-first and split into 6×43-bit limbs
 */
@Slf4j
public final class CircuitMsgHash {

    private CircuitMsgHash() {}

    private static final int HEADER_BUFFER_SIZE = 64;
    private static final int PAYLOAD_BUFFER_SIZE = 1024;
    private static final int DOT_POSITION = 64; // Index where dot separator is inserted
    private static final int TOTAL_BUFFER_SIZE = HEADER_BUFFER_SIZE + 1 + PAYLOAD_BUFFER_SIZE; // +1 for dot
    private static final int LIMB_BITS = 43;
    private static final int NUM_LIMBS = 6;

    /**
     * Computes message hash limbs exactly as the circuit does.
     * 
     * @param header JWT header as Map
     * @param payload JWT payload as Map
     * @return Array of 6 limb values as strings (compatible with circuit expectations)
     * @throws RuntimeException if hash calculation fails
     */
    public static String[] computeMsgHashLimbs(Map<String, Object> header, Map<String, Object> payload) {
        try {
            // Step 1: Serialize JSON compactly (no spaces)
            ObjectMapper mapper = new ObjectMapper();
            String headerJson = mapper.writeValueAsString(header);
            String payloadJson = mapper.writeValueAsString(payload);
            
            log.debug("Header JSON (compact): {}", headerJson);
            log.debug("Payload JSON (compact): {}", payloadJson);

            // Step 2: Base64url encode without padding
            String headerB64 = base64UrlEncodeWithoutPadding(headerJson.getBytes(StandardCharsets.UTF_8));
            String payloadB64 = base64UrlEncodeWithoutPadding(payloadJson.getBytes(StandardCharsets.UTF_8));
            
            log.debug("Header Base64url: {}", headerB64);
            log.debug("Payload Base64url: {}", payloadB64);

            // Step 3: Create fixed-size buffer with padding
            byte[] buffer = createCircuitBuffer(headerB64, payloadB64);
            
            log.debug("Buffer size: {}", buffer.length);
            log.debug("Buffer content (first 100 bytes): {}", Arrays.toString(Arrays.copyOf(buffer, Math.min(100, buffer.length))));

            // Step 4: Calculate SHA-256 over complete buffer
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(buffer);
            
            log.debug("SHA-256 hash: {}", bytesToHex(hash));

            // Step 5: Convert to limbs (LSB-first interpretation)
            String[] limbs = hashToLimbs(hash);
            
            log.info("Computed circuit-compatible message hash limbs: {}", Arrays.toString(limbs));
            return limbs;

        } catch (Exception e) {
            throw new RuntimeException("Failed to compute circuit message hash limbs", e);
        }
    }

    /**
     * Base64url encode without padding (as required by JWT/JOSE standard).
     */
    private static String base64UrlEncodeWithoutPadding(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Creates the circuit buffer with exact layout:
     * - Header Base64url ASCII bytes (padded to 64 bytes with nulls)
     * - Dot separator (ASCII 46) at index 64
     * - Payload Base64url ASCII bytes (padded to 1024 bytes with nulls)
     */
    private static byte[] createCircuitBuffer(String headerB64, String payloadB64) {
        byte[] buffer = new byte[TOTAL_BUFFER_SIZE];
        
        // Convert Base64url strings to ASCII bytes
        byte[] headerBytes = headerB64.getBytes(StandardCharsets.US_ASCII);
        byte[] payloadBytes = payloadB64.getBytes(StandardCharsets.US_ASCII);
        
        // Validate sizes don't exceed buffer limits
        if (headerBytes.length > HEADER_BUFFER_SIZE) {
            throw new IllegalArgumentException("Header Base64url too long: " + headerBytes.length + " > " + HEADER_BUFFER_SIZE);
        }
        if (payloadBytes.length > PAYLOAD_BUFFER_SIZE) {
            throw new IllegalArgumentException("Payload Base64url too long: " + payloadBytes.length + " > " + PAYLOAD_BUFFER_SIZE);
        }
        
        // Copy header bytes (rest remains zero-padded)
        System.arraycopy(headerBytes, 0, buffer, 0, headerBytes.length);
        
        // Insert dot separator at fixed position
        buffer[DOT_POSITION] = 46; // ASCII code for '.'
        
        // Copy payload bytes after dot (rest remains zero-padded)
        System.arraycopy(payloadBytes, 0, buffer, DOT_POSITION + 1, payloadBytes.length);
        
        return buffer;
    }

    /**
     * Converts SHA-256 hash to 6×43-bit limbs using the exact circuit logic.
     * 
     * EXACTLY matching the circuit:
     * 1. Combined buffer -> Num2Bits(8) per byte (LSB-first output)  
     * 2. SHA256 gets sequential bits BUT with 32-bit word bit reversal!
     * 3. SHA256 outputs with 32-bit word bit reversal: out[i*32+31-j] = (H[i] >> j) & 1
     * 4. Bits2Num(43): limb[i] = sum(sha.out[i*43+j] * 2^j) for j=0..42
     * 
     * Key insight from circomlib/sha256/sha256compression.circom line 76:
     * w[t][k] <== inp[t*32+31-k];  // 32-bit word bit reversal!
     */
    private static String[] hashToLimbs(byte[] hash) {
        log.debug("Hash bytes: {}", bytesToHex(hash));
        
        // Step 1: Convert hash bytes to bits with CIRCOM's 32-bit word bit reversal
        // Circom SHA-256 output: out[i*32+31-j] = (H[i] >> j) & 1 
        boolean[] sha_out = new boolean[256];
        
        // Process in 32-bit (4-byte) words to match circuit
        for (int word = 0; word < 8; word++) { // 256 bits = 8 * 32-bit words
            // Get the 4 bytes for this word (big-endian from hash)
            int wordValue = 0;
            for (int b = 0; b < 4; b++) {
                wordValue = (wordValue << 8) | (hash[word * 4 + b] & 0xFF);
            }
            
            // Apply Circom's bit reversal: out[word*32+31-j] = (H[word] >> j) & 1
            for (int j = 0; j < 32; j++) {
                boolean bit = ((wordValue >>> j) & 1) == 1;
                sha_out[word * 32 + (31 - j)] = bit;  // Bit reversal within word!
            }
        }
        
        // Step 2: Extract limbs using Bits2Num(43) logic  
        // EXACTLY like circuit lines 79-90
        final int LIMB_BITS = 43;
        final int NUM_LIMBS = 6;
        
        String[] limbs = new String[NUM_LIMBS];
        for (int i = 0; i < NUM_LIMBS; i++) {
            long limb = 0L; // 43 bits fits in long
            
            // Bits2Num(43): out = sum(in[j] * 2^j) for j=0..42
            for (int j = 0; j < LIMB_BITS; j++) {
                int bitPos = i * LIMB_BITS + j;    // Sequential: 0..255
                if (bitPos < 256 && sha_out[bitPos]) {
                    limb |= (1L << j);             // Add 2^j if bit is set
                }
            }
            
            limbs[i] = Long.toString(limb);
            log.debug("Limb {}: value={}", i, limbs[i]);
        }
        
        return limbs;
    }
    
    /**
     * Fallback method for other hashes - implements the best transformation we found.
     */
    private static String[] hashToLimbsFallback(byte[] hash) {
        // Apply best transformation: "Reverse words, LSB-first" with distance 21
        byte[] transformedHash = reverseWordsTransformation(hash);
        
        // Extract bits LSB-first per byte
        boolean[] bits = new boolean[256];
        int k = 0;
        for (int i = 0; i < 32; i++) {
            int b = transformedHash[i] & 0xFF;
            for (int j = 0; j < 8; j++) {
                bits[k++] = ((b >> j) & 1) == 1;
            }
        }
        
        // Convert to limbs
        String[] limbs = new String[NUM_LIMBS];
        for (int i = 0; i < NUM_LIMBS; i++) {
            BigInteger limbValue = BigInteger.ZERO;
            for (int j = 0; j < LIMB_BITS; j++) {
                int bitPos = i * LIMB_BITS + j;
                if (bitPos < 256 && bits[bitPos]) {
                    limbValue = limbValue.add(BigInteger.ONE.shiftLeft(j));
                }
            }
            limbs[i] = limbValue.toString();
        }
        
        return limbs;
    }
    
    /**
     * Construct the remaining 192 bits (after the known first 64) from the hash.
     * This is a temporary solution until we figure out the exact transformation.
     */
    private static String constructRemainingBits(byte[] hash) {
        StringBuilder remaining = new StringBuilder();
        
        // Apply the best transformation we found: "Reverse words, LSB-first"
        // Transform the hash and extract bits 64-255
        byte[] transformedHash = reverseWordsTransformation(hash);
        
        // Extract bits 64-255 using LSB-first per byte
        for (int i = 8; i < 32; i++) { // Start from byte 8 (bit 64)
            int b = transformedHash[i] & 0xFF;
            for (int j = 0; j < 8; j++) {
                remaining.append(((b >> j) & 1) == 1 ? '1' : '0');
            }
        }
        
        return remaining.toString();
    }
    
    /**
     * Apply "reverse words" transformation that showed best results.
     */
    private static byte[] reverseWordsTransformation(byte[] hash) {
        byte[] result = new byte[32];
        
        // Reverse 4-byte words (8 words total)
        for (int word = 0; word < 8; word++) {
            int srcStart = word * 4;
            int dstStart = (7 - word) * 4; // Reverse word order
            
            // Copy word in original byte order
            System.arraycopy(hash, srcStart, result, dstStart, 4);
        }
        
        return result;
    }

    /**
     * Helper method to convert bytes to hex string for debugging.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Validates that the computed limbs match expected circuit values.
     * Expected values from your circuit debug output:
     * [903983084076, 4228136620343, 8721219778381, 2472920564340, 4037971556771, 1395065035042]
     */
    public static boolean validateAgainstExpectedLimbs(String[] computedLimbs) {
        String[] expectedLimbs = {
            "903983084076",
            "4228136620343", 
            "8721219778381",
            "2472920564340",
            "4037971556771",
            "1395065035042"
        };
        
        if (computedLimbs.length != expectedLimbs.length) {
            log.error("Limb count mismatch: computed={}, expected={}", computedLimbs.length, expectedLimbs.length);
            return false;
        }
        
        boolean allMatch = true;
        for (int i = 0; i < expectedLimbs.length; i++) {
            if (!expectedLimbs[i].equals(computedLimbs[i])) {
                log.error("Limb {} mismatch: computed={}, expected={}", i, computedLimbs[i], expectedLimbs[i]);
                allMatch = false;
            }
        }
        
        if (allMatch) {
            log.info("All computed limbs match expected circuit values!");
        } else {
            log.error("Computed limbs do NOT match expected circuit values");
        }
        
        return allMatch;
    }
}