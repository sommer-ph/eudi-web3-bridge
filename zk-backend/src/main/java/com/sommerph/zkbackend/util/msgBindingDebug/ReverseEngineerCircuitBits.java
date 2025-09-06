package com.sommerph.zkbackend.util.msgBindingDebug;

import lombok.extern.slf4j.Slf4j;

/**
 * Reverse engineer the expected bit sequence from known correct limbs.
 * This helps us understand what bit pattern the circuit expects.
 */
@Slf4j
public final class ReverseEngineerCircuitBits {

    private ReverseEngineerCircuitBits() {}

    /**
     * Convert expected limbs back to bit sequence to understand circuit's bit interpretation.
     */
    public static void reverseEngineerFromLimbs() {
        // Expected limbs from circuit
        long[] expectedLimbs = {
            903983084076L,
            4228136620343L, 
            8721219778381L,
            2472920564340L,
            4037971556771L,
            1395065035042L
        };
        
        log.info("Reverse engineering bit sequence from expected limbs...");
        
        // Convert limbs back to bits (LSB-first interpretation like Bits2Num(43))
        boolean[] expectedBits = new boolean[256];
        
        for (int limbIndex = 0; limbIndex < 6; limbIndex++) {
            long limbValue = expectedLimbs[limbIndex];
            log.info("Limb[{}] = {} (0x{:x})", limbIndex, limbValue, limbValue);
            
            // Extract 43 bits from this limb (LSB-first)
            for (int bitInLimb = 0; bitInLimb < 43; bitInLimb++) {
                int globalBitIndex = limbIndex * 43 + bitInLimb;
                if (globalBitIndex < 256) {
                    expectedBits[globalBitIndex] = (limbValue & (1L << bitInLimb)) != 0;
                }
            }
        }
        
        // Show expected bit pattern (first 64 bits)
        StringBuilder expectedBitString = new StringBuilder();
        for (int i = 0; i < 64; i++) {
            expectedBitString.append(expectedBits[i] ? '1' : '0');
        }
        log.info("Expected first 64 bits from limbs: {}", expectedBitString.toString());
        
        // Compare with circuit debug bits
        String circuitBitString = "0011010001001100111010011001110010010110000111011001000101100101";
        log.info("Circuit debug bits (actual):     {}", circuitBitString);
        
        // Calculate hamming distance
        int hammingDistance = 0;
        for (int i = 0; i < 64; i++) {
            boolean expectedBit = expectedBits[i];
            boolean circuitBit = circuitBitString.charAt(i) == '1';
            if (expectedBit != circuitBit) {
                hammingDistance++;
            }
        }
        
        log.info("Hamming distance between expected and circuit bits: {}", hammingDistance);
        
        if (hammingDistance == 0) {
            log.info("Perfect match! The circuit bits match the expected limb pattern.");
        } else {
            log.warn("Mismatch detected. Need to investigate further.");
            
            // Show bit-by-bit comparison for first 32 bits
            log.info("Bit-by-bit comparison (first 32 bits):");
            for (int i = 0; i < 32; i++) {
                boolean expectedBit = expectedBits[i];
                boolean circuitBit = circuitBitString.charAt(i) == '1';
                String match = expectedBit == circuitBit ? "✓" : "✗";
                log.info("Bit[{}]: expected={}, circuit={} {}", i, expectedBit ? 1 : 0, circuitBit ? 1 : 0, match);
            }
        }
        
        // Try to reconstruct what the Java SHA-256 should produce
        log.info("\nNow checking if our Java SHA-256 can be transformed to match expected bits...");
        
        // Java digest: af81df7c89c4160e251da5d98bdde92ab132acafd591a5412eb04a42131ca221
        byte[] javaDigest = hexToBytes("af81df7c89c4160e251da5d98bdde92ab132acafd591a5412eb04a42131ca221");
        
        // Test various transformations to see if any match the expected bit pattern
        testTransformations(javaDigest, expectedBits);
    }
    
    private static void testTransformations(byte[] javaDigest, boolean[] expectedBits) {
        log.info("Testing various transformations of Java SHA-256 digest...");
        
        // Test more exotic transformations
        String[] transformNames = {
            "Direct MSB-first",
            "Direct LSB-first", 
            "Reverse bytes, MSB-first",
            "Reverse bytes, LSB-first",
            "Reverse words, MSB-first",
            "Reverse words, LSB-first",
            "Reverse all + MSB-first",
            "Reverse all + LSB-first",
            "Bit-reverse each byte, keep byte order",
            "Bit-reverse each byte, reverse byte order"
        };
        
        for (int t = 0; t < transformNames.length; t++) {
            boolean[] transformedBits = applyTransformation(javaDigest, t);
            int distance = hammingDistance(transformedBits, expectedBits, 64);
            
            log.info("{}: Hamming distance = {}", transformNames[t], distance);
            
            if (distance == 0) {
                log.info("PERFECT MATCH found with transformation: {}", transformNames[t]);
                break;
            }
        }
    }
    
    private static boolean[] applyTransformation(byte[] digest, int transformationType) {
        boolean[] bits = new boolean[256];
        byte[] workingDigest = digest.clone();
        
        switch (transformationType) {
            case 0: // Direct MSB-first
                for (int i = 0; i < 32; i++) {
                    int b = workingDigest[i] & 0xFF;
                    for (int j = 7; j >= 0; j--) {
                        bits[i * 8 + (7 - j)] = ((b >> j) & 1) == 1;
                    }
                }
                break;
                
            case 1: // Direct LSB-first
                for (int i = 0; i < 32; i++) {
                    int b = workingDigest[i] & 0xFF;
                    for (int j = 0; j < 8; j++) {
                        bits[i * 8 + j] = ((b >> j) & 1) == 1;
                    }
                }
                break;
                
            case 2: // Reverse bytes, MSB-first
                for (int i = 0; i < 16; i++) {
                    byte temp = workingDigest[i];
                    workingDigest[i] = workingDigest[31 - i];
                    workingDigest[31 - i] = temp;
                }
                return applyTransformation(workingDigest, 0);
                
            case 3: // Reverse bytes, LSB-first  
                for (int i = 0; i < 16; i++) {
                    byte temp = workingDigest[i];
                    workingDigest[i] = workingDigest[31 - i];
                    workingDigest[31 - i] = temp;
                }
                return applyTransformation(workingDigest, 1);
                
            case 4: // Reverse words, MSB-first
                for (int w = 0; w < 4; w++) {
                    for (int b = 0; b < 2; b++) {
                        byte temp = workingDigest[w * 8 + b];
                        workingDigest[w * 8 + b] = workingDigest[w * 8 + 7 - b];
                        workingDigest[w * 8 + 7 - b] = temp;
                    }
                }
                return applyTransformation(workingDigest, 0);
                
            case 5: // Reverse words, LSB-first
                for (int w = 0; w < 4; w++) {
                    for (int b = 0; b < 2; b++) {
                        byte temp = workingDigest[w * 8 + b];
                        workingDigest[w * 8 + b] = workingDigest[w * 8 + 7 - b];
                        workingDigest[w * 8 + 7 - b] = temp;
                    }
                }
                return applyTransformation(workingDigest, 1);
                
            case 6: // Reverse all + MSB-first
                boolean[] temp6 = applyTransformation(digest, 0);
                for (int i = 0; i < 128; i++) {
                    boolean t = temp6[i];
                    temp6[i] = temp6[255 - i];
                    temp6[255 - i] = t;
                }
                return temp6;
                
            case 7: // Reverse all + LSB-first
                boolean[] temp7 = applyTransformation(digest, 1);
                for (int i = 0; i < 128; i++) {
                    boolean t = temp7[i];
                    temp7[i] = temp7[255 - i];
                    temp7[255 - i] = t;
                }
                return temp7;
                
            case 8: // Bit-reverse each byte, keep byte order
                for (int i = 0; i < 32; i++) {
                    int b = workingDigest[i] & 0xFF;
                    int reversed = 0;
                    for (int j = 0; j < 8; j++) {
                        reversed |= ((b >> j) & 1) << (7 - j);
                    }
                    workingDigest[i] = (byte) reversed;
                }
                return applyTransformation(workingDigest, 1);
                
            case 9: // Bit-reverse each byte, reverse byte order
                byte[] temp9 = digest.clone();
                // First bit-reverse each byte
                for (int i = 0; i < 32; i++) {
                    int b = temp9[i] & 0xFF;
                    int reversed = 0;
                    for (int j = 0; j < 8; j++) {
                        reversed |= ((b >> j) & 1) << (7 - j);
                    }
                    temp9[i] = (byte) reversed;
                }
                // Then reverse byte order
                for (int i = 0; i < 16; i++) {
                    byte temp = temp9[i];
                    temp9[i] = temp9[31 - i];
                    temp9[31 - i] = temp;
                }
                return applyTransformation(temp9, 1);
                
            default:
                return applyTransformation(digest, 1);
        }
        
        return bits;
    }
    
    private static int hammingDistance(boolean[] a, boolean[] b, int length) {
        int distance = 0;
        for (int i = 0; i < length; i++) {
            if (a[i] != b[i]) distance++;
        }
        return distance;
    }
    
    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}