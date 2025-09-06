package com.sommerph.zkbackend.util.msgBindingDebug;

import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility to find the correct bit mapping between Java SHA-256 output 
 * and Circom SHA-256 output by comparing against circuit debug bits.
 */
@Slf4j
public final class CircuitBitMappingCalibrator {

    private CircuitBitMappingCalibrator() {}

    /**
     * Configuration for bit interpretation variants.
     */
    public static class BitVariant {
        public final boolean msbFirstPerByte;
        public final boolean reverseWords;
        public final boolean reverseBytesInWord;
        public final boolean reverseWholeStream;
        
        public BitVariant(boolean msbFirstPerByte, boolean reverseWords, 
                         boolean reverseBytesInWord, boolean reverseWholeStream) {
            this.msbFirstPerByte = msbFirstPerByte;
            this.reverseWords = reverseWords;
            this.reverseBytesInWord = reverseBytesInWord;
            this.reverseWholeStream = reverseWholeStream;
        }
        
        @Override
        public String toString() {
            return String.format("msbFirst=%s, revWords=%s, revBytesInWord=%s, revStream=%s",
                msbFirstPerByte, reverseWords, reverseBytesInWord, reverseWholeStream);
        }
    }

    /**
     * Generate bits from bytes with specified bit ordering per byte.
     */
    public static boolean[] bitsFromBytes(byte[] bytes, boolean msbFirstPerByte) {
        boolean[] bits = new boolean[bytes.length * 8];
        int k = 0;
        for (byte b : bytes) {
            int x = b & 0xFF;
            if (msbFirstPerByte) {
                for (int j = 7; j >= 0; j--) {
                    bits[k++] = ((x >> j) & 1) == 1;
                }
            } else {
                for (int j = 0; j < 8; j++) {
                    bits[k++] = ((x >> j) & 1) == 1;
                }
            }
        }
        return bits;
    }

    /**
     * Reorder SHA-256 digest bytes by words and byte order within words.
     */
    public static byte[] reorderDigest(byte[] digest, boolean reverseWords, boolean reverseBytesInWord) {
        if (digest.length != 32) {
            throw new IllegalArgumentException("Expected 32-byte SHA-256 digest");
        }
        
        byte[] out = new byte[32];
        // 32 bytes = 8 words of 4 bytes each
        for (int wordIndex = 0; wordIndex < 8; wordIndex++) {
            int srcWordIndex = reverseWords ? (7 - wordIndex) : wordIndex;
            byte[] word = Arrays.copyOfRange(digest, srcWordIndex * 4, srcWordIndex * 4 + 4);
            
            if (reverseBytesInWord) {
                // Reverse bytes within this word
                for (int i = 0; i < 2; i++) {
                    byte temp = word[i];
                    word[i] = word[3 - i];
                    word[3 - i] = temp;
                }
            }
            
            System.arraycopy(word, 0, out, wordIndex * 4, 4);
        }
        return out;
    }

    /**
     * Calculate Hamming distance between two boolean arrays.
     */
    public static int hammingDistance(boolean[] a, boolean[] b, int length) {
        int distance = 0;
        for (int i = 0; i < length; i++) {
            if (a[i] != b[i]) {
                distance++;
            }
        }
        return distance;
    }

    /**
     * Find the best bit mapping variant by comparing against circuit debug bits.
     */
    public static BitVariant findBitMapping(byte[] javaDigest, boolean[] circuitFirst64Bits) {
        log.info("Calibrating bit mapping between Java SHA-256 and Circuit SHA-256...");
        log.info("Java digest: {}", bytesToHex(javaDigest));
        log.info("Circuit first 64 bits: {}", boolArrayToString(circuitFirst64Bits, 64));
        
        // Generate all plausible variants
        List<BitVariant> variants = new ArrayList<>();
        for (boolean msbFirst : new boolean[]{true, false}) {
            for (boolean revWords : new boolean[]{false, true}) {
                for (boolean revBytes : new boolean[]{false, true}) {
                    for (boolean revStream : new boolean[]{false, true}) {
                        variants.add(new BitVariant(msbFirst, revWords, revBytes, revStream));
                    }
                }
            }
        }
        
        int bestDistance = Integer.MAX_VALUE;
        BitVariant bestVariant = null;
        
        log.info("Testing {} bit interpretation variants...", variants.size());
        
        for (BitVariant variant : variants) {
            // Apply variant transformations
            byte[] reorderedDigest = reorderDigest(javaDigest, variant.reverseWords, variant.reverseBytesInWord);
            boolean[] bits = bitsFromBytes(reorderedDigest, variant.msbFirstPerByte);
            
            if (variant.reverseWholeStream) {
                // Reverse entire bit stream
                for (int i = 0, j = bits.length - 1; i < j; i++, j--) {
                    boolean temp = bits[i];
                    bits[i] = bits[j];
                    bits[j] = temp;
                }
            }
            
            int distance = hammingDistance(bits, circuitFirst64Bits, 64);
            
            log.debug("Variant {}: Hamming distance = {}", variant, distance);
            
            if (distance < bestDistance) {
                bestDistance = distance;
                bestVariant = variant;
            }
            
            if (distance == 0) {
                log.info("Perfect match found: {}", variant);
                break;
            }
        }
        
        if (bestDistance == 0) {
            log.info("Found exact bit mapping: {}", bestVariant);
        } else {
            log.warn("No perfect match found. Best distance: {} with variant: {}", bestDistance, bestVariant);
        }
        
        return bestVariant;
    }

    /**
     * Apply the discovered bit variant to extract all 256 bits from Java digest.
     */
    public static boolean[] applyBitVariant(byte[] javaDigest, BitVariant variant) {
        byte[] reorderedDigest = reorderDigest(javaDigest, variant.reverseWords, variant.reverseBytesInWord);
        boolean[] bits = bitsFromBytes(reorderedDigest, variant.msbFirstPerByte);
        
        if (variant.reverseWholeStream) {
            // Reverse entire bit stream
            for (int i = 0, j = bits.length - 1; i < j; i++, j--) {
                boolean temp = bits[i];
                bits[i] = bits[j];
                bits[j] = temp;
            }
        }
        
        return bits;
    }

    /**
     * Convert boolean array to string for debugging.
     */
    public static String boolArrayToString(boolean[] bits, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(length, bits.length); i++) {
            sb.append(bits[i] ? '1' : '0');
        }
        return sb.toString();
    }

    /**
     * Convert bytes to hex string.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}