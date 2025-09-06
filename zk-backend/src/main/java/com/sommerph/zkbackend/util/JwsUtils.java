package com.sommerph.zkbackend.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

public class JwsUtils {

    private static final String TAG_X = "\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"";
    private static final String TAG_Y = "\",\"y\":\"";
    private static final Pattern BASE64_URL_PATTERN = Pattern.compile("^[A-Za-z0-9_-]*$");

    /**
     * Converts SHA-256 hash bytes to 6 limbs of 43 bits each (as String array).
     *
     * @param asciiInput The ASCII input bytes to hash
     * @return String array of 6 limbs (decimal strings)
     */
    public static String[] sha256To6Limbs43(byte[] asciiInput) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(asciiInput);
            
            // Convert hash bytes to BigInteger (big-endian)
            BigInteger hash = new BigInteger(1, hashBytes);
            
            // Split into 6 limbs of 43 bits each using existing LimbUtils
            return LimbUtils.scalarToLimbsR1(hash);
            
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Converts EC point coordinates to 2x6 limbs (as String array).
     *
     * @param x The x-coordinate (32-byte big-endian)
     * @param y The y-coordinate (32-byte big-endian)
     * @return 2D String array: [2][6] → [x limbs][y limbs]
     */
    public static String[][] ecPointTo2x6Limbs(BigInteger x, BigInteger y) {
        return LimbUtils.pointToLimbsR1(x, y);
    }

    /**
     * Validates if a string contains only valid Base64url characters (no padding).
     *
     * @param s The string to validate
     * @return true if valid Base64url ASCII, false otherwise
     */
    public static boolean isValidBase64UrlAscii(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        
        // Check for padding characters (not allowed)
        if (s.contains("=")) {
            return false;
        }
        
        // Check charset: [A-Z a-z 0-9 - _]
        return BASE64_URL_PATTERN.matcher(s).matches();
    }

    /**
     * Converts Base64url string to ASCII byte array.
     *
     * @param base64UrlString The Base64url encoded string
     * @return ASCII bytes as BigInteger array (for Circom compatibility)
     */
    public static BigInteger[] base64UrlToAsciiBytes(String base64UrlString) {
        byte[] asciiBytes = base64UrlString.getBytes(StandardCharsets.US_ASCII);
        BigInteger[] result = new BigInteger[asciiBytes.length];
        
        for (int i = 0; i < asciiBytes.length; i++) {
            result[i] = BigInteger.valueOf(asciiBytes[i] & 0xFF);
        }
        
        return result;
    }

    /**
     * Converts Base64url string to ASCII byte array (String version for compatibility).
     *
     * @param base64UrlString The Base64url encoded string
     * @return ASCII bytes as String array (decimal values)
     */
    public static String[] base64UrlToAsciiBytesString(String base64UrlString) {
        byte[] asciiBytes = base64UrlString.getBytes(StandardCharsets.US_ASCII);
        String[] result = new String[asciiBytes.length];
        
        for (int i = 0; i < asciiBytes.length; i++) {
            result[i] = String.valueOf(asciiBytes[i] & 0xFF);
        }
        
        return result;
    }

    /**
     * Result class for JWK x/y offset finding.
     */
    public static class OffsetResult {
        public final int offTagX;
        public final int offX;
        public final int lenX;
        public final int offTagY;
        public final int offY;
        public final int lenY;
        public final boolean found;

        public OffsetResult(int offTagX, int offX, int lenX, int offTagY, int offY, int lenY, boolean found) {
            this.offTagX = offTagX;
            this.offX = offX;
            this.lenX = lenX;
            this.offTagY = offTagY;
            this.offY = offY;
            this.lenY = lenY;
            this.found = found;
        }

        public static OffsetResult notFound() {
            return new OffsetResult(-1, -1, -1, -1, -1, -1, false);
        }
    }

    /**
     * Finds JWK x/y field offsets and lengths in decoded payload JSON (ASCII).
     * Handles flexible field ordering in JWK objects.
     *
     * @param payloadJsonAscii The decoded payload JSON as ASCII bytes
     * @return OffsetResult containing offsets and lengths, or notFound() if tags not found
     */
    public static OffsetResult findJwkXYOffsets(byte[] payloadJsonAscii) {
        String payloadString = new String(payloadJsonAscii, StandardCharsets.UTF_8);
        
        // Find the jwk object start
        int jwkStart = payloadString.indexOf("\"jwk\":{");
        if (jwkStart == -1) {
            return OffsetResult.notFound();
        }
        
        // Find the jwk object end (matching closing brace)
        int jwkEnd = findMatchingBrace(payloadString, jwkStart + 6); // 6 = length of "\"jwk\":{"
        if (jwkEnd == -1) {
            return OffsetResult.notFound();
        }
        
        String jwkSection = payloadString.substring(jwkStart, jwkEnd + 1);
        
        // Find x field: "x":"value"
        int xFieldStart = jwkSection.indexOf("\"x\":\"");
        if (xFieldStart == -1) {
            return OffsetResult.notFound();
        }
        
        int offX = jwkStart + xFieldStart + 5; // 5 = length of "\"x\":\""
        int endX = payloadString.indexOf('"', offX);
        if (endX == -1) {
            return OffsetResult.notFound();
        }
        int lenX = endX - offX;
        
        // Find y field: "y":"value"  
        int yFieldStart = jwkSection.indexOf("\"y\":\"");
        if (yFieldStart == -1) {
            return OffsetResult.notFound();
        }
        
        int offY = jwkStart + yFieldStart + 5; // 5 = length of "\"y\":\""
        int endY = payloadString.indexOf('"', offY);
        if (endY == -1) {
            return OffsetResult.notFound();
        }
        int lenY = endY - offY;
        
        // For consistency, set offTagX/offTagY to the start of the field declarations
        int offTagX = jwkStart + xFieldStart;
        int offTagY = jwkStart + yFieldStart;
        
        return new OffsetResult(offTagX, offX, lenX, offTagY, offY, lenY, true);
    }
    
    /**
     * Finds the matching closing brace for a JSON object.
     */
    private static int findMatchingBrace(String json, int openBracePos) {
        int depth = 1;
        boolean inString = false;
        boolean escaped = false;
        
        for (int i = openBracePos + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            
            if (escaped) {
                escaped = false;
                continue;
            }
            
            if (c == '\\') {
                escaped = true;
                continue;
            }
            
            if (c == '"') {
                inString = !inString;
                continue;
            }
            
            if (!inString) {
                if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        return i;
                    }
                }
            }
        }
        
        return -1; // No matching brace found
    }

}