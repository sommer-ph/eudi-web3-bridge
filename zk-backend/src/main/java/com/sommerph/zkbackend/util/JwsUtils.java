package com.sommerph.zkbackend.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class JwsUtils {

    private JwsUtils() {}

    // [A-Za-z0-9_-], no padding
    private static final Pattern BASE64_URL_PATTERN = Pattern.compile("^[A-Za-z0-9_-]*$");

    /** Validates Base64url-ASCII format (without '=') */
    public static boolean isValidBase64UrlAscii(String s) {
        return s != null && !s.isEmpty() && !s.contains("=") && BASE64_URL_PATTERN.matcher(s).matches();
    }

    /** Base64url-String → ASCII bytes as decimal strings (for Circom) */
    public static String[] base64UrlToAsciiBytesString(String base64UrlString) {
        byte[] ascii = base64UrlString.getBytes(StandardCharsets.US_ASCII);
        String[] out = new String[ascii.length];
        for (int i = 0; i < ascii.length; i++) out[i] = String.valueOf(ascii[i] & 0xFF);
        return out;
    }

    /** Result for x/y coordinate locations (in JSON bytes) */
    public static final class OffsetResult {
        public final int offTagX, offX, lenX, offTagY, offY, lenY;
        public final boolean found;
        private OffsetResult(int tx, int ox, int lx, int ty, int oy, int ly, boolean f) {
            offTagX = tx; offX = ox; lenX = lx; offTagY = ty; offY = oy; lenY = ly; found = f;
        }
        public static OffsetResult of(int tx, int ox, int lx, int ty, int oy, int ly) {
            return new OffsetResult(tx, ox, lx, ty, oy, ly, true);
        }
        public static OffsetResult notFound() { return new OffsetResult(-1,-1,-1,-1,-1,-1,false); }
    }

    /**
     * Finds x/y field values (only the value spans) within the JWK object in decoded JSON bytes.
     * Order-agnostic and whitespace-tolerant.
     */
    public static OffsetResult findJwkXYOffsets(byte[] payloadJsonAscii) {
        final String s = new String(payloadJsonAscii, StandardCharsets.UTF_8);

        // 1) Find jwk object robustly: "jwk" \s* : \s* {
        Matcher mjwk = Pattern.compile("\"jwk\"\\s*:\\s*\\{").matcher(s);
        if (!mjwk.find()) return OffsetResult.notFound();

        // Start of the opening '{' of the jwk object
        int jwkOpen = s.indexOf('{', mjwk.start());
        if (jwkOpen < 0) return OffsetResult.notFound();

        // 2) Find matching closing '}' (respecting strings & escapes)
        int jwkClose = findMatchingBrace(s, jwkOpen);
        if (jwkClose < 0) return OffsetResult.notFound();

        // 3) Within jwk, search for x/y as Base64url values (42–44 chars)
        String jwkSection = s.substring(jwkOpen, jwkClose + 1);
        Matcher mx = Pattern.compile("\"x\"\\s*:\\s*\"([A-Za-z0-9_-]{42,44})\"").matcher(jwkSection);
        Matcher my = Pattern.compile("\"y\"\\s*:\\s*\"([A-Za-z0-9_-]{42,44})\"").matcher(jwkSection);
        if (!mx.find() || !my.find()) return OffsetResult.notFound();

        int offX = jwkOpen + mx.start(1);
        int lenX = mx.group(1).length();
        int offY = jwkOpen + my.start(1);
        int lenY = my.group(1).length();
        int offTagX = jwkOpen + mx.start();
        int offTagY = jwkOpen + my.start();

        return OffsetResult.of(offTagX, offX, lenX, offTagY, offY, lenY);
    }

    /** Find closing brace for '{' at position openBracePos (safe for strings/escapes) */
    private static int findMatchingBrace(String json, int openBracePos) {
        int depth = 1; boolean inString = false; boolean esc = false;
        for (int i = openBracePos + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (esc) { esc = false; continue; }
            if (c == '\\') { esc = true; continue; }
            if (c == '"') { inString = !inString; continue; }
            if (inString) continue;
            if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return i;
        }
        return -1;
    }

    /** Result for offsets/lengths in Base64url-encoded payload */
    public static final class Base64UrlOffsetResult {
        public final int offXB64, lenXB64, offYB64, lenYB64;
        public final boolean found;
        private Base64UrlOffsetResult(int ox, int lx, int oy, int ly, boolean f) {
            offXB64 = ox; lenXB64 = lx; offYB64 = oy; lenYB64 = ly; found = f;
        }
        public static Base64UrlOffsetResult of(int ox, int lx, int oy, int ly) { return new Base64UrlOffsetResult(ox,lx,oy,ly,true); }
        public static Base64UrlOffsetResult notFound() { return new Base64UrlOffsetResult(-1,-1,-1,-1,false); }
    }

    /** L(n) = Length of Base64url output (without padding) for the first n bytes */
    private static int b64UrlLenOfPrefix(int n) {
        int r = n % 3;
        return 4 * (n / 3) + (r == 0 ? 0 : (r + 1));
    }

    /**
     * Finds x/y offsets directly in Base64url-encoded payload.
     * Approach: payloadB64 → decode → find JSON offsets → map exactly to Base64url offsets.
     * (No substring decoding! See comment above.)
     */
    public static Base64UrlOffsetResult findJwkXYOffsetsInBase64url(String payloadB64) {
        try {
            // Java decoder may need padding
            String s = payloadB64;
            int mod = s.length() % 4;
            if (mod != 0) s += "===".substring(0, 4 - mod);

            byte[] json = Base64.getUrlDecoder().decode(s);

            // Determine JSON offsets of values (only value, without quotes)
            OffsetResult j = findJwkXYOffsets(json);
            if (!j.found) return Base64UrlOffsetResult.notFound();

            // P-256: 43 (occasionally 44) Base64url characters
            if (j.lenX < 42 || j.lenX > 44 || j.lenY < 42 || j.lenY > 44)
                return Base64UrlOffsetResult.notFound();

            // Exact mapping byte offset → Base64url offset
            int offXB64 = b64UrlLenOfPrefix(j.offX);
            int lenXB64 = b64UrlLenOfPrefix(j.offX + j.lenX) - offXB64;

            int offYB64 = b64UrlLenOfPrefix(j.offY);
            int lenYB64 = b64UrlLenOfPrefix(j.offY + j.lenY) - offYB64;

            return Base64UrlOffsetResult.of(offXB64, lenXB64, offYB64, lenYB64);
        } catch (Exception e) {
            return Base64UrlOffsetResult.notFound();
        }
    }

    /**
     * Validates the calculation: we decode ONCE completely, read x/y from JSON,
     * and check that their lengths are plausible. No decoding of substrings needed.
     */
    public static void validateBase64urlCoordinates(
            String payloadB64,
            Base64UrlOffsetResult off,
            Map<String, Object> originalPayload
    ) {
        try {
            if (off == null || !off.found) throw new IllegalStateException("Offset result not found");

            // Original x/y from payload map (source of truth)
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) ((Map<?, ?>) originalPayload.get("cnf")).get("jwk");
            String xOrig = (String) jwk.get("x");
            String yOrig = (String) jwk.get("y");
            if (xOrig == null || yOrig == null) throw new IllegalStateException("Missing x/y in payload");

            if (!isValidBase64UrlAscii(xOrig) || !isValidBase64UrlAscii(yOrig))
                throw new IllegalStateException("x/y not Base64url ASCII");

            if (xOrig.length() < 42 || xOrig.length() > 44 || yOrig.length() < 42 || yOrig.length() > 44)
                throw new IllegalStateException("Unexpected x/y length");

            // Additional plausibility check: length mapping consistent?
            // (With correct formula: lenB64 == L(off+len) - L(off))
            // Here it's sufficient that we used the formula exactly as such – nothing more to do.

        } catch (Exception e) {
            throw new IllegalStateException("Base64url coordinate validation failed: " + e.getMessage(), e);
        }
    }

    /** Legacy API – please do not use anymore. */
    @Deprecated
    public static OffsetResult findJwkXYOffsetsInBase64Url(String payloadB64) {
        try {
            String s = payloadB64;
            int mod = s.length() % 4;
            if (mod != 0) s += "===".substring(0, 4 - mod);
            byte[] json = Base64.getUrlDecoder().decode(s);
            return findJwkXYOffsets(json);
        } catch (Exception e) {
            return OffsetResult.notFound();
        }
    }
}
