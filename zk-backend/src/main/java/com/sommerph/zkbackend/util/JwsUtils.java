package com.sommerph.zkbackend.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwsUtils {

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

    /** Result for aligned Base64url slice plus inner selection data */
    public static final class Base64UrlAlignedOffsetResult {
        public final int offXB64, lenXB64, dropX, lenXInner;
        public final int offYB64, lenYB64, dropY, lenYInner;
        public final boolean found;
        private Base64UrlAlignedOffsetResult(int ox, int lx, int dx, int lix,
                                             int oy, int ly, int dy, int liy, boolean f) {
            this.offXB64 = ox; this.lenXB64 = lx; this.dropX = dx; this.lenXInner = lix;
            this.offYB64 = oy; this.lenYB64 = ly; this.dropY = dy; this.lenYInner = liy; this.found = f;
        }
        public static Base64UrlAlignedOffsetResult of(int ox, int lx, int dx, int lix,
                                                      int oy, int ly, int dy, int liy) {
            return new Base64UrlAlignedOffsetResult(ox,lx,dx,lix,oy,ly,dy,liy,true);
        }
        public static Base64UrlAlignedOffsetResult notFound() {
            return new Base64UrlAlignedOffsetResult(-1,-1,-1,-1,-1,-1,-1,-1,false);
        }
    }

    /** L(n) = Length of Base64url output (without padding) for the first n bytes */
    private static int b64UrlLenOfPrefix(int n) {
        int r = n % 3;
        return 4 * (n / 3) + (r == 0 ? 0 : (r + 1));
    }

    /**
     * Compute aligned Base64 slice for a JSON substring with drop/length hints so that
     * decoding the slice (with padding) and then dropping `drop` bytes yields exactly the
     * inner Base64url value bytes (length 43 or 44).
     */
    public static Base64UrlAlignedOffsetResult findJwkXYOffsetsInBase64urlAligned(String payloadB64) {
        try {
            String s = payloadB64;
            int mod = s.length() % 4;
            if (mod != 0) s += "===".substring(0, 4 - mod);

            byte[] json = Base64.getUrlDecoder().decode(s);

            OffsetResult j = findJwkXYOffsets(json);
            if (!j.found) return Base64UrlAlignedOffsetResult.notFound();

            int offX = j.offX, lenX = j.lenX; // inner Base64url ascii
            int offY = j.offY, lenY = j.lenY;

            // X alignment
            int startBlockX = offX / 3;           // 3-byte block index
            int offXB64 = startBlockX * 4;        // encoded start (aligned)
            int dropX = offX - startBlockX * 3;   // bytes to drop after decode (0..2)
            int blocksX = (dropX + lenX + 2) / 3; // ceil((drop+len)/3)
            int lenXB64 = blocksX * 4;            // encoded length (aligned)

            // Y alignment
            int startBlockY = offY / 3;
            int offYB64 = startBlockY * 4;
            int dropY = offY - startBlockY * 3;
            int blocksY = (dropY + lenY + 2) / 3;
            int lenYB64 = blocksY * 4;

            return Base64UrlAlignedOffsetResult.of(offXB64, lenXB64, dropX, lenX, offYB64, lenYB64, dropY, lenY);
        } catch (Exception e) {
            return Base64UrlAlignedOffsetResult.notFound();
        }
    }

}
