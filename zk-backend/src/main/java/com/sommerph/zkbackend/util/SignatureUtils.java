package com.sommerph.zkbackend.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;

public class SignatureUtils {

    public static byte[] hash(String input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hashing failed", e);
        }
    }

    public static String base64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static EcdsaSignature decodeDerSignature(byte[] derBytes) {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(derBytes))) {
            ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
            BigInteger r = ((ASN1Integer) sequence.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) sequence.getObjectAt(1)).getValue();
            return new EcdsaSignature(r, s);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse DER-encoded ECDSA signature", e);
        }
    }

    public static byte[] concatSignature(BigInteger r, BigInteger s) {
        byte[] rBytes = leftPadTo32Bytes(r.toByteArray());
        byte[] sBytes = leftPadTo32Bytes(s.toByteArray());
        byte[] result = new byte[64];
        System.arraycopy(rBytes, 0, result, 0, 32);
        System.arraycopy(sBytes, 0, result, 32, 32);
        return result;
    }

    private static byte[] leftPadTo32Bytes(byte[] bytes) {
        if (bytes.length == 32) return bytes;
        byte[] padded = new byte[32];
        int srcPos = Math.max(0, bytes.length - 32);
        int destPos = 32 - (bytes.length - srcPos);
        int length = bytes.length - srcPos;
        System.arraycopy(bytes, srcPos, padded, destPos, length);
        return padded;
    }

    public static class EcdsaSignature {
        private final BigInteger r;
        private final BigInteger s;

        public EcdsaSignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        public BigInteger getR() {
            return r;
        }

        public BigInteger getS() {
            return s;
        }
    }

}
