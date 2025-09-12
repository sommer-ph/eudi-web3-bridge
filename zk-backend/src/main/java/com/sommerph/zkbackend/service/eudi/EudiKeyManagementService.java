package com.sommerph.zkbackend.service.eudi;

import com.sommerph.zkbackend.config.KeyConfigProperties;
import com.sommerph.zkbackend.util.LimbUtils;
import com.sommerph.zkbackend.util.SignatureUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Slf4j
@Service
public class EudiKeyManagementService {

    private final KeyConfigProperties config;

    // Fixed issuer key pair parameters injected from configuration
    @Value("${keys.issuer.fixed-private}")
    private String fixedPrivDec;

    @Value("${keys.issuer.fixed-public-x}")
    private String fixedPubXDec;

    @Value("${keys.issuer.fixed-public-y}")
    private String fixedPubYDec;

    @Getter
    private KeyPair issuerKeyPair;

    public EudiKeyManagementService(KeyConfigProperties config) {
        this.config = config;
    }

    @PostConstruct
    public void init() throws GeneralSecurityException {
        log.info("Initialize issuer key pair with curve: {}", config.getCurve());
        if ("generate".equalsIgnoreCase(config.getIssuer().getSource())) {
            this.issuerKeyPair = generateKeyPair();
        } else {
            this.issuerKeyPair = loadFixedKeyPair();
        }
    }

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        log.info("Generate EC key pair using curve: {}", config.getCurve());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec(config.getCurve()));
        return keyGen.generateKeyPair();
    }

    private KeyPair loadFixedKeyPair() throws GeneralSecurityException {
        log.info("Load fixed issuer key pair");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(config.getCurve()));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);

        KeyFactory factory = KeyFactory.getInstance("EC");
        BigInteger priv = new BigInteger(fixedPrivDec);
        BigInteger x = new BigInteger(fixedPubXDec);
        BigInteger y = new BigInteger(fixedPubYDec);

        ECPoint w = new ECPoint(x, y);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(w, ecSpec);
        ECPrivateKeySpec privSpec = new ECPrivateKeySpec(priv, ecSpec);

        PublicKey pubKey = factory.generatePublic(pubSpec);
        PrivateKey privKey = factory.generatePrivate(privSpec);
        return new KeyPair(pubKey, privKey);
    }

    public Map<String, Object> toJwk(PublicKey publicKey) {
        log.info("Convert public key to JWK format");
        ECPublicKey ecKey = (ECPublicKey) publicKey;
        byte[] x = ecKey.getW().getAffineX().toByteArray();
        byte[] y = ecKey.getW().getAffineY().toByteArray();

        return Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", base64url(x),
                "y", base64url(y)
        );
    }

    private String base64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public KeyPair decodeKeyPair(String base64Priv, String base64Pub) {
        try {
            byte[] privBytes = Base64.getDecoder().decode(base64Priv);
            PrivateKey privKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privBytes));
            byte[] pubBytes = Base64.getDecoder().decode(base64Pub);
            PublicKey pubKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(pubBytes));
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode EC key pair", e);
        }
    }

    // Circuit-related operations

    public String[][] getIssuerPublicKeyLimbs() {
        log.info("Get issuer public key limbs");
        BigInteger x = ((ECPublicKey) issuerKeyPair.getPublic()).getW().getAffineX();
        BigInteger y = ((ECPublicKey) issuerKeyPair.getPublic()).getW().getAffineY();
        return LimbUtils.pointToLimbsR1(x, y);
    }

    public String[] getUserCredentialSecretKeyLimbs(String base64EncodedSecretKey) {
        // Parse PKCS#8 encoded secret key
        log.info("Get user credential secret key limbs");
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64EncodedSecretKey);
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            BigInteger s = ((java.security.interfaces.ECPrivateKey) privateKey).getS();
            return LimbUtils.scalarToLimbsR1(s);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse user credential secret key", e);
        }
    }

    public String[][] getCredentialBindingKeyJwkLimbs(Map<String, Object> jwk) {
        log.info("Get credential binding key JWK limbs");
        BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("x")));
        BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("y")));
        return LimbUtils.pointToLimbsR1(x, y);
    }

    public String[] computeCredentialMsgHashLimbs(Map<String, Object> header, Map<String, Object> payload) {
        log.info("Compute credential message hash limbs");
        try {
            ObjectMapper mapper = new ObjectMapper();
            String encodedHeader = SignatureUtils.base64url(mapper.writeValueAsBytes(header));
            String encodedPayload = SignatureUtils.base64url(mapper.writeValueAsBytes(payload));
            String signingInput = encodedHeader + "." + encodedPayload;
            byte[] hash = SignatureUtils.hash(signingInput);
            BigInteger hashInt = new BigInteger(1, hash);
            return LimbUtils.scalarToLimbsR1(hashInt);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute credential message hash", e);
        }
    }

    /**
     * Compute the circuit-style padded message hash limbs.
     * Message layout (fixed):
     *   [ headerB64 ASCII (len h) | zeros to 64 ]
     *   '.' (ASCII 46) at index 64
     *   [ payloadB64 ASCII (len p) | zeros to 1024 ]
     * Total message length = 64 + 1 + 1024 bytes (1089 bytes).
     */
    public String[] computeCredentialPaddedMsgHashLimbs(Map<String, Object> header, Map<String, Object> payload) {
        log.info("Compute padded credential message hash limbs");
        try {
            byte[] msg = buildCredentialPaddedSigningInput(header, payload);
            // Hash exact bytes as used by the circuit
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(msg);
            BigInteger hashInt = new BigInteger(1, hash);
            return LimbUtils.scalarToLimbsR1(hashInt);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute circuit-padded credential message hash", e);
        }
    }

    /**
     * Build the exact fixed-length byte layout used by the circuit for message hashing.
     * Layout:
     *   [ headerB64 ASCII (len h) | zeros to 64 ]
     *   '.' (ASCII 46) at index 64
     *   [ payloadB64 ASCII (len p) | zeros to 1024 ]
     * Total length: 64 + 1 + 1024 bytes.
     */
    public byte[] buildCredentialPaddedSigningInput(Map<String, Object> header, Map<String, Object> payload) {
        try {
            final int MAX_HEADER = 64;
            final int MAX_PAYLOAD = 1024;
            final int MAX_TOTAL = MAX_HEADER + 1 + MAX_PAYLOAD;

            ObjectMapper mapper = new ObjectMapper();
            String headerB64 = SignatureUtils.base64url(mapper.writeValueAsBytes(header));
            String payloadB64 = SignatureUtils.base64url(mapper.writeValueAsBytes(payload));

            byte[] headerAscii = headerB64.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] payloadAscii = payloadB64.getBytes(java.nio.charset.StandardCharsets.US_ASCII);

            byte[] msg = new byte[MAX_TOTAL];
            // Header region [0..63]
            System.arraycopy(headerAscii, 0, msg, 0, Math.min(headerAscii.length, MAX_HEADER));
            // Dot at index 64
            msg[MAX_HEADER] = 46; // '.'
            // Payload region starts at 65
            int payCopy = Math.min(payloadAscii.length, MAX_PAYLOAD);
            System.arraycopy(payloadAscii, 0, msg, MAX_HEADER + 1, payCopy);
            return msg;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build padded credential signing input", e);
        }
    }

    public Map<String, String[]> extractCredentialSignatureLimbs(byte[] derSignature) {
        log.info("Parse credential signature limbs from DER format");
        try {
            SignatureUtils.EcdsaSignature sig = SignatureUtils.decodeDerSignature(derSignature);
            String[] rLimbs = LimbUtils.scalarToLimbsR1(sig.getR());
            String[] sLimbs = LimbUtils.scalarToLimbsR1(sig.getS());
            return Map.of(
                    "r", rLimbs,
                    "s", sLimbs
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse ECDSA signature for zk-input", e);
        }
    }

    // Direct hex methods for recursive proof preparation
    
    public String getCredentialMsgHashHex(Map<String, Object> header, Map<String, Object> payload) {
        log.info("Get credential message hash hex");
        try {
            ObjectMapper mapper = new ObjectMapper();
            String encodedHeader = SignatureUtils.base64url(mapper.writeValueAsBytes(header));
            String encodedPayload = SignatureUtils.base64url(mapper.writeValueAsBytes(payload));
            String signingInput = encodedHeader + "." + encodedPayload;
            byte[] hash = SignatureUtils.hash(signingInput);
            BigInteger hashInt = new BigInteger(1, hash);
            return "0x" + hashInt.toString(16);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute credential message hash hex", e);
        }
    }

    public String getCredentialPaddedMsgHashHex(Map<String, Object> header, Map<String, Object> payload) {
        log.info("Get padded credential message hash hex");
        try {
            byte[] msg = buildCredentialPaddedSigningInput(header, payload);
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(msg);
            BigInteger hashInt = new BigInteger(1, hash);
            return "0x" + hashInt.toString(16);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute padded credential message hash hex", e);
        }
    }

    public Map<String, String> extractCredentialSignatureHex(byte[] derSignature) {
        log.info("Extract credential signature hex from DER format");
        try {
            SignatureUtils.EcdsaSignature sig = SignatureUtils.decodeDerSignature(derSignature);
            return Map.of(
                    "r", "0x" + sig.getR().toString(16),
                    "s", "0x" + sig.getS().toString(16)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract ECDSA signature hex", e);
        }
    }

    public Map<String, String> getCredentialBindingKeyJwkHex(Map<String, Object> jwk) {
        log.info("Get credential binding key JWK hex");
        BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("x")));
        BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("y")));
        return Map.of(
                "x", "0x" + x.toString(16),
                "y", "0x" + y.toString(16)
        );
    }

    public Map<String, String> getIssuerPublicKeyHex() {
        log.info("Get issuer public key hex");
        BigInteger x = ((ECPublicKey) issuerKeyPair.getPublic()).getW().getAffineX();
        BigInteger y = ((ECPublicKey) issuerKeyPair.getPublic()).getW().getAffineY();
        return Map.of(
                "x", "0x" + x.toString(16),
                "y", "0x" + y.toString(16)
        );
    }

    public String getUserCredentialSecretKeyHex(String base64EncodedSecretKey) {
        log.info("Get user credential secret key hex");
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64EncodedSecretKey);
            PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            BigInteger s = ((java.security.interfaces.ECPrivateKey) privateKey).getS();
            return "0x" + s.toString(16);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get user credential secret key hex", e);
        }
    }

}
