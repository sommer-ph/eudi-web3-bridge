package com.sommerph.zkbackend.service.eudi;

import com.sommerph.zkbackend.config.KeyConfigProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

@Slf4j
@Service
public class EudiKeyManagementService {

    private final KeyConfigProperties config;
    private KeyPair issuerKeyPair;

    public EudiKeyManagementService(KeyConfigProperties config) {
        this.config = config;
    }

    @PostConstruct
    public void init() throws GeneralSecurityException {
        log.info("Initialize issuer key pair with curve: {}", config.getCurve());
        this.issuerKeyPair = generateKeyPair();
    }

    public KeyPair getIssuerKeyPair() {
        return issuerKeyPair;
    }

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        log.info("Generated EC key pair using curve: {}", config.getCurve());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec(config.getCurve()));
        KeyPair keyPair = keyGen.generateKeyPair();

        // Temporary implementation to log key pair details relevant for proofs
        // TODO: Replace temporary implementation with updated Eudi Wallet model, which includes pk_I in desired format
        ECPublicKey ecPubKey = (ECPublicKey) keyPair.getPublic();
        byte[] xBytes = stripLeadingZero(ecPubKey.getW().getAffineX().toByteArray());
        byte[] yBytes = stripLeadingZero(ecPubKey.getW().getAffineY().toByteArray());

        String xDecimal = ecPubKey.getW().getAffineX().toString();
        String yDecimal = ecPubKey.getW().getAffineY().toString();

        log.info("Public Key (Circom decimal):");
        log.info("  x (decimal):   {}", xDecimal);
        log.info("  y (decimal):   {}", yDecimal);
        // End of temporary implementation

        return keyPair;
    }

    public Map<String, Object> toJwk(PublicKey publicKey) {
        ECPublicKey ecKey = (ECPublicKey) publicKey;
        byte[] x = ecKey.getW().getAffineX().toByteArray();
        byte[] y = ecKey.getW().getAffineY().toByteArray();

        return Map.of(
                "kty", "EC",
                "crv", "P-256",
                "x", base64url(stripLeadingZero(x)),
                "y", base64url(stripLeadingZero(y))
        );
    }

    public String computeKeyId(PublicKey publicKey) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(publicKey.getEncoded());
        return base64url(hash);
    }

    private String base64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] stripLeadingZero(byte[] bytes) {
        return (bytes.length > 0 && bytes[0] == 0x00) ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

}
