package com.sommerph.zkbackend.controller;

import com.sommerph.zkbackend.model.eudi.EudiCredential;
import com.sommerph.zkbackend.model.eudi.EudiWallet;
import com.sommerph.zkbackend.service.eudi.EudiCredentialService;
import com.sommerph.zkbackend.service.eudi.EudiWalletService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/eudi/wallet")
@RequiredArgsConstructor
@Tag(name = "EUDI", description = "Endpoints for EUDI wallet operations")
public class EudiController {

    private final EudiWalletService walletService;
    private final EudiCredentialService credentialService;

    @Operation(summary = "Initialize a new EUDI wallet for the given user")
    @PostMapping("/{userId}/init")
    public ResponseEntity<?> initWallet(@PathVariable @NotBlank String userId) {
        log.info("Initialize EUDI wallet for user: {}", userId);
        try {
            if (walletService.walletExists(userId)) {
                return ResponseEntity.badRequest().body("EUDI wallet already exists for user: " + userId);
            }
            walletService.createWallet(userId);
            return ResponseEntity.ok("EUDI wallet created for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to initialize EUDI wallet for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error creating EUDI wallet: " + e.getMessage());
        }
    }

    @Operation(summary = "Issue a new credential and add it to the EUDI wallet")
    @PostMapping("/{userId}/credential/issue")
    public ResponseEntity<?> issueCredential(
            @PathVariable @NotBlank String userId,
            @RequestBody Map<String, String> attributes) {
        log.info("Issue credential for user: {}", userId);
        try {
            EudiCredential credential = credentialService.issueCredential(userId, attributes);
            return ResponseEntity.ok(credential);
        } catch (Exception e) {
            log.error("Credential issuance failed for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Credential issuance failed: " + e.getMessage());
        }
    }

    @Operation(summary = "Get the EUDI wallet for the given user")
    @GetMapping("/{userId}")
    public ResponseEntity<?> getWallet(@PathVariable @NotBlank String userId) {
        log.info("Load EUDI wallet for user: {}", userId);
        try {
            EudiWallet wallet = walletService.loadWallet(userId);
            return ResponseEntity.ok(wallet);
        } catch (Exception e) {
            log.error("Failed to load EUDI wallet for user: {}", userId, e);
            return ResponseEntity.badRequest().body("EUDI wallet not found for user: " + userId);
        }
    }

    @Operation(summary = "List all credentials stored in the EUDI wallet")
    @GetMapping("/{userId}/credentials")
    public ResponseEntity<?> getCredentials(@PathVariable @NotBlank String userId) {
        log.info("Fetch credentials for user: {}", userId);
        try {
            EudiWallet wallet = walletService.loadWallet(userId);
            return ResponseEntity.ok(wallet.getCredentials());
        } catch (Exception e) {
            log.error("Failed to fetch credentials for user: {}", userId, e);
            return ResponseEntity.badRequest().body("EUDI wallet not found for user: " + userId);
        }
    }

}
