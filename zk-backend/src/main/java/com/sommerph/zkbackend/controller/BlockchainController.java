package com.sommerph.zkbackend.controller;

import com.sommerph.zkbackend.model.blockchain.BlockchainWallet;
import com.sommerph.zkbackend.model.blockchain.ChildKey;
import com.sommerph.zkbackend.service.blockchain.BlockchainWalletService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/blockchain/wallet")
@RequiredArgsConstructor
@Tag(name = "Blockchain", description = "Endpoints for blockchain wallet operations")
public class BlockchainController {

    private final BlockchainWalletService walletService;

    @Operation(summary = "Initialize a new blockchain wallet for the given user")
    @PostMapping("/{userId}/init")
    public ResponseEntity<?> initWallet(@PathVariable @NotBlank String userId) {
        log.info("Initialize blockchain wallet for user: {}", userId);
        try {
            if (walletService.walletExists(userId)) {
                return ResponseEntity.badRequest().body("Blockchain wallet already exists for user: " + userId);
            }
            walletService.createWallet(userId);
            return ResponseEntity.ok("Blockchain wallet created for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to initialize blockchain wallet for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error creating blockchain wallet: " + e.getMessage());
        }
    }

    @Operation(summary = "Get blockchain wallet for the given user")
    @GetMapping("/{userId}")
    public ResponseEntity<?> getWallet(@PathVariable @NotBlank String userId) {
        log.info("Load blockchain wallet for user: {}", userId);
        try {
            BlockchainWallet wallet = walletService.loadWallet(userId);
            return ResponseEntity.ok(wallet);
        } catch (Exception e) {
            log.error("Failed to load blockchain wallet for user: {}", userId, e);
            return ResponseEntity.badRequest().body("Blockchain wallet not found for user: " + userId);
        }
    }

    @Operation(summary = "Recover blockchain wallet from a mnemonic phrase")
    @PostMapping("/recover")
    public ResponseEntity<?> recoverWallet(@RequestBody RecoverRequest request) {
        log.info("Recover blockchain wallet for user: {}", request.getUserId());
        try {
            BlockchainWallet wallet = walletService.recoverWallet(request.getUserId(), request.getMnemonic());
            return ResponseEntity.ok(wallet);
        } catch (Exception e) {
            log.error("Failed to recover blockchain wallet for user: {}", request.getUserId(), e);
            return ResponseEntity.internalServerError().body("Recover blockchain wallet failed: " + e.getMessage());
        }
    }

    @Operation(summary = "Derive a child key for a blockchain wallet by index")
    @PostMapping("/derive")
    public ResponseEntity<?> deriveKey(@RequestBody DeriveRequest request) {
        log.info("Derive child key for user: {} at index: {}", request.getUserId(), request.getIndex());
        try {
            ChildKey key = walletService.deriveChildKey(request.getUserId(), request.getIndex());
            return ResponseEntity.ok(key);
        } catch (Exception e) {
            log.error("Failed to derive child key for user: {}", request.getUserId(), e);
            return ResponseEntity.internalServerError().body("Derive child key failed: " + e.getMessage());
        }
    }

    @Data
    public static class RecoverRequest {
        @NotBlank
        private String userId;
        @NotBlank
        private String mnemonic;
    }

    @Data
    public static class DeriveRequest {
        @NotBlank
        private String userId;
        @Min(0)
        private int index;
    }

}
