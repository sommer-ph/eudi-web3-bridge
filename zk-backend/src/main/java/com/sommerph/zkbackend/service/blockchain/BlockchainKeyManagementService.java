package com.sommerph.zkbackend.service.blockchain;

import com.sommerph.zkbackend.util.LimbUtils;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDUtils;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

@Slf4j
@Service
public class BlockchainKeyManagementService {

    public String generateMnemonic() {
        log.info("Generate mnemonic for blockchain wallet");
        try {
            byte[] entropy = new byte[16]; // 128 bit = 12 words
            SecureRandom.getInstanceStrong().nextBytes(entropy);
            return String.join(" ", org.bitcoinj.crypto.MnemonicCode.INSTANCE.toMnemonic(entropy));
        } catch (Exception e) {
            log.error("Failed to generate mnemonic", e);
            throw new RuntimeException("Mnemonic generation failed", e);
        }
    }

    public DeterministicKey deriveMasterKey(String mnemonic) {
        log.info("Derive master key from mnemonic: {}", mnemonic);
        try {
            List<String> words = List.of(mnemonic.trim().split("\\s+"));
            DeterministicSeed seed = new DeterministicSeed(words, null, "", 0L);
            DeterministicKeyChain keyChain = DeterministicKeyChain.builder().seed(seed).build();
            return keyChain.getKeyByPath(HDUtils.parsePath("M/44H/0H/0H"), true);
        } catch (Exception e) {
            log.error("Failed to derive master key", e);
            throw new RuntimeException("Master key derivation failed", e);
        }
    }

    public DeterministicKey deriveChildKey(String mnemonic, int index) {
        log.info("Derive child key at index {}", index);
        try {
            List<String> words = List.of(mnemonic.trim().split("\\s+"));
            DeterministicSeed seed = new DeterministicSeed(words, null, "", 0L);
            DeterministicKeyChain keyChain = DeterministicKeyChain.builder().seed(seed).build();
            /*
            This implementation uses a simplified derivation path:
            - Standard BIP44 path: m / purpose' / coin_type' / account' / change / address_index
            - Here, child keys (normally at the address_index level) are derived directly under the account node (at the change level)
            - This design aligns with the construction chapter and simplifies zk-proof implementation
            - Normally, the full BIP44-compliant path would be: m/44H/0H/0H/0/ + index
            - In this setup, the master key pair corresponds to node m/44H/0H/0H, and each child key at index i is derived at m/44H/0H/0H/i
            - This is a single-layer derivation from the account node
            */
            List<ChildNumber> path = HDUtils.parsePath("M/44H/0H/0H/" + index);
            return keyChain.getKeyByPath(path, true);
        } catch (Exception e) {
            log.error("Failed to derive child key at index {}", index, e);
            throw new RuntimeException("Child key derivation failed", e);
        }
    }

    public String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // Circuit-related operations

    public String[] getSecretKeyLimbs(DeterministicKey key) {
        log.info("Get secret key limbs");
        BigInteger sk = new BigInteger(1, key.getPrivKeyBytes());
        return LimbUtils.scalarToLimbsK1(sk);
    }

    public String[][] getPublicKeyLimbs(DeterministicKey key) {
        log.info("Get public key limbs");
        BigInteger x = key.getPubKeyPoint().getXCoord().toBigInteger();
        BigInteger y = key.getPubKeyPoint().getYCoord().toBigInteger();
        return LimbUtils.pointToLimbsK1(x, y);
    }

}
