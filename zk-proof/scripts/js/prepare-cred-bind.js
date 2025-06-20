/**
 * prepare-credbind-full.js (finale, robuste Version)
 * ----------------------------------------------------
 * Build full input.json for Credential-Wallet-Binding proof.
 */

const fs = require("fs");
const crypto = require("crypto");
const base64url = require("base64url");
const asn1 = require("asn1.js");
const { buildPoseidon } = require("circomlibjs");

// ──────────────────────────── Helpers ────────────────────────────

function toLimbs43(decStr) {
  let n = BigInt(decStr);
  const mask = (1n << 43n) - 1n;
  const out = [];
  for (let i = 0; i < 6; i++) {
    out.push((n & mask).toString());
    n >>= 43n;
  }
  return out.reverse();
}

function toLimbs64(decStr) {
  let n = BigInt(decStr);
  const mask = (1n << 64n) - 1n;
  const out = [];
  for (let i = 0; i < 4; i++) {
    out.push((n & mask).toString());
    n >>= 64n;
  }
  return out.reverse();
}

function sha256BigIntBE(str) {
  const h = crypto.createHash("sha256").update(str, "ascii").digest();
  return [...h].reduce((acc, byte) => (acc << 8n) + BigInt(byte), 0n).toString();
}

// ASN.1 decoders

const ECDSASignature = asn1.define("ECDSASignature", function () {
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

const PrivateKeyInfoASN = asn1.define("PrivateKeyInfo", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("privateKeyAlgorithm").seq().obj(
      this.key("algorithm").objid(),
      this.key("parameters").optional()
    ),
    this.key("privateKey").octstr()
  );
});

const ECPrivateKeyASN = asn1.define("ECPrivateKey", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("privateKey").octstr(),
    this.key("parameters").optional().explicit(0).any(),
    this.key("publicKey").optional().explicit(1).bitstr()
  );
});

// secp256k1 field prime
const SECP256K1_P = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

// Modular square root for secp256k1 (Tonelli-Shanks simplified for p ≡ 3 mod 4)
function modSqrt(a, p) {
  return modPow(a, (p + 1n) / 4n, p);
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  base = base % modulus;
  while (exponent > 0) {
    if (exponent % 2n === 1n) result = (result * base) % modulus;
    exponent = exponent / 2n;
    base = (base * base) % modulus;
  }
  return result;
}

// ──────────────────────────── Main ────────────────────────────

(async function main() {
  try {
    console.log("🔄 Loading input files...");

    const wallet = JSON.parse(fs.readFileSync("philipp-eudi-wallet.json", "utf8"));
    const issuer = JSON.parse(fs.readFileSync("philipp-eudi-credential-verification.json", "utf8"));
    const blockchain = JSON.parse(fs.readFileSync("philipp-blockchain-wallet.json", "utf8"));

    const cred = wallet.credentials?.[0];
    if (!cred) throw new Error("No credential found in EUDI wallet");

    console.log("✅ Files loaded successfully");

    // ───── 1. Extract sk_c ─────

    console.log("🔄 Extracting EUDI wallet private key (sk_c)...");

    const skDer = Buffer.from(wallet.base64SecretKey, "base64");
    const pkcs8Obj = PrivateKeyInfoASN.decode(skDer, "der");
    const ecPrivateKeyDer = pkcs8Obj.privateKey;
    const skObj = ECPrivateKeyASN.decode(ecPrivateKeyDer, "der");
    const sk_c_BN = BigInt("0x" + skObj.privateKey.toString("hex"));
    const sk_c_limbs = toLimbs43(sk_c_BN.toString());

    // ───── 2. Extract pk_c ─────

    console.log("🔄 Extracting EUDI wallet public key (pk_c)...");

    const pkDer = Buffer.from(wallet.base64PublicKey, "base64");
    const pubkey = pkDer.slice(-65);
    if (pubkey[0] !== 0x04) throw new Error("Unexpected EC point format in public key");

    const pk_c_x = BigInt("0x" + pubkey.slice(1, 33).toString("hex"));
    const pk_c_y = BigInt("0x" + pubkey.slice(33).toString("hex"));
    const pk_c = [toLimbs43(pk_c_x.toString()), toLimbs43(pk_c_y.toString())];

    // ───── 3. Extract pk_I ─────

    console.log("🔄 Extracting issuer public key (pk_I)...");

    const pk_I = [
      toLimbs43(issuer.issuerPublicKey.x),
      toLimbs43(issuer.issuerPublicKey.y)
    ];

    // ───── 4. Compute message hash ─────

    console.log("🔄 Computing credential message hash...");

    const hdrB64 = base64url.encode(JSON.stringify(cred.header));
    const payB64 = base64url.encode(JSON.stringify(cred.payload));
    const message = `${hdrB64}.${payB64}`;
    const msgHashLimbs = toLimbs43(sha256BigIntBE(message));

    // ───── 5. Extract signature ─────

    console.log("🔄 Extracting ECDSA signature...");

    const { r, s } = ECDSASignature.decode(base64url.toBuffer(cred.signature), "der");
    const rLimbs = toLimbs43(r.toString());
    const sLimbs = toLimbs43(s.toString());

    // ───── 6. Extract blockchain wallet keys ─────

    console.log("🔄 Processing blockchain wallet keys...");

    const sk0_BN = BigInt("0x" + Buffer.from(blockchain.base64MasterSecretKey, "base64").toString("hex"));
    const sk0Limbs = toLimbs64(sk0_BN.toString());

    const pk0Buf = Buffer.from(blockchain.base64MasterPublicKey, "base64");

    let final_pk0Limbs;

    if (pk0Buf.length === 33 && (pk0Buf[0] === 0x02 || pk0Buf[0] === 0x03)) {
      console.log("ℹ Detected compressed secp256k1 public key");
      const x = BigInt("0x" + pk0Buf.slice(1, 33).toString("hex"));
      const ySquared = (x ** 3n + 7n) % SECP256K1_P;
      let y = modSqrt(ySquared, SECP256K1_P);
      const isYOdd = (y % 2n) === 1n;
      const prefixOdd = pk0Buf[0] === 0x03;
      if (isYOdd !== prefixOdd) {
        y = SECP256K1_P - y;
      }
      final_pk0Limbs = [toLimbs64(x.toString()), toLimbs64(y.toString())];
      console.log("✅ Successfully decompressed secp256k1 public key");
    } else if (pk0Buf.length === 65 && pk0Buf[0] === 0x04) {
      console.log("ℹ Detected uncompressed secp256k1 public key");
      const x = BigInt("0x" + pk0Buf.slice(1, 33).toString("hex"));
      const y = BigInt("0x" + pk0Buf.slice(33).toString("hex"));
      final_pk0Limbs = [toLimbs64(x.toString()), toLimbs64(y.toString())];
    } else {
      throw new Error("Unexpected format in blockchain public key");
    }

    // ───── 7. Compute Poseidon hash h_0 ─────

    console.log("🔄 Computing Poseidon commitment h_0...");

    const poseidon = await buildPoseidon();
    const poseidonInputs = [...final_pk0Limbs[0].map(BigInt), ...final_pk0Limbs[1].map(BigInt)];
    const h0_F = poseidon.F.toString(poseidon(poseidonInputs));

    // ───── 8. Write circom input ─────

    console.log("🔄 Building final input.json...");

    const circomInput = {
      pk_I, h_0: h0_F,
      sk_c: sk_c_limbs,
      pk_c,
      msghash: msgHashLimbs,
      r: rLimbs,
      s: sLimbs,
      sk_0: sk0Limbs,
      pk_0: final_pk0Limbs
    };

    fs.writeFileSync("input.json", JSON.stringify(circomInput, null, 2));
    console.log("✅ input.json written successfully.");

  } catch (err) {
    console.error("❌ Error:", err.message);
    process.exit(1);
  }
})();
