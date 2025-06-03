/**
 * prepare-ecdsa-input.js
 * ----------------------
 * Liest input/eudi-wallet.json und schreibt input/prepared-input.json
 * im Format, das der Circom-Circuit mit n = 43, k = 6 erwartet.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const base64url = require("base64url");
const asn1 = require("asn1.js");

// ── util: 258-Bit-Zahl → 6 Little-Endian-Limbs à 43 Bit ────────────
function toLimbs43(decStr) {
  let n = BigInt(decStr);
  const mask = (1n << 43n) - 1n;
  const limbs = [];
  for (let i = 0; i < 6; i++) {
    limbs.push((n & mask).toString()); // Dezimal-String für Circom
    n >>= 43n;
  }
  return limbs; // Länge 6
}

// ── util: SHA-256(messageStr) → BigInt (little-endian) ────────────
function sha256BigIntLE(asciiStr) {
  const hash = crypto.createHash("sha256").update(asciiStr, "ascii").digest();
  let acc = 0n;
  for (let i = 31; i >= 0; i--) acc = (acc << 8n) + BigInt(hash[i]); // LE
  return acc.toString();
}

// ── ASN.1-Schema für r/s-Extraktion ───────────────────────────────
const ECDSASignature = asn1.define("ECDSASignature", function () {
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

// ── main ───────────────────────────────────────────────────────────
(function main() {
  const inFile = path.join(__dirname, "..", "input", "eudi-wallet.json");
  const outFile = path.join(__dirname, "..", "input", "prepared-input.json");

  const wallet = JSON.parse(fs.readFileSync(inFile, "utf8"));
  const cred = wallet.credentials[0];

  // 1) Header.Payload zusammen­bauen
  const headerB64 = base64url.encode(JSON.stringify(cred.header));
  const payloadB64 = base64url.encode(JSON.stringify(cred.payload));
  const messageStr = `${headerB64}.${payloadB64}`; // SD-JWT Input

  // 2) SHA-256 off-chain hashen
  const hashLimbs = toLimbs43(sha256BigIntLE(messageStr));

  // 3) Signatur (r, s) aus DER
  const sigBuf = base64url.toBuffer(cred.signature);
  const { r, s } = ECDSASignature.decode(sigBuf, "der");
  const rLimbs = toLimbs43(r.toString());
  const sLimbs = toLimbs43(s.toString());

  // 4) Issuer-Pubkey (dezimal) → Limbs
  const { x, y } = wallet.issuerPublicKey;
  const xLimbs = toLimbs43(x);
  const yLimbs = toLimbs43(y);

  // 5) Ergebnis schreiben
  const out = {
    msghash: hashLimbs, // [6]
    r: rLimbs, // [6]
    s: sLimbs, // [6]
    pub: [xLimbs, yLimbs], // [2][6]
    dummy: 1,
  };

  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log("✅  prepared-input.json wurde gespeichert.");
})();
