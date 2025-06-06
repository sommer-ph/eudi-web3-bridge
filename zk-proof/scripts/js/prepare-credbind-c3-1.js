/**
 * prepare-credbind-c3-1.js
 * --------------------------------------------------
 * Build JSON input for CredBind-C3 (ECDSA-P256 check).
 *
 * Args (injected by 3-prepare-input.sh):
 *   0 node
 *   1 script name
 *   2 USER_ID
 *   3 RAW_DIR   (…/input/raw)
 *   4 PREP_DIR  (…/input/prepared)
 *
 * Expects two files inside RAW_DIR:
 *   <uid>-eudi-wallet.json
 *   <uid>-eudi-credential-verification.json
 *
 * Produces  <PREP_DIR>/<uid>-credbind-c3.json
 * in the 6-limb (43-bit) format the Circom circuit expects.
 */

const fs        = require("fs");
const path      = require("path");
const crypto    = require("crypto");
const base64url = require("base64url");
const asn1      = require("asn1.js");

/*────────────────── helpers ──────────────────*/

// 258-bit → 6 little-endian 43-bit limbs (decimal strings)
function toLimbs43(decStr) {
  let n = BigInt(decStr);
  const mask = (1n << 43n) - 1n;
  const out = [];
  for (let i = 0; i < 6; i++) { out.push((n & mask).toString()); n >>= 43n; }
  return out.reverse();          // Circom wants MSB limb first
}

// SHA-256(message) → bigint (BE) as decimal
function sha256BigIntBE(str) {
  const h = crypto.createHash("sha256").update(str, "ascii").digest();
  return [...h].reduce((acc, byte) => (acc << 8n) + BigInt(byte), 0n).toString();
}

// ASN.1 decoder for r / s
const ECDSASignature = asn1.define("ECDSASignature", function () {
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

/*────────────────── main ──────────────────*/
(function main() {
  const uid     = process.argv[2];
  const rawDir  = process.argv[3];
  const prepDir = process.argv[4];

  if (!uid || !rawDir || !prepDir) {
    console.error("Usage: node prepare-credbind-c3-1.js <UID> <RAW_DIR> <PREP_DIR>");
    process.exit(1);
  }

  // ---------- input paths ----------
  const walletFile   = path.join(rawDir, `${uid}-eudi-wallet.json`);
  const issuerFile   = path.join(rawDir, `${uid}-eudi-credential-verification.json`);
  const outFile      = path.join(prepDir, `${uid}-credbind-c3.json`);

  if (!fs.existsSync(walletFile))  { console.error(`Wallet not found: ${walletFile}`);  process.exit(1); }
  if (!fs.existsSync(issuerFile))  { console.error(`Issuer key not found: ${issuerFile}`); process.exit(1); }

  const wallet  = JSON.parse(fs.readFileSync(walletFile, "utf8"));
  const issuer  = JSON.parse(fs.readFileSync(issuerFile, "utf8"));

  const cred = wallet.credentials?.[0];
  if (!cred) { console.error("No credential in wallet JSON"); process.exit(1); }

  // ---------- 1) message = Base64URL(header).payload ----------
  const hdrB64 = base64url.encode(JSON.stringify(cred.header));
  const payB64 = base64url.encode(JSON.stringify(cred.payload));
  const message = `${hdrB64}.${payB64}`;

  const hashLimbs = toLimbs43(sha256BigIntBE(message));

  // ---------- 2) extract r / s ----------
  const { r, s } = ECDSASignature.decode(base64url.toBuffer(cred.signature), "der");
  const rLimbs   = toLimbs43(r.toString());
  const sLimbs   = toLimbs43(s.toString());

  // ---------- 3) issuer public key limbs ----------
  const xLimbs = toLimbs43(issuer.issuerPublicKey.x);
  const yLimbs = toLimbs43(issuer.issuerPublicKey.y);

  // ---------- 4) final JSON ----------
  const circomJson = {
    msghash: hashLimbs,      // [6]
    r:       rLimbs,         // [6]
    s:       sLimbs,         // [6]
    pk_I:    [xLimbs, yLimbs]// [2][6]
  };

  fs.writeFileSync(outFile, JSON.stringify(circomJson, null, 2));
  console.log(`DONE: ${path.basename(outFile)} written.`);
})();
