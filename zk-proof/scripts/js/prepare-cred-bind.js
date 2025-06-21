import fs from "fs";
import asn1 from "asn1.js";
import { createHash } from "crypto";
import { Crypto } from "@peculiar/webcrypto";
import poseidon from "poseidon-lite"; // Oder circomlibjs.poseidon wenn du circomlib verwendest

// Initialisiere WebCrypto
const crypto = new Crypto();

// Konstanten
const limbBitsR1 = 43;
const limbBitsK1 = 64;

// Hilfsfunktionen
function bigintToLimbs(val, limbBits, numLimbs) {
  const mask = (BigInt(1) << BigInt(limbBits)) - BigInt(1);
  const limbs = [];
  for (let i = 0; i < numLimbs; i++) {
    limbs.push(((val >> BigInt(i * limbBits)) & mask).toString());
  }
  return limbs;
}

async function computePkC(skLimbs) {
  let skBigInt = BigInt(0);
  for (let i = 0; i < skLimbs.length; i++) {
    skBigInt += BigInt(skLimbs[i]) << BigInt(i * limbBitsR1);
  }

  // Generiere PKCS#8 Struktur für Import
  const skHex = skBigInt.toString(16).padStart(64, "0");
  const skBytes = Buffer.from(skHex, "hex");

  const pkcs8Prefix = Buffer.from(
    "308141020100301306072a8648ce3d020106082a8648ce3d030107044d304b0201010420",
    "hex"
  );
  const pkcs8Suffix = Buffer.from("a144034200" + "00".repeat(65), "hex"); // 65-Byte Dummy für PublicKey

  const pkcs8Key = Buffer.concat([pkcs8Prefix, skBytes, pkcs8Suffix]);

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8Key,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"]
  );

  const publicKeyDer = await crypto.subtle.exportKey("spki", privateKey);
  const publicKey = Buffer.from(publicKeyDer);

  // Extrahiere X und Y aus SPKI
  const publicKeyBytes = publicKey.slice(-65);
  const pkX = BigInt("0x" + publicKeyBytes.slice(1, 33).toString("hex"));
  const pkY = BigInt("0x" + publicKeyBytes.slice(33).toString("hex"));

  return {
    x: bigintToLimbs(pkX, limbBitsR1, 6),
    y: bigintToLimbs(pkY, limbBitsR1, 6),
  };
}

async function main() {
  // Daten einlesen
  const wallet = JSON.parse(fs.readFileSync("philipp-eudi-wallet.json"));
  const credential = JSON.parse(
    fs.readFileSync("philipp-eudi-credential-verification.json")
  );
  const blockchain = JSON.parse(
    fs.readFileSync("philipp-blockchain-wallet.json")
  );

  // 1) sk_c dekodieren
  const pkcs8 = asn1.define("PrivateKeyInfo", function () {
    this.seq().obj(
      this.key("version").int(),
      this.key("privateKeyAlgorithm")
        .seq()
        .obj(
          this.key("algorithm").objid(),
          this.key("parameters").optional().any()
        ),
      this.key("privateKey").octstr()
    );
  });
  const pkcs8Decoded = pkcs8.decode(
    Buffer.from(wallet.privateKey, "base64"),
    "der"
  );
  const privateKeyHex = pkcs8Decoded.privateKey.toString("hex");
  const sk_c_bigint = BigInt("0x" + privateKeyHex);
  const sk_c_limbs = bigintToLimbs(sk_c_bigint, limbBitsR1, 6);

  // 2) pk_c berechnen (neu!)
  const pk_c = await computePkC(sk_c_limbs);

  // 3) issuer public key dekodieren
  const issuerPublicKeyHex = Buffer.from(
    credential.issuerPublicKey,
    "base64"
  ).toString("hex");
  const pk_I_x = BigInt("0x" + issuerPublicKeyHex.slice(2, 66));
  const pk_I_y = BigInt("0x" + issuerPublicKeyHex.slice(66));
  const pk_I = [
    bigintToLimbs(pk_I_x, limbBitsR1, 6),
    bigintToLimbs(pk_I_y, limbBitsR1, 6),
  ];

  // 4) msghash berechnen
  const header = credential.jwt.split(".")[0];
  const payload = credential.jwt.split(".")[1];
  const data = Buffer.from(`${header}.${payload}`);
  const hash = createHash("sha256").update(data).digest();
  const msghash_bigint = BigInt("0x" + hash.toString("hex"));
  const msghash = bigintToLimbs(msghash_bigint, limbBitsR1, 6);

  // 5) Signatur dekodieren
  const signatureDER = Buffer.from(credential.signature, "base64");
  const ECDSASig = asn1.define("ECDSASignature", function () {
    this.seq().obj(this.key("r").int(), this.key("s").int());
  });
  const sigDecoded = ECDSASig.decode(signatureDER, "der");
  const r_limbs = bigintToLimbs(sigDecoded.r, limbBitsR1, 6);
  const s_limbs = bigintToLimbs(sigDecoded.s, limbBitsR1, 6);

  // 6) sk_0 Blockchain Secret Key dekodieren
  const sk_0_bigint = BigInt(
    "0x" + Buffer.from(blockchain.privateKey, "base64").toString("hex")
  );
  const sk_0_limbs = bigintToLimbs(sk_0_bigint, limbBitsK1, 4);

  // 7) pk_0 Blockchain Public Key dekodieren
  const blockchainPublicKey = Buffer.from(blockchain.publicKey, "base64");
  let pk_0_x, pk_0_y;
  if (blockchainPublicKey[0] === 0x04) {
    pk_0_x = BigInt("0x" + blockchainPublicKey.slice(1, 33).toString("hex"));
    pk_0_y = BigInt("0x" + blockchainPublicKey.slice(33).toString("hex"));
  } else {
    throw new Error("Compressed format nicht unterstützt");
  }
  const pk_0 = [
    bigintToLimbs(pk_0_x, limbBitsK1, 4),
    bigintToLimbs(pk_0_y, limbBitsK1, 4),
  ];

  // 8) Poseidon Commitment h_0
  const poseidonInputs = [...pk_0[0].map(BigInt), ...pk_0[1].map(BigInt)];
  const h_0_bigint = poseidon(poseidonInputs);
  const h_0 = h_0_bigint.toString();

  // 9) Zusammenführen ins input.json
  const input = {
    pk_I: pk_I,
    h_0: h_0,
    sk_c: sk_c_limbs,
    pk_c: [pk_c.x, pk_c.y],
    msghash: msghash,
    r: r_limbs,
    s: s_limbs,
    sk_0: sk_0_limbs,
    pk_0: pk_0,
  };

  // Schreiben
  fs.writeFileSync("input/prepared/input.json", JSON.stringify(input, null, 2));
  console.log("input.json successfully written.");
}

// Starte Main
main().catch(console.error);
