const fs = require('fs');
const crypto = require('crypto');
const buildEddsa = require("circomlibjs").buildEddsa;
const buildBabyjub = require("circomlibjs").buildBabyjub;

function msghashToHashValue(msghash) {
    // Convert 6 43-bit limbs (little-endian) back to 256-bit hash value
    let result = BigInt(0);
    for (let i = 5; i >= 0; i--) { // Start from highest limb (little-endian order)
        result = (result << BigInt(43)) + BigInt(msghash[i]);
    }
    return result;
}

async function generateSignatureVerificationInputs() {
    const eddsa = await buildEddsa();
    const babyJub = await buildBabyjub();
    const F = babyJub.F;

    // Read values from c3-with-hash.json
    const c3Data = JSON.parse(fs.readFileSync('input/msg-pk_c-binding/c3-with-hash.json', 'utf8'));

    // Extract values from c3-with-hash.json
    const msghash = c3Data.msghash;
    const headerB64 = c3Data.headerB64;
    const headerB64Length = c3Data.headerB64Length;
    const payloadB64 = c3Data.payloadB64;
    const payloadB64Length = c3Data.payloadB64Length;

    // Convert msghash from 43-bit limbs to single hash value for EdDSA signature
    const hashValue = msghashToHashValue(msghash);

    // Generate a random private key (32 bytes)
    const prvKey = crypto.randomBytes(32);

    // Generate public key from private key
    const pubKey = eddsa.prv2pub(prvKey);

    // Sign the hash using EdDSA MiMC
    const signature = eddsa.signMiMC(prvKey, F.e(hashValue));

    // Verify the signature works (optional check)
    const isValid = eddsa.verifyMiMC(F.e(hashValue), signature, pubKey);
    if (!isValid) {
        throw new Error("Generated signature is invalid!");
    }

    console.log("Using msghash from c3-with-hash.json:", msghash);
    console.log("Hash as BigInt for EdDSA:", hashValue.toString());
    console.log("Header length:", headerB64Length);
    console.log("Payload length:", payloadB64Length);

    return {
        msghash: msghash,
        headerB64: headerB64,
        headerB64Length: headerB64Length,
        payloadB64: payloadB64,
        payloadB64Length: payloadB64Length,
        publicKeyX: F.toObject(pubKey[0]).toString(),
        publicKeyY: F.toObject(pubKey[1]).toString(),
        signatureR8x: F.toObject(signature.R8[0]).toString(),
        signatureR8y: F.toObject(signature.R8[1]).toString(),
        signatureS: signature.S.toString()
    };
}

// Generate inputs and save to JSON file
async function main() {
    const inputs = await generateSignatureVerificationInputs();
    const outputPath = 'input/snark-friendly/eddsa/eddsa-signature-verification.json';

    // Ensure directory exists
    const dir = 'input/snark-friendly/eddsa';
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    // Write to file
    fs.writeFileSync(outputPath, JSON.stringify(inputs, null, 2));
    console.log(`EdDSA signature verification inputs generated and saved to: ${outputPath}`);
    console.log('Inputs:', inputs);
}

main().catch(console.error);