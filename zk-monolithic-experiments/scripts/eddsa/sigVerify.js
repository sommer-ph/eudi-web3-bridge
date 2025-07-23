const fs = require('fs');
const crypto = require('crypto');
const buildEddsa = require("circomlibjs").buildEddsa;
const buildBabyjub = require("circomlibjs").buildBabyjub;

async function generateSignatureVerificationInputs() {
    const eddsa = await buildEddsa();
    const babyJub = await buildBabyjub();
    const F = babyJub.F;
    
    // Generate a random private key (32 bytes)
    const prvKey = crypto.randomBytes(32);
    
    // Generate public key from private key
    const pubKey = eddsa.prv2pub(prvKey);
    
    // Message to sign (use F.e to create proper field element)
    const msg = F.e(1234567890);
    
    // Sign the message using EdDSA MiMC
    const signature = eddsa.signMiMC(prvKey, msg);
    
    // Verify the signature works (optional check)
    const isValid = eddsa.verifyMiMC(msg, signature, pubKey);
    if (!isValid) {
        throw new Error("Generated signature is invalid!");
    }
    
    return {
        message: F.toObject(msg).toString(),
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
    const outputPath = 'input/prepared/eddsa-signature-verification.json';

    // Ensure directory exists
    const dir = 'input/prepared';
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    // Write to file
    fs.writeFileSync(outputPath, JSON.stringify(inputs, null, 2));
    console.log(`EdDSA signature verification inputs generated and saved to: ${outputPath}`);
    console.log('Inputs:', inputs);
}

main().catch(console.error);