const fs = require('fs');
const crypto = require('crypto');
const buildEddsa = require("circomlibjs").buildEddsa;
const buildBabyJub = require("circomlibjs").buildBabyjub;

// EdDSA key derivation input generation
async function generateKeyDerivationInputs() {
    const eddsa = await buildEddsa();
    const babyJub = await buildBabyJub();
    
    // Generate a random private key (32 bytes)
    const privKey = crypto.randomBytes(32);
    const privKeyBigInt = BigInt('0x' + privKey.toString('hex'));
    
    // Ensure private key is within the Baby Jubjub field order
    const privKeyMod = privKeyBigInt % babyJub.subOrder;
    
    // Generate public key from private key using BabyJub multiplication (privKey * G)
    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, privKeyMod);
    
    const inputs = {
        privKey: privKeyMod.toString(),
        pubKey: [
            babyJub.F.toString(pubKey[0]),
            babyJub.F.toString(pubKey[1])
        ]
    };
    
    return inputs;
}

// Generate inputs and save to JSON file
async function main() {
    const inputs = await generateKeyDerivationInputs();
    const outputPath = 'input/prepared/eddsa-key-derivation.json';

    // Ensure directory exists
    const dir = 'input/prepared';
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    // Write to file
    fs.writeFileSync(outputPath, JSON.stringify(inputs, null, 2));
    console.log(`EdDSA key derivation inputs generated and saved to: ${outputPath}`);
    console.log('Inputs:', inputs);
}

main().catch(console.error);