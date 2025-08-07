use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Point {
    pub x: String,
    pub y: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: String,
    pub s: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterExtendedInput {
    // Inner extended circuit fields
    pub pk_issuer: Point,
    pub msg: String,
    pub signature: Signature,
    pub pk_c: Point,
    pub sk_c: String,
    pub sk_0: String,

    // Inner and outer extended circuit fields (connection point)
    pub pk_0: Point,
    
    // Outer extended circuit BIP32 fields
    pub cc_0: String,
    pub derivation_index: u32,
    pub pk_i: Point,
    pub cc_i: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterProofInput {
    // Inner circuit fields
    pub pk_issuer: Point,
    pub msg: String,
    pub signature: Signature,
    pub pk_c: Point,
    pub sk_c: String,
    // Outer circuit fields
    pub sk_0: String,
    pub pk_0: Point,
}

// Experimental circuit input structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterKeyDerInput {
    // Inner key derivation fields
    pub pk_c: Point,
    pub sk_c: String,
    // Outer key derivation fields  
    pub sk_0: String,
    pub pk_0: Point,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterSigVerifyInput {
    // Inner signature verification fields
    pub pk_issuer: Point,
    pub msg: String,
    pub signature: Signature,
    // Outer signature verification fields
    pub sk_0: String,
    pub pk_0: Point,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bip32KeyDerInput {
    // Parent key and chain code (parent public key is private input)
    pub pk_0: Point,
    pub cc_0: String,
    // Derivation parameters and expected results (public inputs)
    pub derivation_index: u32,
    pub pk_i: Point,
    pub cc_i: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerSigVerifyStaticInput {
    // Inner signature verification fields with static public key
    // No pk_issuer field needed since it's fixed in the circuit
    pub msg: String,
    pub signature: Signature,
}
