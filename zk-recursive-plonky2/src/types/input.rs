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
pub enum SignatureMode {
    Static,   // pk_issuer is static  
    Dynamic,  // pk_issuer is dynamic
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeriveMode {
    Sha512,   // Use HMAC-SHA512 for BIP32 key derivation
    Poseidon, // Use HMAC-Poseidon for BIP32-like key derivation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    pub signature_mode: SignatureMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullInput {
    // C1+C2: EUDI Key Derivation (P256)
    pub pk_c: Point,
    pub sk_c: String,
    
    // C3: Signature Verification (P256)
    pub pk_issuer: Option<Point>,  // None when SignatureMode::Static
    pub msg: String,
    pub signature: Signature,
    
    // C4: Secp256k1 Key Derivation 
    pub sk_0: String,
    pub pk_0: Point,
    
    // C5: BIP32 Key Derivation - ONLY FOR OUTER
    pub cc_0: String,
    pub derivation_index: u32,
    pub pk_i: Point,
    pub cc_i: String,
}
