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
pub struct OuterProofInput {
    // Inner circuit fields
    pub pk_i: Point,
    pub msg: String,
    pub signature: Signature,
    pub pk_cred: Point,
    pub sk_c: String,
    // Outer circuit fields
    pub sk0: String,
    pub pk0: Point,
}

// Experimental circuit input structures

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterKeyDerInput {
    // Inner key derivation fields
    pub pk_cred: Point,
    pub sk_c: String,
    // Outer key derivation fields  
    pub sk0: String,
    pub pk0: Point,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterSigVerifyInput {
    // Inner signature verification fields
    pub pk_i: Point,
    pub msg: String,
    pub signature: Signature,
    // Outer signature verification fields
    pub sk0: String,
    pub pk0: Point,
}
