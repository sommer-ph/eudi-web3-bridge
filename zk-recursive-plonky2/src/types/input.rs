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
pub struct InnerProofInput {
    pub pk_i: Point,
    pub msg: String,
    pub signature: Signature,
    pub pk_cred: Point,
    pub sk_c: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterProofInput {
    pub sk0: String,
    pub pk0: Point,
}

