use anyhow::Result;
use hex::FromHex;
use k256::{ecdsa::SigningKey as K256Secret, PublicKey as K256Public};
use p256::{ecdsa::SigningKey as P256Secret, PublicKey as P256Public};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct Point { x: String, y: String }

#[derive(Deserialize)]
struct Input {
    pk_cred: Point,
    sk_c: String,
    sk0: String,
    pk0: Point,
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    Vec::from_hex(s.trim_start_matches("0x")).unwrap()
}

fn main() -> Result<()> {
    let json: Input = serde_json::from_slice(
        &fs::read(PathBuf::from("inputs/experiments/outer_key_der.json"))?
    )?;

    // ---------- 1. Check P-256 Key Derivation (EUDI Credential) ----------
    let sk_c_bytes = hex_to_bytes(&json.sk_c);
    let sk_c = P256Secret::from_slice(&sk_c_bytes)?;
    let pk_cred_calc = P256Public::from(sk_c.verifying_key());

    let x_cred_bytes = hex_to_bytes(&json.pk_cred.x);
    let y_cred_bytes = hex_to_bytes(&json.pk_cred.y);
    // SEC1 uncompressed format: 0x04 + x + y
    let mut pk_cred_bytes = vec![0x04];
    pk_cred_bytes.extend_from_slice(&x_cred_bytes);
    pk_cred_bytes.extend_from_slice(&y_cred_bytes);
    let pk_cred_given = P256Public::from_sec1_bytes(&pk_cred_bytes)?;

    assert_eq!(pk_cred_calc, pk_cred_given, "pk_cred does not match sk_c");
    println!("P-256 keypair (sk_c / pk_cred) is consistent");

    // ---------- 2. Check secp256k1 Key Derivation (Blockchain Wallet) ----------
    let sk0_bytes = hex_to_bytes(&json.sk0);
    let sk0 = K256Secret::from_slice(&sk0_bytes)?;
    let pk0_calc = K256Public::from(sk0.verifying_key());

    let x0_bytes = hex_to_bytes(&json.pk0.x);
    let y0_bytes = hex_to_bytes(&json.pk0.y);
    let mut pk0_bytes = vec![0x04];
    pk0_bytes.extend_from_slice(&x0_bytes);
    pk0_bytes.extend_from_slice(&y0_bytes);
    let pk0_given = K256Public::from_sec1_bytes(&pk0_bytes)?;

    assert_eq!(pk0_calc, pk0_given, "pk0 does not match sk0");
    println!("secp256k1 keypair (sk0 / pk0) is consistent");

    println!("All key derivations are valid");
    Ok(())
}