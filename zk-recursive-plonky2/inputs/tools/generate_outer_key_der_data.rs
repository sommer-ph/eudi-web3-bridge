use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{PrimeField, Sample};
use plonky2_ecdsa::{
    curve::{
        ecdsa::ECDSASecretKey,
        p256::P256,
        secp256k1::Secp256K1,
    },
    field::p256_scalar::P256Scalar,
};
use serde::Serialize;
use std::{fs, path::PathBuf};

#[derive(Parser)]
struct Args {
    /// Output file path
    #[arg(short, long, default_value = "inputs/experiments/outer_key_der.json")]
    output: PathBuf,
}

#[derive(Serialize)]
struct Point {
    x: String,
    y: String,
}

#[derive(Serialize)]
struct OuterKeyDerInput {
    pk_cred: Point,
    sk_c: String,
    sk0: String,
    pk0: Point,
}

/// 64-character hex representation (big-endian) of a field element
fn to_hex<F: PrimeField>(x: &F) -> String {
    let mut s = x.to_canonical_biguint().to_str_radix(16);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    format!("0x{s}")
}

/// Same for BigUint (coordinate points)
fn to_hex_biguint(b: &BigUint) -> String {
    let mut s = b.to_str_radix(16);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    format!("0x{s}")
}

fn main() -> Result<()> {
    let args = Args::parse();

    // ---------- 1. EUDI Credential Key (P-256) ----------
    let sk_c_scalar = P256Scalar::rand();
    let sk_c = ECDSASecretKey::<P256>(sk_c_scalar);
    let pk_cred = sk_c.to_public().0;

    // ---------- 2. Blockchain Wallet Key (secp256k1) ----------
    let sk0_scalar = Secp256K1Scalar::rand();
    let sk0 = ECDSASecretKey::<Secp256K1>(sk0_scalar);
    let pk0 = sk0.to_public().0;

    // ---------- 3. Output JSON ----------
    let json = OuterKeyDerInput {
        pk_cred: Point {
            x: to_hex(&pk_cred.x),
            y: to_hex(&pk_cred.y),
        },
        sk_c: to_hex(&sk_c_scalar),
        sk0: to_hex(&sk0_scalar),
        pk0: Point {
            x: to_hex_biguint(&pk0.x.to_canonical_biguint()),
            y: to_hex_biguint(&pk0.y.to_canonical_biguint()),
        },
    };

    fs::write(&args.output, serde_json::to_string_pretty(&json)?)?;
    println!("New key derivation test JSON written to {:?}", args.output);
    Ok(())
}