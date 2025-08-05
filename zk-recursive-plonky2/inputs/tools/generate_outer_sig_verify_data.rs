use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2_ecdsa::{
    curve::{
        ecdsa::{sign_message, ECDSASecretKey},
        p256::P256,
        secp256k1::Secp256K1,
    },
    field::p256_scalar::P256Scalar,
};
use serde::Serialize;
use std::{fs, path::PathBuf};
use num_traits::Num;

#[derive(Parser)]
struct Args {
    /// Output file path
    #[arg(short, long, default_value = "inputs/experiments/outer_sig_verify.json")]
    output: PathBuf,
}

#[derive(Serialize)]
struct Point {
    x: String,
    y: String,
}
#[derive(Serialize)]
struct Signature {
    r: String,
    s: String,
}
#[derive(Serialize)]
struct OuterSigVerifyInput {
    pk_issuer: Point,
    msg: String,
    signature: Signature,
    sk_0: String,
    pk_0: Point,
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

    // ---------- 1. Issuer-Key (P-256) ----------
    let sk_issuer = ECDSASecretKey::<P256>(P256Scalar::rand());
    let pk_issuer = sk_issuer.to_public().0;

    let msg = P256Scalar::rand();                  // random message
    let mut sig = sign_message(msg, sk_issuer);         // (r,s)

    // ---------- Low-s normalization ----------
    // Group order n of P-256 as BigUint
    const N_HEX: &str =
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    let n = BigUint::from_str_radix(N_HEX, 16).unwrap();
    let n_half = &n >> 1;

    let s_big = sig.s.to_canonical_biguint();
    if s_big > n_half {
        let s_low = &n - s_big;
        sig.s = P256Scalar::from_noncanonical_biguint(s_low);
    }

    // ---------- 2. Wallet-Key (secp256k1) ----------
    let sk_0_scalar = Secp256K1Scalar::rand();
    let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_scalar);
    let pk_0 = sk_0.to_public().0;

    // ---------- 3. Output JSON ----------
    let json = OuterSigVerifyInput {
        pk_issuer: Point {
            x: to_hex(&pk_issuer.x),
            y: to_hex(&pk_issuer.y),
        },
        msg: to_hex(&msg),
        signature: Signature {
            r: to_hex(&sig.r),
            s: to_hex(&sig.s),
        },
        sk_0: to_hex(&sk_0_scalar),
        pk_0: Point {
            x: to_hex_biguint(&pk_0.x.to_canonical_biguint()),
            y: to_hex_biguint(&pk_0.y.to_canonical_biguint()),
        },
    };

    fs::write(&args.output, serde_json::to_string_pretty(&json)?)?;
    println!("New test JSON written to {:?}", args.output);
    Ok(())
}
