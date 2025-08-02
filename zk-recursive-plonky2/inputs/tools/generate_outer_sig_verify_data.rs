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
    /// Ziel-Datei
    #[arg(short, long, default_value = "outer_sig_verify.json")]
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
    pk_i: Point,
    msg: String,
    signature: Signature,
    sk0: String,
    pk0: Point,
}

/// 64-stellige Hex-Darstellung (big-endian) eines Feld-Elements
fn to_hex<F: PrimeField>(x: &F) -> String {
    let mut s = x.to_canonical_biguint().to_str_radix(16);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    format!("0x{s}")
}
/// dito für BigUint (Koordinatenpunkte)
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
    let sk_i = ECDSASecretKey::<P256>(P256Scalar::rand());
    let pk_i = sk_i.to_public().0;

    let msg = P256Scalar::rand();                  // zufällige Nachricht
    let mut sig = sign_message(msg, sk_i);         // (r,s)

    // ---------- Low-s-Normalisierung ----------
    // Gruppenordnung n von P-256 als BigUint
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
    let sk0_scalar = Secp256K1Scalar::rand();
    let sk0 = ECDSASecretKey::<Secp256K1>(sk0_scalar);
    let pk0 = sk0.to_public().0;

    // ---------- 3. JSON ausgeben ----------
    let json = OuterSigVerifyInput {
        pk_i: Point {
            x: to_hex(&pk_i.x),
            y: to_hex(&pk_i.y),
        },
        msg: to_hex(&msg),
        signature: Signature {
            r: to_hex(&sig.r),
            s: to_hex(&sig.s),
        },
        sk0: to_hex(&sk0_scalar),
        pk0: Point {
            x: to_hex_biguint(&pk0.x.to_canonical_biguint()),
            y: to_hex_biguint(&pk0.y.to_canonical_biguint()),
        },
    };

    fs::write(&args.output, serde_json::to_string_pretty(&json)?)?;
    println!("Neue Test-JSON unter {:?}", args.output);
    Ok(())
}
