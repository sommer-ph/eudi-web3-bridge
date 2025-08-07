use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use plonky2::field::types::{Field, PrimeField, Sample};
use plonky2_ecdsa::{
    curve::{
        ecdsa::{sign_message, ECDSASecretKey},
        p256::P256,
    },
    field::p256_scalar::P256Scalar,
};
use serde::Serialize;
use std::{fs, path::PathBuf};
use num_traits::Num;

#[derive(Parser)]
struct Args {
    /// Output file path
    #[arg(short, long, default_value = "inputs/experiments/inner_sig_verify_static.json")]
    output: PathBuf,
}

#[derive(Serialize)]
struct Signature {
    r: String,
    s: String,
}

#[derive(Serialize)]
struct InnerSigVerifyStaticInput {
    // No pk_issuer field needed since it's fixed in the circuit
    msg: String,
    signature: Signature,
}

/// 64-character hex representation (big-endian) of a field element
fn to_hex<F: PrimeField>(x: &F) -> String {
    let mut s = x.to_canonical_biguint().to_str_radix(16);
    while s.len() < 64 {
        s.insert(0, '0');
    }
    format!("0x{s}")
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Generate test data for static public key signature verification
    println!("Generating inner signature verification (static PK) test data...");

    // Use the fixed private key from the specification 
    let sk_issuer_fixed = "46012408107196755923706193987463047920137073659172279781266729514345066549384";
    let sk_issuer_val = P256Scalar::from_noncanonical_biguint(
        BigUint::from_str_radix(sk_issuer_fixed, 10)?
    );
    let sk_issuer = ECDSASecretKey::<P256>(sk_issuer_val);
    let pk_issuer = sk_issuer.to_public().0;

    // Verify that the public key matches the expected fixed coordinates
    let expected_x = "66432692286261411630769223098970693805397596870633670159153355502222145619968";
    let expected_y = "63182586149833488067701290985084360701345487374231728189741684364091950142361";
    let expected_x_big = BigUint::from_str_radix(expected_x, 10)?;
    let expected_y_big = BigUint::from_str_radix(expected_y, 10)?;
    assert_eq!(pk_issuer.x.to_canonical_biguint(), expected_x_big);
    assert_eq!(pk_issuer.y.to_canonical_biguint(), expected_y_big);
    
    println!("Using fixed issuer public key:");
    println!("  x: {}", expected_x);
    println!("  y: {}", expected_y);

    // Generate random message for signature
    let msg = P256Scalar::rand();
    println!("Generated message: {}", to_hex(&msg));

    // Sign message with fixed issuer key
    let sig = sign_message(msg, sk_issuer);
    println!("Generated signature:");
    println!("  r: {}", to_hex(&sig.r));
    println!("  s: {}", to_hex(&sig.s));

    // Create input structure (no pk_issuer field needed)
    let input = InnerSigVerifyStaticInput {
        msg: to_hex(&msg),
        signature: Signature {
            r: to_hex(&sig.r),
            s: to_hex(&sig.s),
        },
    };

    // Write JSON file
    let json = serde_json::to_string_pretty(&input)?;
    fs::write(&args.output, json)?;

    println!("Inner signature verification (static PK) test data written to: {}", args.output.display());

    Ok(())
}