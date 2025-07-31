use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Sample, PrimeField};
use serde_json::json;

fn main() {
    // Generate P256 data for inner signature verification
    let sk_i_val = P256Scalar::rand();
    let sk_i = ECDSASecretKey::<P256>(sk_i_val);
    let pk_i = sk_i.to_public().0;
    
    // Generate random message to sign
    let msg = P256Scalar::rand();
    
    // Sign message with issuer's P256 key (this creates a valid signature)
    let sig = sign_message(msg, sk_i);
    
    // Generate Secp256K1 data for outer circuit
    let sk0_val = Secp256K1Scalar::rand();
    let sk0 = ECDSASecretKey::<Secp256K1>(sk0_val);
    let pk0 = sk0.to_public().0;
    
    // Create JSON output with both P256 (inner) and Secp256K1 (outer) data
    let test_data = json!({
        "pk_i": {
            "x": format!("0x{:064x}", pk_i.x.to_canonical_biguint()),
            "y": format!("0x{:064x}", pk_i.y.to_canonical_biguint())
        },
        "msg": format!("0x{:064x}", msg.to_canonical_biguint()),
        "signature": {
            "r": format!("0x{:064x}", sig.r.to_canonical_biguint()),
            "s": format!("0x{:064x}", sig.s.to_canonical_biguint())
        },
        "sk0": format!("0x{:064x}", sk0_val.to_canonical_biguint()),
        "pk0": {
            "x": format!("0x{:064x}", pk0.x.to_canonical_biguint()),
            "y": format!("0x{:064x}", pk0.y.to_canonical_biguint())
        }
    });
    
    println!("{}", serde_json::to_string_pretty(&test_data).unwrap());
}