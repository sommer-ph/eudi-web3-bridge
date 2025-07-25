use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2::field::types::{Sample, PrimeField};
use serde_json::json;

fn main() {
    // Generate random secret key for issuer
    let sk_i_val = P256Scalar::rand();
    let sk_i = ECDSASecretKey::<P256>(sk_i_val);
    let pk_i = sk_i.to_public().0;
    
    // Generate random message to sign
    let msg = P256Scalar::rand();
    
    // Sign message with issuer's key
    let sig = sign_message(msg, sk_i);
    
    // Generate random secret key for EUDI wallet
    let sk_c_val = P256Scalar::rand();
    let sk_c = ECDSASecretKey::<P256>(sk_c_val);
    let pk_cred = sk_c.to_public().0;
    
    // Create JSON output
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
        "pk_cred": {
            "x": format!("0x{:064x}", pk_cred.x.to_canonical_biguint()),
            "y": format!("0x{:064x}", pk_cred.y.to_canonical_biguint())
        },
        "sk_c": format!("0x{:064x}", sk_c_val.to_canonical_biguint())
    });
    
    println!("{}", serde_json::to_string_pretty(&test_data).unwrap());
}