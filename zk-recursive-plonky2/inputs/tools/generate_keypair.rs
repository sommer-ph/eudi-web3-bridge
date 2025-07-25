use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{PrimeField, Sample};
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::ecdsa::ECDSASecretKey;

fn main() {
    // Generate a random secp256k1 private key
    let sk_val = Secp256K1Scalar::rand();
    let sk = ECDSASecretKey::<Secp256K1>(sk_val);
    let pk = sk.to_public().0;
    
    println!("Generated valid secp256k1 key pair:");
    println!("{{");
    println!("  \"sk0\": \"0x{:064x}\",", sk_val.to_canonical_biguint());
    println!("  \"pk0\": {{");
    println!("    \"x\": \"0x{:064x}\",", pk.x.to_canonical_biguint());
    println!("    \"y\": \"0x{:064x}\"", pk.y.to_canonical_biguint());
    println!("  }}");
    println!("}}");
}