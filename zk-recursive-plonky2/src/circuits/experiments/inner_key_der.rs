use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the key derivation only inner circuit.
#[allow(dead_code)]
pub struct InnerKeyDerTargets {
    pub pk_c: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
}

/// Circuit that only implements the key derivation constraint: pk_c = KeyDer(sk_c)
#[allow(dead_code)]
pub struct InnerKeyDerCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: InnerKeyDerTargets,
}

/// Build inner circuit that only proves key derivation: pk_c = KeyDer(sk_c)
/// This isolates the C1 constraint from the full inner circuit for debugging.
pub fn build_inner_key_der_circuit() -> InnerKeyDerCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public output: derived public key (pk_c)
    let pk_c = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_c.x.value.limbs.iter().chain(pk_c.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private input: EUDI wallet secret key
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // === C1: EUDI Wallet Key Derivation (pk_c = KeyDer(sk_c)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk_c_calc =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);

    // Ensure the calculated public key matches the provided public key
    builder.connect_affine_point(&pk_c_calc, &pk_c);

    let data = builder.build::<Cfg>();
    let targets = InnerKeyDerTargets { pk_c, sk_c };
    InnerKeyDerCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::field::types::Sample;
    use crate::utils::parsing::set_nonnative_target;
    use plonky2::field::types::{PrimeField};
    use plonky2::iop::witness::PartialWitness;
    use plonky2_ecdsa::curve::ecdsa::ECDSASecretKey;
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

    #[test]
    #[ignore]
    fn test_inner_key_der_circuit_only() -> Result<()> {
        use std::time::Instant;
        
        println!("=== INNER KEY DERIVATION CIRCUIT ===");
        
        let start = Instant::now();
        let inner = build_inner_key_der_circuit();
        println!("Circuit building time: {:?}", start.elapsed());
        println!("Circuit size: {} gates", inner.data.common.degree());

        println!("\nGenerating test data...");
        let data_start = Instant::now();
        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk_c = sk_c.to_public().0;
        println!("Test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up witness...");
        let witness_start = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        pw.set_biguint_target(&inner.targets.pk_c.x.value, &pk_c.x.to_canonical_biguint())?;
        pw.set_biguint_target(&inner.targets.pk_c.y.value, &pk_c.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw, &inner.targets.sk_c, sk_c_val)?;
        println!("Witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating proof...");
        let prove_start = Instant::now();
        let proof = inner.data.prove(pw)?;
        let prove_time = prove_start.elapsed();
        println!("Proof generation time: {:?}", prove_time);
        println!("Proof size: {} bytes", proof.to_bytes().len());

        println!("\nVerifying proof...");
        let verify_start = Instant::now();
        let result = inner.data.verify(proof);
        let verify_time = verify_start.elapsed();
        println!("Proof verification time: {:?}", verify_time);
        
        println!("\nTotal key derivation circuit time: {:?}", start.elapsed());
        println!("=== KEY DERIVATION CIRCUIT COMPLETE ===\n");
        
        result
    }
}