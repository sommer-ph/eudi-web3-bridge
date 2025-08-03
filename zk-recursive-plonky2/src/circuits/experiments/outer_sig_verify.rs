use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the outer signature verification circuit.
#[allow(dead_code)]
pub struct OuterSigVerifyTargets {
    pub pk0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
}

/// Outer circuit that recursively verifies the inner signature verification circuit.
#[allow(dead_code)]
pub struct OuterSigVerifyCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: OuterSigVerifyTargets,
}

/// Build outer circuit that proves secp256k1 key derivation and recursively verifies inner signature verification proof.
/// This circuit performs:
/// 1. pk0 = KeyDer(sk0) over secp256k1 (blockchain wallet key derivation)
/// 2. Recursively verifies the inner signature verification proof (P256 ECDSA signature verification)
pub fn build_outer_sig_verify_circuit(inner_common: &CommonCircuitData<F, D>) -> OuterSigVerifyCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: secp256k1 blockchain wallet public key (pk0)
    let pk0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    for limb in pk0.x.value.limbs.iter().chain(pk0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private input: secp256k1 blockchain wallet secret key (sk0)
    let sk0 = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();

    // === Blockchain Wallet Key Derivation (pk0 = KeyDer(sk0)) ===
    // Derive public key from secret key using secp256k1 base point multiplication
    let pk0_calc = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        &mut builder,
        Secp256K1::GENERATOR_AFFINE,
        &sk0,
    );
    builder.connect_affine_point(&pk0_calc, &pk0);

    // === Recursive Proof Verification ===
    // Add targets for the proof of the inner signature verification circuit and verify it recursively
    let proof = builder.add_virtual_proof_with_pis(inner_common);
    let vd = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_common);

    let data = builder.build::<Cfg>();
    let targets = OuterSigVerifyTargets {
        pk0,
        sk0,
        proof,
        vd,
    };
    OuterSigVerifyCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::experiments::inner_sig_verify::build_inner_sig_verify_circuit;
    use anyhow::Result;
    use plonky2::field::types::Sample;
    use crate::utils::parsing::set_nonnative_target;
    use plonky2::field::types::{PrimeField};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
    use plonky2_ecdsa::field::p256_scalar::P256Scalar;
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

    #[test]
    #[ignore]
    fn test_recursive_sig_verify_proof() -> Result<()> {
        use std::time::Instant;
        
        println!("=== RECURSIVE SIGNATURE VERIFICATION PROOF SYSTEM ===");
        let total_start = Instant::now();

        println!("\n=== INNER CIRCUIT: P256 SIGNATURE VERIFICATION ===");
        
        // Build inner signature verification circuit and generate witness.
        let inner_start = Instant::now();
        let inner = build_inner_sig_verify_circuit();
        println!("Inner circuit building time: {:?}", inner_start.elapsed());
        println!("Inner circuit size: {} gates", inner.data.common.degree());

        println!("\nGenerating inner circuit test data...");
        let data_start = Instant::now();
        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<plonky2_ecdsa::curve::p256::P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);
        println!("Inner test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up inner circuit witness...");
        let witness_start = Instant::now();
        let mut pw1 = PartialWitness::<F>::new();
        pw1.set_biguint_target(&inner.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&inner.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &inner.targets.msg, msg)?;
        set_nonnative_target(&mut pw1, &inner.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw1, &inner.targets.sig.s, sig.s)?;
        println!("Inner witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating inner circuit proof...");
        let prove1_start = Instant::now();
        let proof1 = inner.data.prove(pw1)?;
        let prove1_time = prove1_start.elapsed();
        println!("Inner proof generation time: {:?}", prove1_time);
        println!("Inner proof size: {} bytes", proof1.to_bytes().len());

        println!("\nVerifying inner circuit proof...");
        let verify1_start = Instant::now();
        inner.data.verify(proof1.clone())?;
        println!("Inner proof verification time: {:?}", verify1_start.elapsed());
        
        let inner_total = inner_start.elapsed();
        println!("Inner circuit total time: {:?}", inner_total);

        println!("\n=== OUTER CIRCUIT: RECURSIVE SIGNATURE VERIFICATION WITH SECP256K1 ===");

        // Build outer circuit and prove recursively.
        let outer_start = Instant::now();
        let outer = build_outer_sig_verify_circuit(&inner.data.common);
        println!("Outer circuit building time: {:?}", outer_start.elapsed());
        println!("Outer circuit size: {} gates", outer.data.common.degree());

        println!("\nGenerating outer circuit test data...");
        let data2_start = Instant::now();
        let sk0_val = Secp256K1Scalar::rand();
        let sk0 = ECDSASecretKey::<Secp256K1>(sk0_val);
        let pk0 = sk0.to_public().0;
        println!("Outer test data generation time: {:?}", data2_start.elapsed());

        println!("\nSetting up outer circuit witness...");
        let witness2_start = Instant::now();
        let mut pw2 = PartialWitness::<F>::new();
        pw2.set_biguint_target(&outer.targets.pk0.x.value, &pk0.x.to_canonical_biguint())?;
        pw2.set_biguint_target(&outer.targets.pk0.y.value, &pk0.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw2, &outer.targets.sk0, sk0_val)?;
        pw2.set_proof_with_pis_target(&outer.targets.proof, &proof1)?;
        pw2.set_verifier_data_target(&outer.targets.vd, &inner.data.verifier_only)?;
        println!("Outer witness setup time: {:?}", witness2_start.elapsed());

        println!("\nGenerating outer circuit recursive proof...");
        let prove2_start = Instant::now();
        let proof2 = outer.data.prove(pw2)?;
        let prove2_time = prove2_start.elapsed();
        println!("Outer proof generation time: {:?}", prove2_time);
        println!("Outer proof size: {} bytes", proof2.to_bytes().len());

        println!("\nVerifying outer circuit recursive proof...");
        let verify2_start = Instant::now();
        let result = outer.data.verify(proof2);
        println!("Outer proof verification time: {:?}", verify2_start.elapsed());
        
        let outer_total = outer_start.elapsed();
        println!("Outer circuit total time: {:?}", outer_total);
        
        println!("\n=== PERFORMANCE SUMMARY ===");
        println!("Inner Circuit (P256 Sig Verify) total time: {:?}", inner_total);
        println!("Outer Circuit (Recursive Sig Verify) total time: {:?}", outer_total);
        println!("Total recursive signature verification proof system time: {:?}", total_start.elapsed());
        println!("=== RECURSIVE SIGNATURE VERIFICATION PROOF COMPLETE ===\n");
        
        result
    }
}