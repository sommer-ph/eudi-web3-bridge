use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets returned when building the P256 outer circuit.
#[allow(dead_code)]
pub struct OuterP256CircuitTargets {
    pub pk0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
}

/// Circuit and targets for the P256 outer recursive circuit.
#[allow(dead_code)]
pub struct OuterP256Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: OuterP256CircuitTargets,
}

/// Build the P256 outer circuit proving P256 key derivation and recursively verifying the inner proof.
/// This corresponds to the blockchain wallet key derivation circuit that:
/// 1. Proves pk0 = KeyDer(sk0) over P256 (instead of secp256k1)
/// 2. Recursively verifies the inner EUDI credential binding proof
pub fn build_outer_p256_circuit(inner_common: &CommonCircuitData<F, D>) -> OuterP256Circuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: P256 blockchain wallet public key (pk0)
    let pk0 = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk0.x.value.limbs.iter().chain(pk0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private input: P256 blockchain wallet secret key (sk0)
    let sk0 = builder.add_virtual_nonnative_target::<P256Scalar>();

    // === Blockchain Wallet Key Derivation (pk0 = KeyDer(sk0)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk0_calc = fixed_base_curve_mul_circuit::<P256, F, D>(
        &mut builder,
        P256::GENERATOR_AFFINE,
        &sk0,
    );
    builder.connect_affine_point(&pk0_calc, &pk0);

    // === Recursive Proof Verification ===
    // Add targets for the proof of the inner EUDI circuit and verify it recursively
    let proof = builder.add_virtual_proof_with_pis(inner_common);
    let vd = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_common);

    let data = builder.build::<Cfg>();
    let targets = OuterP256CircuitTargets {
        pk0,
        sk0,
        proof,
        vd,
    };
    OuterP256Circuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::inner::build_inner_circuit;
    use anyhow::Result;
    use plonky2::field::types::Sample;
    use plonky2::field::types::{PrimeField, PrimeField64};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

    /// Helper to set a nonnative target.
    fn set_nonnative_target<FF: PrimeField>(
        pw: &mut PartialWitness<F>,
        target: &plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<FF>,
        value: FF,
    ) -> Result<()>
    where
        F: PrimeField64,
    {
        pw.set_biguint_target(&target.value, &value.to_canonical_biguint())
    }

    #[test]
    #[ignore]
    fn test_recursive_proof_p256() -> Result<()> {
        use std::time::Instant;
        
        println!("=== RECURSIVE ZK-SNARK PROOF SYSTEM (P256 VARIANT) ===");
        let total_start = Instant::now();

        println!("\n=== INNER CIRCUIT: EUDI CREDENTIAL BINDING ===");
        
        // Build inner circuit and generate witness.
        let inner_start = Instant::now();
        let inner = build_inner_circuit();
        println!("Inner circuit building time: {:?}", inner_start.elapsed());
        println!("Inner circuit size: {} gates", inner.data.common.degree());

        println!("\nGenerating inner circuit test data...");
        let data_start = Instant::now();
        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk = sk_c.to_public().0;
        println!("Inner test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up inner circuit witness...");
        let witness_start = Instant::now();
        let mut pw1 = PartialWitness::<F>::new();
        pw1.set_biguint_target(&inner.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&inner.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &inner.targets.msg, msg)?;
        set_nonnative_target(&mut pw1, &inner.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw1, &inner.targets.sig.s, sig.s)?;
        pw1.set_biguint_target(&inner.targets.pk_cred.x.value, &pk.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&inner.targets.pk_cred.y.value, &pk.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &inner.targets.sk_c, sk_c_val)?;
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

        println!("\n=== OUTER CIRCUIT: RECURSIVE CIRCUIT WITH P256 ===");

        // Build P256 outer circuit and prove recursively.
        let outer_start = Instant::now();
        let outer = build_outer_p256_circuit(&inner.data.common);
        println!("Outer P256 circuit building time: {:?}", outer_start.elapsed());
        println!("Outer P256 circuit size: {} gates", outer.data.common.degree());

        println!("\nGenerating outer P256 circuit test data...");
        let data2_start = Instant::now();
        let sk0_val = P256Scalar::rand();
        let sk0 = ECDSASecretKey::<P256>(sk0_val);
        let pk0 = sk0.to_public().0;
        println!("Outer P256 test data generation time: {:?}", data2_start.elapsed());

        println!("\nSetting up outer P256 circuit witness...");
        let witness2_start = Instant::now();
        let mut pw2 = PartialWitness::<F>::new();
        pw2.set_biguint_target(&outer.targets.pk0.x.value, &pk0.x.to_canonical_biguint())?;
        pw2.set_biguint_target(&outer.targets.pk0.y.value, &pk0.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw2, &outer.targets.sk0, sk0_val)?;
        pw2.set_proof_with_pis_target(&outer.targets.proof, &proof1)?;
        pw2.set_verifier_data_target(&outer.targets.vd, &inner.data.verifier_only)?;
        println!("Outer P256 witness setup time: {:?}", witness2_start.elapsed());

        println!("\nGenerating outer P256 circuit recursive proof...");
        let prove2_start = Instant::now();
        let proof2 = outer.data.prove(pw2)?;
        let prove2_time = prove2_start.elapsed();
        println!("Outer P256 proof generation time: {:?}", prove2_time);
        println!("Outer P256 proof size: {} bytes", proof2.to_bytes().len());

        println!("\nVerifying outer P256 circuit recursive proof...");
        let verify2_start = Instant::now();
        let result = outer.data.verify(proof2);
        println!("Outer P256 proof verification time: {:?}", verify2_start.elapsed());
        
        let outer_total = outer_start.elapsed();
        println!("Outer P256 circuit total time: {:?}", outer_total);
        
        println!("\n=== PERFORMANCE SUMMARY (P256 VARIANT) ===");
        println!("Inner Circuit (EUDI) total time: {:?}", inner_total);
        println!("Outer P256 Circuit (Recursive) total time: {:?}", outer_total);
        println!("Total recursive proof system time: {:?}", total_start.elapsed());
        println!("=== RECURSIVE P256 PROOF COMPLETE ===\n");
        
        result
    }
}