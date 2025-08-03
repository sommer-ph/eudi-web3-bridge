//! Inner circuit implementation for the recursive zk-SNARK system.
//!
//! This module implements the inner circuit which performs two main computations:
//! - C1: Credential key derivation (pk_c = sk_c * G)
//! - C2: Credential public key equality check (pk_c === pk_cred) 
//! - C3: ECDSA signature verification
//!
//! The inner circuit produces a proof that can be recursively verified by the outer circuit.

use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::ecdsa::{
    verify_p256_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets returned when building the inner circuit.
#[allow(dead_code)]
pub struct InnerCircuitTargets {
    pub pk_i: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,
    pub pk_cred: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
}

/// Circuit and targets for the inner EUDI credential binding circuit.
#[allow(dead_code)]
pub struct InnerCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: InnerCircuitTargets,
}

/// Build the inner circuit proving correctness of a P256 signature and key derivation.
/// This corresponds to the EUDI credential binding circuit with three components:
/// C1: pk_c = KeyDer(sk_c) - EUDI wallet key derivation over P256
/// C2: pk_c === pk_cred - Public key equality check  
/// C3: SigVerify(pk_I, msg, sig) - Credential signature verification over P256
pub fn build_inner_circuit() -> InnerCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: issuer public key (pk_I)
    let pk_i = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_i.x.value.limbs.iter().chain(pk_i.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private inputs
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    // Private inputs: credential public key (extracted from c.cnf.jwk)
    let pk_cred = builder.add_virtual_affine_point_target::<P256>();
    
    // Private input: EUDI wallet secret key
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // === C1: EUDI Wallet Key Derivation (pk_c = KeyDer(sk_c)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk_c =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);

    // === C2: Credential Public Key Check (pk_c === pk_cred) ===
    // Ensure the derived public key matches the key stored in the credential
    builder.connect_affine_point(&pk_c, &pk_cred);

    // === C3: Credential Signature Verification (SigVerify(pk_I, msg, sig)) ===
    // Verify that the credential was validly signed by a trusted issuer
    let pk_target = ECDSAPublicKeyTarget(pk_i.clone());
    verify_p256_message_circuit(&mut builder, msg.clone(), signature.clone(), pk_target);

    let data = builder.build::<Cfg>();
    let targets = InnerCircuitTargets {
        pk_i,
        msg,
        sig: signature,
        pk_cred,
        sk_c,
    };
    InnerCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::field::types::{Sample, PrimeField};
    use plonky2::iop::witness::PartialWitness;
    use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
    use crate::utils::parsing::set_nonnative_target;

    #[test]
    #[ignore]
    fn test_inner_circuit_only() -> Result<()> {
        use std::time::Instant;
        
        println!("=== INNER CIRCUIT: EUDI CREDENTIAL BINDING ===");
        
        let start = Instant::now();
        let inner = build_inner_circuit();
        println!("Circuit building time: {:?}", start.elapsed());
        println!("Circuit size: {} gates", inner.data.common.degree());

        println!("\nGenerating test data...");
        let data_start = Instant::now();
        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk = sk_c.to_public().0;
        println!("Test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up witness...");
        let witness_start = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        pw.set_biguint_target(&inner.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw.set_biguint_target(&inner.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw, &inner.targets.msg, msg)?;
        set_nonnative_target(&mut pw, &inner.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw, &inner.targets.sig.s, sig.s)?;
        pw.set_biguint_target(&inner.targets.pk_cred.x.value, &pk.x.to_canonical_biguint())?;
        pw.set_biguint_target(&inner.targets.pk_cred.y.value, &pk.y.to_canonical_biguint())?;
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
        
        println!("\nTotal inner circuit time: {:?}", start.elapsed());
        println!("=== INNER CIRCUIT COMPLETE ===\n");
        
        result
    }
}