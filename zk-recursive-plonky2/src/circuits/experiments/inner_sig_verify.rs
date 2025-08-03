use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::ecdsa::{
    verify_p256_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the signature verification only inner circuit.
#[allow(dead_code)]
pub struct InnerSigVerifyTargets {
    pub pk_i: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,
}

/// Circuit that only implements the signature verification constraint: VerifySig(pk_I, msg, sig)
#[allow(dead_code)]
pub struct InnerSigVerifyCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: InnerSigVerifyTargets,
}

/// Build inner circuit that only proves signature verification: VerifySig(pk_I, msg, sig)
/// This isolates the C3 constraint from the full inner circuit for debugging.
pub fn build_inner_sig_verify_circuit() -> InnerSigVerifyCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: issuer public key (pk_I)
    let pk_i = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_i.x.value.limbs.iter().chain(pk_i.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private inputs: message and signature
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    // === C3: Credential Signature Verification (SigVerify(pk_I, msg, sig)) ===
    // Verify that the credential was validly signed by a trusted issuer
    let pk_target = ECDSAPublicKeyTarget(pk_i.clone());
    verify_p256_message_circuit(&mut builder, msg.clone(), signature.clone(), pk_target);

    let data = builder.build::<Cfg>();
    let targets = InnerSigVerifyTargets {
        pk_i,
        msg,
        sig: signature,
    };
    InnerSigVerifyCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::field::types::Sample;
    use crate::utils::parsing::set_nonnative_target;
    use plonky2::field::types::{PrimeField};
    use plonky2::iop::witness::PartialWitness;
    use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

    #[test]
    #[ignore]
    fn test_inner_sig_verify_circuit_only() -> Result<()> {
        use std::time::Instant;
        
        println!("=== INNER SIGNATURE VERIFICATION CIRCUIT ===");
        
        let start = Instant::now();
        let inner = build_inner_sig_verify_circuit();
        println!("Circuit building time: {:?}", start.elapsed());
        println!("Circuit size: {} gates", inner.data.common.degree());

        println!("\nGenerating test data...");
        let data_start = Instant::now();
        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);
        println!("Test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up witness...");
        let witness_start = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        pw.set_biguint_target(&inner.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw.set_biguint_target(&inner.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw, &inner.targets.msg, msg)?;
        set_nonnative_target(&mut pw, &inner.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw, &inner.targets.sig.s, sig.s)?;
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
        
        println!("\nTotal signature verification circuit time: {:?}", start.elapsed());
        println!("=== SIGNATURE VERIFICATION CIRCUIT COMPLETE ===\n");
        
        result
    }
}