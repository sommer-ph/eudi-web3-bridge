use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
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

/// Targets returned when building the first circuit.
pub struct Step1Targets {
    pub pk_i: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,
    pub pk_cred: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
}

/// Circuit and targets for step one.
pub struct Step1Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: Step1Targets,
}

/// Targets returned when building the second circuit.
pub struct Step2Targets {
    pub pk0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
}

/// Circuit and targets for step two.
pub struct Step2Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: Step2Targets,
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_step1_only() -> Result<()> {
        let step1 = build_step1_circuit();

        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk = sk_c.to_public().0;

        let mut pw1 = PartialWitness::<F>::new();
        pw1.set_biguint_target(&step1.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.msg, msg)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.s, sig.s)?;
        pw1.set_biguint_target(&step1.targets.pk_cred.x.value, &pk.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_cred.y.value, &pk.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.sk_c, sk_c_val)?;

        let proof1 = step1.data.prove(pw1)?;
        step1.data.verify(proof1)
    }

    #[test]
    #[ignore]
    fn test_recursive_proof() -> Result<()> {
        // Build step1 circuit and generate witness.
        let step1 = build_step1_circuit();

        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk = sk_c.to_public().0;

        let mut pw1 = PartialWitness::<F>::new();
        pw1.set_biguint_target(&step1.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.msg, msg)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.s, sig.s)?;
        pw1.set_biguint_target(&step1.targets.pk_cred.x.value, &pk.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_cred.y.value, &pk.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.sk_c, sk_c_val)?;

        let proof1 = step1.data.prove(pw1)?;
        step1.data.verify(proof1.clone())?;

        // Build step2 circuit and prove recursively.
        let step2 = build_step2_circuit(&step1.data.common);

        let sk0_val = Secp256K1Scalar::rand();
        let sk0 = ECDSASecretKey::<Secp256K1>(sk0_val);
        let pk0 = sk0.to_public().0;

        let mut pw2 = PartialWitness::<F>::new();
        pw2.set_biguint_target(&step2.targets.pk0.x.value, &pk0.x.to_canonical_biguint())?;
        pw2.set_biguint_target(&step2.targets.pk0.y.value, &pk0.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw2, &step2.targets.sk0, sk0_val)?;
        pw2.set_proof_with_pis_target(&step2.targets.proof, &proof1)?;
        pw2.set_verifier_data_target(&step2.targets.vd, &step1.data.verifier_only)?;

        let proof2 = step2.data.prove(pw2)?;
        step2.data.verify(proof2)
    }
}

/// Build the first circuit proving correctness of a P256 signature and key derivation.
fn build_step1_circuit() -> Step1Circuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: issuer public key
    let pk_i = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_i.x.value.limbs.iter().chain(pk_i.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private inputs
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    let pk_cred = builder.add_virtual_affine_point_target::<P256>();
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // Derive public key from secret key and compare with provided one.
    let pk_c =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);
    builder.connect_affine_point(&pk_c, &pk_cred);

    // Verify issuer signature for the given message.
    let pk_target = ECDSAPublicKeyTarget(pk_i.clone());
    verify_p256_message_circuit(&mut builder, msg.clone(), signature.clone(), pk_target);

    let data = builder.build::<Cfg>();
    let targets = Step1Targets {
        pk_i,
        msg,
        sig: signature,
        pk_cred,
        sk_c,
    };
    Step1Circuit { data, targets }
}

/// Build the second circuit proving secp256k1 key derivation and recursively verifying the first proof.
fn build_step2_circuit(inner_common: &CommonCircuitData<F, D>) -> Step2Circuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: secp256k1 public key
    let pk0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    for limb in pk0.x.value.limbs.iter().chain(pk0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private input: secp256k1 secret key
    let sk0 = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();

    // Derive public key and compare
    let pk0_calc = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        &mut builder,
        Secp256K1::GENERATOR_AFFINE,
        &sk0,
    );
    builder.connect_affine_point(&pk0_calc, &pk0);

    // Add targets for the proof of the first step and verify it recursively
    let proof = builder.add_virtual_proof_with_pis(inner_common);
    let vd = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_common);

    let data = builder.build::<Cfg>();
    let targets = Step2Targets {
        pk0,
        sk0,
        proof,
        vd,
    };
    Step2Circuit { data, targets }
}

fn main() {
    // Build circuits so that they compile; actual proving is out of scope here.
    let step1 = build_step1_circuit();
    let _step2 = build_step2_circuit(&step1.data.common);

    // Prevent unused warnings when running `cargo check`.
    let _ = (step1.data.prover_only, step1.data.verifier_only);
}
