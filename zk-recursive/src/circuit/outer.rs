use ark_bn254::Fr as F;
use ark_r1cs_std::{
    fields::fp::FpVar,
    alloc::AllocVar,
    prelude::*,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, 
    ConstraintSystemRef, 
    SynthesisError
};

#[derive(Clone)]
pub struct KeyBind {
    pub pk0: F,
    pub pk1: F,
    pub cc0: F,
    pub index: F,
}

impl ConstraintSynthesizer<F> for KeyBind {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let pk0_var = FpVar::<F>::new_witness(cs.clone(), || Ok(self.pk0))?;
        let pk1_var = FpVar::<F>::new_input(cs.clone(), || Ok(self.pk1))?;
        let cc0_var = FpVar::<F>::new_input(cs.clone(), || Ok(self.cc0))?;
        let index_var = FpVar::<F>::new_input(cs.clone(), || Ok(self.index))?;

        // Hier: Constraint `pk1 = KeyDer(pk0, cc0, index)`
        // (Noch ohne echte Hash + ECC – Dummy-Gleichheit als Platzhalter)
        let derived = pk0_var.clone() + index_var + cc0_var;

        derived.enforce_equal(&pk1_var)?;

        Ok(())
    }
}
