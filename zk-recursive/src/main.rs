use ark_bn254::Fr;
use ark_relations::r1cs::{
    ConstraintSystem,
    ConstraintSynthesizer
};
use zk_recursive::circuit::outer::KeyBind;

fn main() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let circuit = KeyBind {
        pk0: Fr::from(5),
        cc0: Fr::from(9),
        index: Fr::from(3),
        pk1: Fr::from(17), // 5 + 9 + 3
    };

    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(cs.is_satisfied().unwrap());
    println!("OK: Circuit satisfied.");
}
