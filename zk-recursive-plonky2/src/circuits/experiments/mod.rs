//! Experimental circuits for debugging recursive proof verification.
//! 
//! This module contains isolated implementations of the individual constraints
//! from the main inner circuit, allowing for targeted debugging of recursive
//! verification issues.

pub mod inner_key_der;
pub mod inner_sig_verify;
pub mod outer_key_der;
pub mod outer_sig_verify;

pub use inner_key_der::{build_inner_key_der_circuit, InnerKeyDerCircuit};
pub use inner_sig_verify::{build_inner_sig_verify_circuit, InnerSigVerifyCircuit};
pub use outer_key_der::{build_outer_key_der_circuit, OuterKeyDerCircuit};
pub use outer_sig_verify::{build_outer_sig_verify_circuit, OuterSigVerifyCircuit};