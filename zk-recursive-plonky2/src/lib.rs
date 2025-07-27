pub mod circuits;
pub mod types;

pub use circuits::{
    inner::{build_inner_circuit, InnerCircuit, InnerCircuitTargets},
    outer::{build_outer_circuit, OuterCircuit, OuterCircuitTargets},
    outer_p256::{build_outer_p256_circuit, OuterP256Circuit, OuterP256CircuitTargets},
};
pub use types::input::{InnerProofInput, OuterProofInput};