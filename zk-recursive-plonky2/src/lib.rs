pub mod circuits;
pub mod types;

pub use circuits::{inner::build_inner_circuit, outer::build_outer_circuit};
pub use circuits::{inner::InnerCircuit, inner::InnerCircuitTargets};
pub use circuits::{outer::OuterCircuit, outer::OuterCircuitTargets};
pub use types::input::{InnerProofInput, OuterProofInput};