//! Witness generation for ZK proofs.

use alloy_primitives::{Address, B256, U256};
use pgp_merkle::HierarchicalProof;
use serde::{Deserialize, Serialize};

/// Input note for a transfer witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessInputNote {
    /// Asset (ERC20 address)
    pub asset: Address,
    /// Amount
    pub amount: U256,
    /// Blinding factor
    pub blinding: B256,
    /// Public key of the note owner
    pub public_key: B256,
    /// Merkle proof for this note
    pub proof: HierarchicalProof,
}

/// Output note for a transfer witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessOutputNote {
    /// Asset (ERC20 address)
    pub asset: Address,
    /// Amount
    pub amount: U256,
    /// Blinding factor (computed as Poseidon(random, hashLeavesIn) for transfers)
    pub blinding: B256,
    /// Random value used to derive the blinding (for non-withdrawals)
    /// The circuit enforces: blinding = Poseidon(random, hashLeavesIn)
    pub random: B256,
    /// Public key of the recipient (0 for withdrawal)
    pub public_key: B256,
}

/// Witness for the transfer circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferWitness {
    /// Spending key of the sender
    pub spending_key: B256,
    /// Input notes (2 max)
    pub inputs: Vec<WitnessInputNote>,
    /// Output notes (3 max)
    pub outputs: Vec<WitnessOutputNote>,
    /// Anchor (merkle root) being used
    pub anchor: B256,
}

impl TransferWitness {
    /// Create a new transfer witness.
    pub fn new(spending_key: B256, anchor: B256) -> Self {
        Self {
            spending_key,
            inputs: Vec::new(),
            outputs: Vec::new(),
            anchor,
        }
    }

    /// Add an input note.
    pub fn add_input(&mut self, note: WitnessInputNote) {
        self.inputs.push(note);
    }

    /// Add an output note.
    pub fn add_output(&mut self, note: WitnessOutputNote) {
        self.outputs.push(note);
    }

    /// Validate that the witness is well-formed.
    pub fn validate(&self) -> Result<(), String> {
        // Check input count
        if self.inputs.is_empty() {
            return Err("At least one input note required".to_string());
        }
        if self.inputs.len() > 2 {
            return Err("Maximum 2 input notes".to_string());
        }

        // Check output count
        if self.outputs.is_empty() {
            return Err("At least one output note required".to_string());
        }
        if self.outputs.len() > 3 {
            return Err("Maximum 3 output notes".to_string());
        }

        // Check that all inputs use the same asset
        let asset = self.inputs[0].asset;
        for input in &self.inputs {
            if input.asset != asset {
                return Err("All inputs must use the same asset".to_string());
            }
        }

        // Check that all outputs use the same asset
        for output in &self.outputs {
            if output.asset != asset {
                return Err("All outputs must use the same asset".to_string());
            }
        }

        // Check conservation: sum(inputs) = sum(outputs)
        let input_sum: U256 = self.inputs.iter().map(|n| n.amount).sum();
        let output_sum: U256 = self.outputs.iter().map(|n| n.amount).sum();

        if input_sum != output_sum {
            return Err(format!(
                "Value not conserved: inputs={input_sum}, outputs={output_sum}"
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp_merkle::TreePosition;

    fn make_test_proof() -> HierarchicalProof {
        HierarchicalProof::new(
            TreePosition::new(0, 0, 0),
            B256::ZERO,
            [B256::ZERO; 16],
            [B256::ZERO; 13],
            [B256::ZERO; 15],
        )
    }

    #[test]
    fn test_transfer_witness_validation() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        // No inputs - should fail
        witness.outputs.push(WitnessOutputNote {
            asset: Address::ZERO,
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::ZERO,
        });
        assert!(witness.validate().is_err());

        // Add input
        witness.inputs.push(WitnessInputNote {
            asset: Address::ZERO,
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        // Now should pass
        assert!(witness.validate().is_ok());
    }

    #[test]
    fn test_transfer_witness_value_conservation() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        witness.inputs.push(WitnessInputNote {
            asset: Address::ZERO,
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        witness.outputs.push(WitnessOutputNote {
            asset: Address::ZERO,
            amount: U256::from(50u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::ZERO,
        });

        // Value not conserved
        assert!(witness.validate().is_err());

        // Add change output
        witness.outputs.push(WitnessOutputNote {
            asset: Address::ZERO,
            amount: U256::from(50u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::repeat_byte(0x22),
        });

        // Now should pass
        assert!(witness.validate().is_ok());
    }

    #[test]
    fn test_transfer_witness_too_many_inputs() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        // Add 3 inputs (maximum is 2)
        for _ in 0..3 {
            witness.inputs.push(WitnessInputNote {
                asset: Address::ZERO,
                amount: U256::from(100u64),
                blinding: B256::ZERO,
                public_key: B256::ZERO,
                proof: make_test_proof(),
            });
        }

        witness.outputs.push(WitnessOutputNote {
            asset: Address::ZERO,
            amount: U256::from(300u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::ZERO,
        });

        let result = witness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Maximum 2 input"));
    }

    #[test]
    fn test_transfer_witness_too_many_outputs() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        witness.inputs.push(WitnessInputNote {
            asset: Address::ZERO,
            amount: U256::from(400u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        // Add 4 outputs (maximum is 3)
        for _ in 0..4 {
            witness.outputs.push(WitnessOutputNote {
                asset: Address::ZERO,
                amount: U256::from(100u64),
                blinding: B256::ZERO,
                random: B256::ZERO,
                public_key: B256::ZERO,
            });
        }

        let result = witness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Maximum 3 output"));
    }

    #[test]
    fn test_transfer_witness_no_outputs() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        witness.inputs.push(WitnessInputNote {
            asset: Address::ZERO,
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        // No outputs
        let result = witness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one output"));
    }

    #[test]
    fn test_transfer_witness_mixed_input_assets() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        // Input 1: asset A
        witness.inputs.push(WitnessInputNote {
            asset: Address::repeat_byte(0xAA),
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        // Input 2: asset B (different!)
        witness.inputs.push(WitnessInputNote {
            asset: Address::repeat_byte(0xBB),
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        witness.outputs.push(WitnessOutputNote {
            asset: Address::repeat_byte(0xAA),
            amount: U256::from(200u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::ZERO,
        });

        let result = witness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("same asset"));
    }

    #[test]
    fn test_transfer_witness_mixed_output_assets() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        witness.inputs.push(WitnessInputNote {
            asset: Address::repeat_byte(0xAA),
            amount: U256::from(200u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        // Output 1: asset A
        witness.outputs.push(WitnessOutputNote {
            asset: Address::repeat_byte(0xAA),
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::ZERO,
        });

        // Output 2: asset B (different!)
        witness.outputs.push(WitnessOutputNote {
            asset: Address::repeat_byte(0xBB),
            amount: U256::from(100u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::ZERO,
        });

        let result = witness.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("same asset"));
    }

    #[test]
    fn test_transfer_witness_valid_two_inputs_three_outputs() {
        let mut witness = TransferWitness::new(B256::repeat_byte(0x11), B256::ZERO);

        // Max valid: 2 inputs, 3 outputs
        witness.inputs.push(WitnessInputNote {
            asset: Address::ZERO,
            amount: U256::from(500u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });
        witness.inputs.push(WitnessInputNote {
            asset: Address::ZERO,
            amount: U256::from(500u64),
            blinding: B256::ZERO,
            public_key: B256::ZERO,
            proof: make_test_proof(),
        });

        witness.outputs.push(WitnessOutputNote {
            asset: Address::ZERO,
            amount: U256::from(400u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::repeat_byte(0x22),
        });
        witness.outputs.push(WitnessOutputNote {
            asset: Address::ZERO,
            amount: U256::from(400u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::repeat_byte(0x33),
        });
        witness.outputs.push(WitnessOutputNote {
            asset: Address::ZERO,
            amount: U256::from(200u64),
            blinding: B256::ZERO,
            random: B256::ZERO,
            public_key: B256::repeat_byte(0x44),
        });

        // Should pass with max inputs/outputs
        assert!(witness.validate().is_ok());
    }
}
