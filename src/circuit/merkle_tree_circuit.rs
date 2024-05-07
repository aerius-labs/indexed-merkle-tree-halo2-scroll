use halo2_proofs::{circuit::*, plonk::*};

use crate::chip::merkle_tree_chip::{MerkleTreeChip, MerkleTreeConfig};
use poseidon_circuit::Bn256Fr as Fr;
#[derive(Default, Debug, Clone)]
pub struct MerkleTreeCircuit {
    pub leaf: Value<Fr>,
    pub path_elements: Vec<Value<Fr>>,
    pub path_indices: Vec<Value<Fr>>,
}
impl MerkleTreeCircuit {
    pub fn new(
        leaf: Value<Fr>,
        path_elements: Vec<Value<Fr>>,
        path_indices: Vec<Value<Fr>>,
    ) -> Self {
        Self {
            leaf,
            path_elements,
            path_indices,
        }
    }

    pub fn calculate_merkle_root_from_leaf(
        &self,
        leaf: &AssignedCell<Fr, Fr>,
        mut layouter: impl Layouter<Fr>,
        chip: &MerkleTreeChip,
    ) -> AssignedCell<Fr, Fr> {
        let leaf_cell = chip
            .assing_leaf(layouter.namespace(|| "assign leaf"), self.leaf)
            .unwrap();

        let _ = layouter.assign_region(
            || "constrain leaf value",
            |mut region| region.constrain_equal(leaf.cell(), leaf_cell.cell()),
        );

        let mut digest = chip
            .compute_merkle_root_from_path(
                layouter.namespace(|| "merkle_prove"),
                &leaf_cell,
                self.path_elements[0],
                self.path_indices[0],
            )
            .unwrap();

        for i in 1..self.path_elements.len() {
            digest = chip
                .compute_merkle_root_from_path(
                    layouter.namespace(|| "next level"),
                    &digest,
                    self.path_elements[i],
                    self.path_indices[i],
                )
                .unwrap();
        }
        digest
    }
}

impl Circuit<Fr> for MerkleTreeCircuit {
    type Config = MerkleTreeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // config for the merkle tree chip
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();

        MerkleTreeChip::configure(meta, [col_a, col_b, col_c, col_d])
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = MerkleTreeChip::construct(config);
        let leaf_cell = chip.assing_leaf(layouter.namespace(|| "assign leaf"), self.leaf)?;

        // apply it for level 0 of the merkle tree
        // node cell passed as input is the leaf cell
        let mut digest = chip.compute_merkle_root_from_path(
            layouter.namespace(|| "merkle_prove"),
            &leaf_cell,
            self.path_elements[0],
            self.path_indices[0],
        )?;

        // apply it for the remaining levels of the merkle tree
        // node cell passed as input is the digest cell
        for i in 1..self.path_elements.len() {
            digest = chip.compute_merkle_root_from_path(
                layouter.namespace(|| "next level"),
                &digest,
                self.path_elements[i],
                self.path_indices[i],
            )?;
        }
        let _ = self.calculate_merkle_root_from_leaf(
            &leaf_cell,
            layouter.namespace(|| "calculate merkle root from leaf path"),
            &chip,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::poseidon_hash;

    use super::MerkleTreeCircuit;
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use poseidon_circuit::Bn256Fr as Fr;

    fn compute_merkle_root(leaf: &u64, elements: &Vec<u64>, indices: &Vec<u64>) -> Fr {
        let k = elements.len();
        let mut digest = Fr::from(leaf.clone());
        let mut message: [Fr; 2];
        for i in 0..k {
            if indices[i] == 0 {
                message = [digest, Fr::from(elements[i])];
            } else {
                message = [Fr::from(elements[i]), digest];
            }
            digest = poseidon_hash(message);
        }
        return digest;
    }

    #[test]
    fn test_merkle_tree() {
        let leaf = 99u64;
        let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
        let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];

        let _ = compute_merkle_root(&leaf, &elements, &indices);

        let leaf_fp = Value::known(Fr::from(leaf));
        let elements_fp: Vec<Value<Fr>> = elements
            .iter()
            .map(|x| Value::known(Fr::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fr>> = indices
            .iter()
            .map(|x| Value::known(Fr::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeCircuit {
            leaf: leaf_fp,
            path_elements: elements_fp,
            path_indices: indices_fp,
        };

        let valid_prover = MockProver::run(10, &circuit, vec![]).unwrap();
        valid_prover.assert_satisfied();
    }
}
