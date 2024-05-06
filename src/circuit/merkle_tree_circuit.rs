use halo2_proofs::{circuit::*, plonk::*};
use halo2curves::group::ff::PrimeField;

use crate::chip::merkle_tree_chip::{MerkleTreeChip, MerkleTreeConfig};

#[derive(Default, Debug, Clone)]
pub struct MerkleTreeCircuit<F: PrimeField> {
    pub leaf: Value<F>,
    pub path_elements: Vec<Value<F>>,
    pub path_indices: Vec<Value<F>>,
}
impl<F: PrimeField> MerkleTreeCircuit<F> {
    pub fn new(leaf: Value<F>, path_elements: Vec<Value<F>>, path_indices: Vec<Value<F>>) -> Self {
        Self {
            leaf,
            path_elements,
            path_indices,
        }
    }

    pub fn calculate_merkle_root_from_leaf(
        &self,
        leaf: &AssignedCell<F, F>,
        mut layouter: impl Layouter<F>,
        chip: &MerkleTreeChip<F>,
    ) -> AssignedCell<F, F> {
        let leaf_cell = chip
            .assing_leaf(layouter.namespace(|| "assign leaf"), self.leaf)
            .unwrap();

        let _ = layouter.assign_region(
            || "constrain leaf value",
            |mut region| region.constrain_equal(leaf.cell(), leaf_cell.cell()),
        );

        chip.expose_public(layouter.namespace(|| "public leaf"), &leaf_cell, 0)
            .unwrap();

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

impl<F: PrimeField> Circuit<F> for MerkleTreeCircuit<F> {
    type Config = MerkleTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // config for the merkle tree chip
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();

        MerkleTreeChip::configure(meta, [col_a, col_b, col_c], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = MerkleTreeChip::construct(config);
        let leaf_cell = chip.assing_leaf(layouter.namespace(|| "assign leaf"), self.leaf)?;
        chip.expose_public(layouter.namespace(|| "public leaf"), &leaf_cell, 0)?;

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
        chip.expose_public(layouter.namespace(|| "public root"), &digest, 1)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MerkleTreeCircuit;
    use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, P128Pow5T3};
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::pasta::Fp};

    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const L: usize = 2;

    fn compute_merkle_root(leaf: &u64, elements: &Vec<u64>, indices: &Vec<u64>) -> Fp {
        let k = elements.len();
        let mut digest = Fp::from(leaf.clone());
        let mut message: [Fp; 2];
        for i in 0..k {
            if indices[i] == 0 {
                message = [digest, Fp::from(elements[i])];
            } else {
                message = [Fp::from(elements[i]), digest];
            }

            digest = poseidon::Hash::<_, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init()
                .hash(message);
        }
        return digest;
    }

    #[test]
    fn test_merkle_tree_3() {
        let leaf = 99u64;
        let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
        let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];

        let root = compute_merkle_root(&leaf, &elements, &indices);

        let leaf_fp = Value::known(Fp::from(leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeCircuit {
            leaf: leaf_fp,
            path_elements: elements_fp,
            path_indices: indices_fp,
        };

        let correct_public_input = vec![Fp::from(leaf), root];
        let valid_prover = MockProver::run(10, &circuit, vec![correct_public_input]).unwrap();
        valid_prover.assert_satisfied();

        let wrong_public_input = vec![Fp::from(leaf), Fp::from(0)];
        let invalid_prover = MockProver::run(10, &circuit, vec![wrong_public_input]).unwrap();
        assert!(invalid_prover.verify().is_err());
    }
}

#[cfg(feature = "dev-graph")]
#[test]
fn print_merkle_tree_3() {
    use halo2_proofs::halo2curves::pasta::Fp;
    use plotters::prelude::*;

    let root =
        BitMapBackend::new("prints/merkle-tree-3-layout.png", (1024, 3096)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Merkle Tree 3 Layout", ("sans-serif", 60))
        .unwrap();

    let leaf = 99u64;
    let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
    let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];
    let digest: u64 = leaf + elements.iter().sum::<u64>();

    let leaf_fp = Value::known(Fp::from(leaf));
    let elements_fp: Vec<Value<Fp>> = elements
        .iter()
        .map(|x| Value::known(Fp::from(x.to_owned())))
        .collect();
    let indices_fp: Vec<Value<Fp>> = indices
        .iter()
        .map(|x| Value::known(Fp::from(x.to_owned())))
        .collect();

    let circuit = MerkleTreeCircuit {
        leaf: leaf_fp,
        path_elements: elements_fp,
        path_indices: indices_fp,
    };

    halo2_proofs::dev::CircuitLayout::default()
        .render(8, &circuit, &root)
        .unwrap();
}
