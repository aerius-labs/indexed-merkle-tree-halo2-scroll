use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::Fr,
    halo2curves::group::ff::PrimeField,
    plonk::{Advice, Assigned, Column, Error},
};

use poseidon_circuit::{
    poseidon::{
        primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3},
        Hash,
    },
    Hashable,
};

pub use poseidon_circuit::poseidon::{Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig};

pub type P128Pow5T3Fr = P128Pow5T3<Fr>;

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const L: usize = 2;


pub fn poseidon_hash_gadget<const L: usize>(
    config: PoseidonConfig<Fr, 3, 2>,
    mut layouter: impl Layouter<Fr>,
    messages: [AssignedCell<Fr, Fr>; L],
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let chip = PoseidonChip::construct(config);
    let hasher = Hash::<_, _, P128Pow5T3<Fr>, ConstantLength<L>, 3, 2>::init(
        chip,
        layouter.namespace(|| "init poseidon hasher"),
    )?;

    hasher.hash(layouter.namespace(|| "hash"), messages)
}

pub fn poseidon_hash<F: Hashable, const L: usize>(message: [F; L]) -> F {
    PoseidonHash::<F, P128Pow5T3<F>, ConstantLength<L>, 3, 2>::init().hash(message)
}
#[derive(Debug, Clone, Default, Copy)]
pub struct IndexedMerkleTreeLeaf {
    pub val: Fr,
    pub next_val: Fr,
    pub next_idx: Fr,
}
impl IndexedMerkleTreeLeaf {
    pub fn new(val: Fr, next_val: Fr, next_idx: Fr) -> Self {
        Self {
            val,
            next_val,
            next_idx,
        }
    }
}

#[derive(Debug)]
pub struct NativeIndexedMerkleTree {
    tree: Vec<Vec<Fr>>,
    root: Fr,
}

impl NativeIndexedMerkleTree {
    pub fn new(leaves: Vec<Fr>) -> Result<NativeIndexedMerkleTree, &'static str> {
        if leaves.is_empty() {
            return Err("Cannot create Merkle Tree with no leaves");
        }
        if leaves.len() == 1 {
            return Ok(NativeIndexedMerkleTree {
                tree: vec![leaves.clone()],
                root: leaves[0],
            });
        }
        if leaves.len() % 2 == 1 {
            return Err("Leaves must be even");
        }

        let mut tree = vec![leaves.clone()];
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = current_level[i + 1];

                next_level.push(poseidon_hash([left, right]));
            }
            tree.push(next_level.clone());
            current_level = next_level.clone();
        }
        Ok(NativeIndexedMerkleTree {
            tree,
            root: current_level[0],
        })
    }

    pub fn get_root(&self) -> Fr {
        self.root
    }

    pub fn get_proof(&self, index: usize) -> (Vec<Fr>, Vec<Fr>) {
        let mut proof = Vec::new();
        let mut proof_helper = Vec::new();
        let mut current_index = index;

        for i in 0..self.tree.len() - 1 {
            let level = &self.tree[i];
            let is_left_node = current_index % 2 == 0;
            let sibling_index = if is_left_node {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling = level[sibling_index];

            proof.push(sibling);
            proof_helper.push(if is_left_node {
                Fr::from(1)
            } else {
                Fr::from(0)
            });

            current_index /= 2;
        }

        (proof, proof_helper)
    }

    pub fn verify_proof(&mut self, leaf: &Fr, index: usize, root: &Fr, proof: &[Fr]) -> bool {
        let mut computed_hash = *leaf;
        let mut current_index = index;

        for i in 0..proof.len() {
            let proof_element = &proof[i];
            let is_left_node = current_index % 2 == 0;

            computed_hash = if is_left_node {
                poseidon_hash([computed_hash, *proof_element])
            } else {
                poseidon_hash([*proof_element, computed_hash])
            };

            current_index /= 2;
        }

        computed_hash == *root
    }
}
