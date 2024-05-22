use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fr,
    plonk::Error,
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

pub fn get_low_leaf_idx(leaves: &Vec<IndexedMerkleTreeLeaf>, new_val: Fr) -> usize {
    let mut low_leaf_idx = 0;
    for (i, node) in leaves.iter().enumerate() {
        if node.next_val == Fr::zero() && i == 0 {
            low_leaf_idx = i;
            break;
        }
        if node.val < new_val && (node.next_val > new_val || node.next_val == Fr::zero()) {
            low_leaf_idx = i;
            break;
        }
    }
    low_leaf_idx
}
pub fn update_sparse_idx_leaf(
    leaves: &mut Vec<IndexedMerkleTreeLeaf>,
    new_val: Fr,
    new_val_idx: u64,
) {
    let mut low_leaf_idx = 0;
    for (i, node) in leaves.iter().enumerate() {
        if node.next_val == Fr::zero() && i == 0 {
            leaves[i + 1].val = new_val;
            leaves[i].next_val = new_val;
            leaves[i].next_idx = Fr::from((i as u64) + 1);
            low_leaf_idx = i;
            break;
        }
        if node.val < new_val && (node.next_val > new_val || node.next_val == Fr::zero()) {
            leaves[new_val_idx as usize].val = new_val;
            leaves[new_val_idx as usize].next_val = leaves[i].next_val;
            leaves[new_val_idx as usize].next_idx = leaves[i].next_idx;
            leaves[i].next_val = new_val;
            leaves[i].next_idx = Fr::from(new_val_idx);
            break;
        }
    }
}

#[derive(Debug, Default)]
pub struct NativeIndexedMerkleTree {
    pub nodes: Vec<Vec<Fr>>,
    pub root: Fr,
}

impl NativeIndexedMerkleTree {
    pub fn new_default_leaf(depth: usize) -> Self {
        let mut nodes = Vec::<Vec<Fr>>::new();
        for _ in 0..depth {
            let mut level_nodes = Vec::<Fr>::new();
            level_nodes.push(Fr::zero());
            nodes.push(level_nodes);
        }
        nodes.push(vec![Fr::zero()]);
        NativeIndexedMerkleTree {
            nodes,
            root: Fr::zero(),
        }
    }

    pub fn get_leaf_at_index(&self, index: usize) -> Fr {
        self.nodes[0][index]
    }

    pub fn insert_leaf(&mut self, leaf: Fr, index: usize) -> (Vec<Fr>, Vec<Fr>) {
        let mut current_index = index;
        if self.nodes[0].len() >= index {
            self.nodes[0].push(Fr::zero());
        }
        self.nodes[0][index] = leaf;
        let mut cur_leaf = leaf;

        let mut proof = Vec::<Fr>::new();
        let mut proof_helper = Vec::<Fr>::new();

        for i in 0..self.nodes.len() - 1 {
            let level = &self.nodes[i];

            let is_left_node = current_index % 2 == 0;
            let sibling_index = if is_left_node {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                Fr::zero()
            };
            proof.push(sibling);

            let parent_leaf_idx = current_index.clone() / 2;

            if self.nodes[i + 1].len() <= parent_leaf_idx {
                self.nodes[i + 1].push(Fr::zero());
            }
            self.nodes[i + 1][parent_leaf_idx] = if is_left_node {
                proof_helper.push(Fr::from(1));
                poseidon_hash([cur_leaf, sibling])
            } else {
                proof_helper.push(Fr::from(0));
                poseidon_hash([sibling, cur_leaf])
            };
            current_index /= 2;

            cur_leaf = self.nodes[i + 1][parent_leaf_idx];
        }

        self.root = self.nodes.last().unwrap()[0];
        (proof, proof_helper)
    }

    pub fn get_proof(&self, index: usize) -> (Vec<Fr>, Vec<Fr>) {
        let mut proof = Vec::new();
        let mut proof_helper = Vec::new();
        let mut current_index = index;

        for i in 0..self.nodes.len() - 1 {
            let level = &self.nodes[i];
            let is_left_node = current_index % 2 == 0;
            let sibling_index = if is_left_node {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < level.len() {
                level[sibling_index]
            } else {
                Fr::zero()
            };
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

    pub fn get_root(&self) -> Fr {
        self.root
    }

    pub fn verify_proof(&mut self, index: usize, root: &Fr, proof: &[Fr]) -> bool {
        let mut computed_hash = self.nodes[0][index];
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

    pub fn print_tree(&mut self) {
        for level in self.nodes.iter() {
            for node in level {
                println!("{:?}  ---   ", node)
            }
            println!();
        }

        println!("depth --- {:?}", self.nodes.len());
    }
}

pub fn hash_indexd_leaf(leaf: &IndexedMerkleTreeLeaf) -> Fr {
    poseidon_hash([leaf.val, leaf.next_val, leaf.next_idx, Fr::one()])
}
