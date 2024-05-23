#[allow(unused)]
use std::time::Instant;

use poseidon_circuit::{hash, Bn256Fr as Fr};

use crate::utils::poseidon_hash;



#[derive(Debug, Default)]
pub struct Hashes {
    list: Vec<Fr>,
}

impl Hashes {
    fn new(depth: usize) -> Self {
        let mut list = vec![Fr::zero(); 32];
        list[0] = Fr::zero();
        for i in 2..depth {
            list[i] = poseidon_hash([list[i-1], list[i-1]]);
        }
        Hashes { list }
    }

    fn get(&self, index: usize) -> Fr {
            self.list[index]
    }
}

#[derive(Debug, Default)]
pub struct NativeIndexedMerkleTree {
    pub nodes: Vec<Vec<Fr>>,
    pub root: Fr,
    pub list_of_hashes: Hashes
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

        let list_of_hashes = Hashes::new(depth);

        NativeIndexedMerkleTree {
            nodes,
            root: Fr::zero(),
            list_of_hashes,
        }
    }

    pub fn get_leaf_at_index(&self, index: usize) -> Fr {
        self.nodes[0][index]
    }

    pub fn insert_leaf(&mut self, leaf: Fr, index: usize) -> (Vec<Fr>, Vec<Fr>) {
        let mut current_index = index;
        if index >= self.nodes[0].len() {
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
                self.list_of_hashes.get(i)
            };
            proof.push(sibling);

            let parent_leaf_idx = current_index.clone() / 2;

            if parent_leaf_idx >= self.nodes[i + 1].len() {
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
                self.list_of_hashes.get(i)
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

#[test]
fn test_native_indexed_tree() {
    let start = Instant::now();
    let mut T = NativeIndexedMerkleTree::new_default_leaf(32);
    T.insert_leaf(Fr::from(3), 1);
    T.insert_leaf(Fr::from(20), 2);
    T.insert_leaf(Fr::from(10), 3);
    let (p, _) = T.insert_leaf(Fr::from(13), 4);

    let end = start.elapsed();
    println!("time taken to calculate ={:?}", end);

    let r = T.get_root();
    print!("check {}", T.verify_proof(4, &r, &p));
}
