use halo2_proofs::{ circuit::{ SimpleFloorPlanner, Value }, plonk::{ Circuit, Error } };
use poseidon_circuit::Bn256Fr as Fr;

use crate::{
    chip::{
        insert_leaf_chip::{ InsertLeafChip, InsertLeafConfig },
        merkle_tree_chip::MerkleTreeChip,
    },
    indexed_merkle_tree::IndexedMerkleTreeLeaf,
};

use super::merkle_tree_circuit::MerkleTreeCircuit;

//TODO: name variable properly
//TODO: Calculate the root of the assigned idx leafs

#[derive(Default, Debug, Clone)]
pub struct InsertLeafCircuit {
    pub idx_low_leaf: IndexedMerkleTreeLeaf,
    pub low_leaf: MerkleTreeCircuit,
    pub new_leaf: MerkleTreeCircuit,
    pub new_leaf_val: Value<Fr>,
    pub new_leaf_idx: Value<Fr>,
}
impl Circuit<Fr> for InsertLeafCircuit {
    type Config = InsertLeafConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<Fr>) -> Self::Config {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instances = [meta.instance_column(), meta.instance_column()];
        InsertLeafChip::configure(meta, advices, instances)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>
    ) -> Result<(), Error> {
        let merkle_tree_chip = MerkleTreeChip::construct(config.merkle_tree_config.clone());
        let chip = InsertLeafChip::construct(config);
        let low_leaf = chip.assign_low_leaf(
            layouter.namespace(|| "assign low leaf"),
            self.idx_low_leaf
        )?;

        //low_leaf should be replaced by hash of the low_leaf
        let old_root = self.low_leaf.calculate_merkle_root_from_leaf(
            &low_leaf[0],
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip
        );

        chip.constrian_old_root(
            layouter.namespace(|| "constrain calculate old root"),
            &old_root
        )?;

        let new_leaf = chip.assign_new_leaf(
            layouter.namespace(|| "assign new leaf"),
            self.new_leaf_val,
            &low_leaf[1],
            &low_leaf[2]
        )?;

        let new_low_leaf = chip.assign_new_low_leaf(
            layouter.namespace(|| "assign new_low_leaf"),
            self.new_leaf_idx,
            &new_leaf[0],
            &low_leaf[0]
        )?;

        //Replace the low_leaf[0] with the hash of the new_low_leaf
        let new_low_leaf_val = new_low_leaf[0].value().map(|val| *val);
        let new_low_leaf_merkle = MerkleTreeCircuit::new(
            new_low_leaf_val,
            self.low_leaf.path_elements.clone(),
            self.low_leaf.path_indices.clone()
        );

        let intermediate_new_low_leaf_root = new_low_leaf_merkle.calculate_merkle_root_from_leaf(
            &low_leaf[0],
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip
        );

        let default_idx_leaf = Value::known(Fr::zero());

        //need to add more constrin to it
        let prev_new_leaf_idx_val_merkle = MerkleTreeCircuit::new(
            default_idx_leaf,
            self.new_leaf.path_elements.clone(),
            self.new_leaf.path_indices.clone()
        );

        //Take the default leaf value from the instance

        let intermediate_new_leaf_root =
            prev_new_leaf_idx_val_merkle.calculate_merkle_root_from_leaf(
                &new_leaf[0],
                layouter.namespace(|| "calculate the merkle root"),
                &merkle_tree_chip
            );

        layouter.assign_region(
            || "constrain the intermediate roots",
            |mut region| {
                region.constrain_equal(
                    intermediate_new_low_leaf_root.cell(),
                    intermediate_new_leaf_root.cell()
                )
            }
        )?;

        //calculate the idx new leaf hash and replace it with new_leaf[0]

        let calculated_new_root = self.new_leaf.calculate_merkle_root_from_leaf(
            &new_leaf[0],
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip
        );

        chip.constrian_new_root(
            layouter.namespace(|| "constrian new root"),
            &calculated_new_root
        )?;

        Ok(())
    }
}
#[cfg(test)]
mod test {
    use poseidon_circuit::Bn256Fr as Fr;

    use crate::{ indexed_merkle_tree::IndexedMerkleTreeLeaf, utils::{poseidon_hash, NativeIndexedMerkleTree} };

    fn update_idx_leaf(
        leaves: Vec<IndexedMerkleTreeLeaf>,
        new_val: Fr,
        new_val_idx: u64
    ) -> (Vec<IndexedMerkleTreeLeaf>, usize) {
        let mut nullifier_tree_preimages = leaves.clone();
        let mut low_leaf_idx = 0;
        for (i, node) in leaves.iter().enumerate() {
            if node.next_val == Fr::zero() && i == 0 {
                nullifier_tree_preimages[i + 1].val = new_val;
                nullifier_tree_preimages[i].next_val = new_val;
                nullifier_tree_preimages[i].next_idx = Fr::from((i as u64) + 1);
                low_leaf_idx = i;
                break;
            }
            if node.val < new_val && (node.next_val > new_val || node.next_val == Fr::zero()) {
                nullifier_tree_preimages[new_val_idx as usize].val = new_val;
                nullifier_tree_preimages[new_val_idx as usize].next_val = nullifier_tree_preimages[
                    i
                ].next_val;
                nullifier_tree_preimages[new_val_idx as usize].next_idx = nullifier_tree_preimages[
                    i
                ].next_idx;
                nullifier_tree_preimages[i].next_val = new_val;
                nullifier_tree_preimages[i].next_idx = Fr::from(new_val_idx);
                low_leaf_idx = i;
                break;
            }
        }
        (nullifier_tree_preimages, low_leaf_idx)
    }
      fn hash_nullifier_pre_images(nullifier_tree_preimages: Vec<IndexedMerkleTreeLeaf>) -> Vec<Fr> {
        nullifier_tree_preimages
            .iter()
            .map(|leaf| {
                poseidon_hash([leaf.val, leaf.next_val, leaf.next_idx])
            })
            .collect::<Vec<_>>()
    }
    fn print_nullifier_leafs(node: Vec<IndexedMerkleTreeLeaf>) {
        for (i, x) in node.iter().enumerate() {
            println!("val[{}]={:?}", i, x.val);
            println!("nxt_idx[{}]={:?}", i, x.next_idx);
            println!("next_val[{}]={:?}\n", i, x.next_val);
        }
    }

    #[test]
    fn test_insert_leafs_circuit() {
        let new_vals = [
            Fr::from(30),
            Fr::from(10),
            Fr::from(20),
            Fr::from(5),
            Fr::from(50),
            Fr::from(35),
        ];

        let mut nullifier_tree_preimages = (0..8)
            .map(|_| IndexedMerkleTreeLeaf {
                val: Fr::from(0u64),
                next_val: Fr::from(0u64),
                next_idx: Fr::from(0u64),
            })
            .collect::<Vec<_>>();

        let mut old_nullifier_tree_preimages = nullifier_tree_preimages.clone();

        let mut nullifier_tree_leaves = hash_nullifier_pre_images(nullifier_tree_preimages.clone());

        let mut low_leaf_idx = 0;

        let mut tree =
            NativeIndexedMerkleTree::new( nullifier_tree_leaves.clone())
                .unwrap();

        for (round, new_val) in new_vals.iter().enumerate() {
            println!("---------------round[{}]----------------", round);
            let old_root = tree.get_root();

            (nullifier_tree_preimages, low_leaf_idx) =
                update_idx_leaf(nullifier_tree_preimages.clone(), *new_val, round as u64 + 1);

            println!("new_val added = {:?}", new_val);
            print_nullifier_leafs(nullifier_tree_preimages.clone());

            let low_leaf = old_nullifier_tree_preimages[low_leaf_idx].clone();

            let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(low_leaf_idx);

            nullifier_tree_leaves = hash_nullifier_pre_images(nullifier_tree_preimages.clone());

            tree = NativeIndexedMerkleTree::new(
                nullifier_tree_leaves.clone(),
            )
            .unwrap();

            let new_leaf = nullifier_tree_preimages[round + 1].clone();
            let new_leaf_index = Fr::from(round as u64 + 1);
            let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(round + 1);
            let new_root = tree.get_root();
            let is_new_leaf_largest = if nullifier_tree_preimages[round + 1].next_val == Fr::zero()
            {
                Fr::from(true)
            } else {
                Fr::from(false)
            };


            //verifying the InsertLeaf circuit

            old_nullifier_tree_preimages = nullifier_tree_preimages.clone();
            }
    }
}
