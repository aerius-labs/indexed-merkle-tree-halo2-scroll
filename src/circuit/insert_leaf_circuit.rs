use halo2_proofs::{ circuit::{ SimpleFloorPlanner, Value }, plonk::{ Circuit, Error } };
use poseidon_circuit::Bn256Fr as Fr;

use crate::{
    chip::{
        insert_leaf_chip::{ InsertLeafChip, InsertLeafConfig },
        merkle_tree_chip::MerkleTreeChip,
    },
    utils::{ poseidon_hash_gadget, IndexedMerkleTreeLeaf },
};

use super::merkle_tree_circuit::MerkleTreeCircuit;

//TODO: name variable properly
//TODO: Constrain path elements and idx 
//TODO: Remove the clone

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
        ];
        let instances = meta.instance_column();
        InsertLeafChip::configure(meta, advices, instances)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2_proofs::circuit::Layouter<Fr>
    ) -> Result<(), Error> {
        let merkle_tree_chip = MerkleTreeChip::construct(config.merkle_tree_config.clone());
        let chip = InsertLeafChip::construct(config.clone());

        let low_leaf_preimage = chip.assign_low_leaf(
            layouter.namespace(|| "assign low leaf"),
            self.idx_low_leaf
        )?;

        println!(" low leaf assigned {:#?}", low_leaf_preimage);

        let low_leaf_hash = poseidon_hash_gadget(
            config.clone().merkle_tree_config.poseidon_config,
            layouter.namespace(|| "hash low leaf"),
            [
                low_leaf_preimage[0].clone(),
                low_leaf_preimage[1].clone(),
                low_leaf_preimage[2].clone(),
            ]
        )?;

        //low_leaf should be replaced by hash of the low_leaf
        let old_root = self.low_leaf.calculate_merkle_root_from_leaf(
            &low_leaf_hash,
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip
        );

        chip.constrian_old_root(
            layouter.namespace(|| "constrain calculate old root"),
            &old_root
        )?;



        let new_leaf_preimage = chip.assign_new_leaf(
            layouter.namespace(|| "assign new leaf"),
            self.new_leaf_val,
     //       &low_leaf_preimage[0],
            &low_leaf_preimage[1],
            &low_leaf_preimage[2]
        )?;
           println!(" new leaf assigned {:#?}", new_leaf_preimage);
      

        let new_low_leaf = chip.assign_new_low_leaf(
            layouter.namespace(|| "assign new_low_leaf"),
            self.new_leaf_idx,
            &new_leaf_preimage[0],
            &low_leaf_preimage[0]
        )?;


        let new_low_leaf_hash = poseidon_hash_gadget(
            config.clone().merkle_tree_config.poseidon_config,
            layouter.namespace(|| "hash new low leaf"),
            [new_low_leaf[0].clone(), new_low_leaf[1].clone(), new_low_leaf[2].clone()]
        )?;
        let mut exp =Vec::<Fr>::new();
        let new_low_leaf_val = new_low_leaf_hash.value().map(|val| {exp.push(val.clone());  *val});
        let new_low_leaf_merkle = MerkleTreeCircuit::new(
            new_low_leaf_val,
            self.low_leaf.path_elements.clone(),
            self.low_leaf.path_indices.clone()
        );

        let intermediate_new_low_leaf_root = new_low_leaf_merkle.calculate_merkle_root_from_leaf(
            &new_low_leaf_hash,
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip
        );

        //need to add more constrin to it
        let default_leaf_assign = chip.assign_default_leaf(
            layouter.namespace(|| "assign default leaf")
        )?;
        let default_leaf_val = default_leaf_assign.value().map(|val| *val);

        let prev_new_leaf_idx_val_merkle = MerkleTreeCircuit::new(
            default_leaf_val,
            self.new_leaf.path_elements.clone(),
            self.new_leaf.path_indices.clone()
        );

        let intermediate_new_leaf_root =
            prev_new_leaf_idx_val_merkle.calculate_merkle_root_from_leaf(
                &default_leaf_assign,
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

        chip.assign_values_to_compare(layouter.namespace(||"low val  < new val"), &new_low_leaf[0], &new_leaf_preimage[0]);

        let new_leaf_hash = poseidon_hash_gadget(
            config.clone().merkle_tree_config.poseidon_config,
            layouter.namespace(|| "calculate the new leaf hash"),
            [
                new_leaf_preimage[0].clone(),
                new_leaf_preimage[1].clone(),
                new_leaf_preimage[2].clone(),
            ]
        )?;
        let calculated_new_root = self.new_leaf.calculate_merkle_root_from_leaf(
            &new_leaf_hash,
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
    use halo2_proofs::{ circuit::Value, dev::MockProver };
    use poseidon_circuit::Bn256Fr as Fr;

    use crate::{
        circuit::{ insert_leaf_circuit::InsertLeafCircuit, merkle_tree_circuit::MerkleTreeCircuit },
        utils::{ poseidon_hash, IndexedMerkleTreeLeaf, NativeIndexedMerkleTree },
    };

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
            .map(|leaf| poseidon_hash([leaf.val, leaf.next_val, leaf.next_idx]))
            .collect::<Vec<_>>()
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

        let new_vals = [Fr::from(10)];

        let mut nullifier_tree_preimages = (0..8)
            .map(|_| IndexedMerkleTreeLeaf {
                val: Fr::from(0u64),
                next_val: Fr::from(0u64),
                next_idx: Fr::from(0u64),
            })
            .collect::<Vec<_>>();

        let mut old_nullifier_tree_preimages = nullifier_tree_preimages.clone();

        let mut nullifier_tree_leaves = hash_nullifier_pre_images(nullifier_tree_preimages.clone());

        let default_leaf = nullifier_tree_leaves[0].clone();

        let mut low_leaf_idx = 0;

        let mut tree = NativeIndexedMerkleTree::new(nullifier_tree_leaves.clone()).unwrap();

        for (round, new_val) in new_vals.iter().enumerate() {
            let old_root = tree.get_root();

            (nullifier_tree_preimages, low_leaf_idx) = update_idx_leaf(
                nullifier_tree_preimages.clone(),
                *new_val,
                (round as u64) + 1
            );

            let low_leaf = old_nullifier_tree_preimages[low_leaf_idx].clone();

            let old_nullifier_tree_preimages_hash = hash_nullifier_pre_images(
                old_nullifier_tree_preimages.clone()
            );

            let (low_leaf_proof, low_leaf_proof_helper) = tree.get_proof(low_leaf_idx);

            nullifier_tree_leaves = hash_nullifier_pre_images(nullifier_tree_preimages.clone());

            tree = NativeIndexedMerkleTree::new(nullifier_tree_leaves.clone()).unwrap();

            let new_leaf = nullifier_tree_preimages[round + 1].clone();
            let new_leaf_index = Fr::from((round as u64) + 1);
            let (new_leaf_proof, new_leaf_proof_helper) = tree.get_proof(round + 1);
            let new_root = tree.get_root();
            tree.verify_proof(
                &nullifier_tree_leaves[round + 1].clone(),
                round + 1,
                &new_root,
                &new_leaf_proof
            );
            let is_new_leaf_largest = if nullifier_tree_preimages[round + 1].next_val == Fr::zero() {
                Fr::from(true)
            } else {
                Fr::from(false)
            };

            let leaf = Value::known(old_nullifier_tree_preimages_hash[low_leaf_idx].clone());
            let path_elements = low_leaf_proof
                .iter()
                .map(|proof| Value::known(*proof))
                .collect::<Vec<_>>();
            let path_indices = low_leaf_proof_helper
                .iter()
                .map(|proof_helper| {
                    if *proof_helper == Fr::zero() {
                        Value::known(Fr::one())
                    } else {
                        Value::known(Fr::zero())
                    }
                })
                .collect::<Vec<_>>();

            let merkle_low_leaf = MerkleTreeCircuit::new(leaf, path_elements, path_indices);

            let new_leaf_merkle = Value::known(nullifier_tree_leaves[round + 1].clone());
            let new_leaf_path_elements = new_leaf_proof
                .iter()
                .map(|proof| Value::known(*proof))
                .collect::<Vec<_>>();
            let new_leaf_path_indices = new_leaf_proof_helper
                .iter()
                .map(|proof_helper| {
                    if *proof_helper == Fr::zero() {
                        Value::known(Fr::one())
                    } else {
                        Value::known(Fr::zero())
                    }
                })
                .collect::<Vec<_>>();

            let merkle_new_leaf = MerkleTreeCircuit::new(
                new_leaf_merkle,
                new_leaf_path_elements,
                new_leaf_path_indices
            );

            let insert_leaf_circuit = InsertLeafCircuit {
                idx_low_leaf: low_leaf.clone(),
                low_leaf: merkle_low_leaf,
                new_leaf: merkle_new_leaf,
                new_leaf_val: Value::known(*new_val),
                new_leaf_idx: Value::known(new_leaf_index),
            };

            let instances = [is_new_leaf_largest, old_root, default_leaf, new_root].to_vec();

            let prover = MockProver::<Fr>::run(10, &insert_leaf_circuit, vec![instances]).unwrap();

            prover.verify().unwrap();

            println!("COMPLETED ROUND {}", round + 1);

            //verify the InsertLeaf circuit

            old_nullifier_tree_preimages = nullifier_tree_preimages.clone();
        }
    }
}
