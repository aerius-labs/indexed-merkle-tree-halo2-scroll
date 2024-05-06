use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Value},
    plonk::{Circuit, Error},
};
use halo2curves::group::ff::PrimeField;

use crate::{
    chip::{
        insert_leaf_chip::{InsertLeafChip, InsertLeafConfig},
        merkle_tree_chip::MerkleTreeChip,
    },
    indexed_merkle_tree::IndexedMerkleTreeLeaf,
};

use super::merkle_tree_circuit::MerkleTreeCircuit;

//TODO: name variable properly
//TODO: Calculate the root of the assigned idx leafs

#[derive(Default, Debug, Clone)]
pub struct InsertLeafCircuit<F: PrimeField> {
    pub idx_low_leaf: IndexedMerkleTreeLeaf<F>,
    pub low_leaf: MerkleTreeCircuit<F>,
    pub new_leaf: MerkleTreeCircuit<F>,
    pub new_leaf_val: Value<F>,
    pub new_leaf_idx: Value<F>,
}
impl<F: PrimeField> Circuit<F> for InsertLeafCircuit<F> {
    type Config = InsertLeafConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
        let advices = [
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
        mut layouter: impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), Error> {
        let merkle_tree_chip = MerkleTreeChip::construct(config.merkle_tree_config.clone());
        let chip = InsertLeafChip::construct(config);
        let low_leaf =
            chip.assign_low_leaf(layouter.namespace(|| "assign low leaf"), self.idx_low_leaf)?;

        //low_leaf should be replaced by hash of the low_leaf
        let old_root = self.low_leaf.calculate_merkle_root_from_leaf(
            &low_leaf[0],
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip,
        );

        chip.constrian_old_root(
            layouter.namespace(|| "constrain calculate old root"),
            &old_root,
        )?;

        let new_leaf = chip.assign_new_leaf(
            layouter.namespace(|| "assign new leaf"),
            self.new_leaf_val,
            &low_leaf[1],
            &low_leaf[2],
        )?;

        let new_low_leaf = chip.assign_new_low_leaf(
            layouter.namespace(|| "assign new_low_leaf"),
            self.new_leaf_idx,
            &new_leaf[0],
            &low_leaf[0],
        )?;

        //Replace the low_leaf[0] with the hash of the new_low_leaf
        let new_low_leaf_val = new_low_leaf[0].value().map(|val| *val);
        let new_low_leaf_merkle = MerkleTreeCircuit::new(
            new_low_leaf_val,
            self.low_leaf.path_elements.clone(),
            self.low_leaf.path_indices.clone(),
        );

        let intermediate_new_low_leaf_root = new_low_leaf_merkle.calculate_merkle_root_from_leaf(
            &low_leaf[0],
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip,
        );

        let default_idx_leaf = Value::known(F::ZERO);

        //need to add more constrin to it
        let prev_new_leaf_idx_val_merkle = MerkleTreeCircuit::new(
            default_idx_leaf,
            self.new_leaf.path_elements.clone(),
            self.new_leaf.path_indices.clone(),
        );

        //Take the default leaf value from the instance

        let intermediate_new_leaf_root = prev_new_leaf_idx_val_merkle
            .calculate_merkle_root_from_leaf(
                &new_leaf[0],
                layouter.namespace(|| "calculate the merkle root"),
                &merkle_tree_chip,
            );

        layouter.assign_region(
            || "constrain the intermediate roots",
            |mut region| {
                region.constrain_equal(
                    intermediate_new_low_leaf_root.cell(),
                    intermediate_new_leaf_root.cell(),
                )
            },
        )?;

        //calculate the idx new leaf hash and replace it with new_leaf[0]

        let calculated_new_root = self.new_leaf.calculate_merkle_root_from_leaf(
            &new_leaf[0],
            layouter.namespace(|| "calculate the merkle root"),
            &merkle_tree_chip,
        );

        chip.constrian_new_root(
            layouter.namespace(|| "constrian new root"),
            &calculated_new_root,
        )?;

        Ok(())
    }
}
