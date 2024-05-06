use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use halo2curves::group::ff::PrimeField;

use crate::merkle_treee::{MerkleTreeV3Chip, MerkleTreeV3Config};

//TODO: Add the merkle tree config and there advices
// Change the selector names

#[derive(Debug, Clone)]
pub struct InsertLeafConfig<F: PrimeField> {
    pub advice: [Column<Advice>; 6],
    pub is_new_leaf_greatest: Selector,
    pub valid_new_leaf_value: Selector,
    pub instances: [Column<Instance>; 2],
    pub merkle_tree_config: MerkleTreeV3Config<F>,
}

#[derive(Debug, Clone)]
pub struct InsertLeafChip<F: PrimeField> {
    config: InsertLeafConfig<F>,
}
impl<F: PrimeField> InsertLeafChip<F> {
    pub fn construct(config: InsertLeafConfig<F>) -> Self {
        Self { config }
    }
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; 3],
        instances: [Column<Instance>; 2],
    ) -> InsertLeafConfig<F> {
        let val_col = advices[0];
        let nxt_val = advices[1];
        let nxt_idx = advices[3];

        // Create selector
        let is_new_leaf_greatest = meta.selector();
        let valid_new_leaf_value = meta.selector();

        // Enable Equality
        meta.enable_equality(val_col);
        meta.enable_equality(nxt_val);
        meta.enable_equality(nxt_idx);
        meta.enable_equality(instances[0]);

        //Check is is new_value_greater | low_leaf_nxt_val = 0
        meta.create_gate("valid new leaf value", |meta| {
            let s = meta.query_selector(is_new_leaf_greatest);
            let is_new_leaf_val_greater_new_leal_val = meta.query_advice(val_col, Rotation::cur());
            let low_leaf_nxt_val = meta.query_advice(nxt_val, Rotation(-2));
            let is_new_leaf_val_largest = meta.query_instance(instances[0], Rotation(-2));
            vec![
                s * is_new_leaf_val_largest
                    * (low_leaf_nxt_val + is_new_leaf_val_greater_new_leal_val
                        - Expression::Constant(F::from(1))),
            ]
        });

        //Check new leaf value greater than low leaf value
        meta.create_gate("new leaf value geather than low leaf value", |meta| {
            let s = meta.query_selector(valid_new_leaf_value);
            let is_new_leaf_val_grt_low_leaf_val = meta.query_advice(nxt_idx, Rotation::cur());
            vec![s - is_new_leaf_val_grt_low_leaf_val]
        });
        let merkle_tree_advices = [advices[3], advices[4], advices[5]];

        let merkle_tree_config =
            MerkleTreeV3Chip::configure(meta, merkle_tree_advices, instances[1]);

        InsertLeafConfig {
            advice: [
                val_col, nxt_val, nxt_idx, advices[3], advices[4], advices[5],
            ],
            is_new_leaf_greatest,
            valid_new_leaf_value,
            instances,
            merkle_tree_config,
        }
    }

    //Assign new leaf
    pub fn assign_new_leaf(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: Value<F>,
        low_leaf_nxt_val: AssignedCell<F, F>,
        low_leaf_nxt_idx: AssignedCell<F, F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let new_leaf_assign = layouter.assign_region(
            || "assign new leaf value",
            |mut region| {
                let new_leaf_val = region.assign_advice(
                    || "assign new leaf",
                    self.config.advice[0],
                    1,
                    || leaf,
                )?;
                let new_leaf_nxt_val = low_leaf_nxt_val.copy_advice(
                    || "copy low leaf nxt val to new leaf nxt val",
                    &mut region,
                    self.config.advice[1],
                    1,
                )?;

                let new_leaf_nxt_idx = low_leaf_nxt_idx.copy_advice(
                    || "copy low leaf nxt idx to new leaf nxt idx",
                    &mut region,
                    self.config.advice[2],
                    1,
                )?;
                Ok([new_leaf_val, new_leaf_nxt_val, new_leaf_nxt_idx].to_vec())
            },
        )?;

        Ok(new_leaf_assign)
    }
    //Assign new low leaf

    pub fn assign_new_low_leaf(
        &self,
        mut layouter: impl Layouter<F>,
        new_leaf_idx: Value<F>,
        new_leaf_val: AssignedCell<F, F>,
        low_leaf_val: AssignedCell<F, F>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let new_low_leaf_assign = layouter.assign_region(
            || "assign new low leaf value",
            |mut region| {
                let new_low_leaf_val = low_leaf_val.copy_advice(
                    || "copy low leaf val to new low leaf val",
                    &mut region,
                    self.config.advice[0],
                    3,
                )?;

                let new_low_leaf_nxt_val = new_leaf_val.copy_advice(
                    || "copy new leaf val to new low leaf nxt val",
                    &mut region,
                    self.config.advice[1],
                    3,
                )?;
                let new_low_leaf_nxt_idx = region.assign_advice(
                    || "assign new low leaf val",
                    self.config.advice[2],
                    3,
                    || new_leaf_idx,
                )?;
                Ok([new_low_leaf_val, new_low_leaf_nxt_val, new_low_leaf_nxt_idx].to_vec())
            },
        )?;
        Ok(new_low_leaf_assign)
    }
}
