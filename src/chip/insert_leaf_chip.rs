use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
//use eth_types::Field;
use poseidon_circuit::Bn256Fr as Fr;

use crate::utils::IndexedMerkleTreeLeaf;

use super::merkle_tree_chip::{MerkleTreeChip, MerkleTreeConfig};

//TODO: Add the merkle tree config and there advices
//TODO: Change the selector names
//TODO: Add LtChip

//3 advice column for Inserting the indexed leaf
//4 advice column for Calculating the merkle root

#[derive(Debug, Clone)]
pub struct InsertLeafConfig {
    pub advice: [Column<Advice>; 7],
    pub is_new_leaf_greatest: Selector,
    pub valid_new_leaf_value: Selector,
    pub instances: Column<Instance>,
    pub merkle_tree_config: MerkleTreeConfig,
    _marker: PhantomData<Fr>,
}

#[derive(Debug, Clone)]
pub struct InsertLeafChip {
    config: InsertLeafConfig,
}
impl InsertLeafChip {
    pub fn construct(config: InsertLeafConfig) -> Self {
        Self { config }
    }
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        advices: [Column<Advice>; 7],
        instances: Column<Instance>,
    ) -> InsertLeafConfig {
        // Create Advice columns
        let val_col = advices[0];
        let nxt_val = advices[1];
        let nxt_idx = advices[3];
        let hash_col = advices[6];

        // Create selector
        let is_new_leaf_greatest = meta.selector();
        let valid_new_leaf_value = meta.selector();

        // Enable Equality
        meta.enable_equality(val_col);
        meta.enable_equality(nxt_val);
        meta.enable_equality(nxt_idx);
        meta.enable_equality(hash_col);
        meta.enable_equality(instances);

        //Check is is new_value_greater | low_leaf_nxt_val = 0
        meta.create_gate("valid new leaf value", |meta| {
            let s = meta.query_selector(is_new_leaf_greatest);
            let is_new_leaf_val_greater_new_leal_val = meta.query_advice(val_col, Rotation::cur());
            let low_leaf_nxt_val = meta.query_advice(nxt_val, Rotation(-2));
            let is_new_leaf_val_largest = meta.query_instance(instances, Rotation(-2));
            vec![
                s * is_new_leaf_val_largest
                    * (low_leaf_nxt_val + is_new_leaf_val_greater_new_leal_val
                        - Expression::Constant(Fr::from(1))),
            ]
        });

        //Check new leaf value greater than low leaf value
        meta.create_gate("new leaf value geather than low leaf value", |meta| {
            let s = meta.query_selector(valid_new_leaf_value);
            let is_new_leaf_val_grt_low_leaf_val = meta.query_advice(nxt_idx, Rotation::cur());
            vec![
                s * (Expression::Constant(Fr::from(1)) - is_new_leaf_val_grt_low_leaf_val
                    + Expression::Constant(Fr::from(1))),
            ]
        });

        let merkle_tree_advices = [advices[3], advices[4], advices[5], hash_col];

        let merkle_tree_config = MerkleTreeChip::configure(meta, merkle_tree_advices);

        InsertLeafConfig {
            advice: [
                val_col, nxt_val, nxt_idx, advices[3], advices[4], advices[5], advices[6],
            ],
            is_new_leaf_greatest,
            valid_new_leaf_value,
            instances,
            merkle_tree_config,
            _marker: PhantomData,
        }
    }

    pub fn assign_low_leaf(
        &self,
        mut layouter: impl Layouter<Fr>,
        leaf: IndexedMerkleTreeLeaf,
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        let assigned_leaf = layouter.assign_region(
            || "assign low leaf",
            |mut region| {
                let leaf_val = region.assign_advice(
                    || "assign leaf value",
                    self.config.advice[0],
                    0,
                    || Value::known(leaf.val),
                )?;
                let leaf_nxt_val = region.assign_advice(
                    || "assign leaf nxt val",
                    self.config.advice[1],
                    0,
                    || Value::known(leaf.next_val),
                )?;

                let leaf_nxt_idx = region.assign_advice(
                    || "assign leaf nxt idx",
                    self.config.advice[2],
                    0,
                    || Value::known(leaf.next_idx),
                )?;

                Ok([leaf_val, leaf_nxt_val, leaf_nxt_idx].to_vec())
            },
        )?;
        Ok(assigned_leaf)
    }

    //Assign new leaf
    pub fn assign_new_leaf(
        &self,
        mut layouter: impl Layouter<Fr>,
        leaf: Value<Fr>,
        low_leaf_nxt_val: &AssignedCell<Fr, Fr>,
        low_leaf_nxt_idx: &AssignedCell<Fr, Fr>,
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
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
        mut layouter: impl Layouter<Fr>,
        new_leaf_idx: Value<Fr>,
        new_leaf_val: &AssignedCell<Fr, Fr>,
        low_leaf_val: &AssignedCell<Fr, Fr>,
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        let new_low_leaf_assign = layouter.assign_region(
            || "assign new low leaf value",
            |mut region| {
                // self.config.valid_new_leaf_value.enable(&mut region, 3)?;
                let new_low_leaf_val = low_leaf_val.copy_advice(
                    || "copy low leaf val to new low leaf val",
                    &mut region,
                    self.config.advice[0],
                    2,
                )?;

                let new_low_leaf_nxt_val = new_leaf_val.copy_advice(
                    || "copy new leaf val to new low leaf nxt val",
                    &mut region,
                    self.config.advice[1],
                    2,
                )?;
                let new_low_leaf_nxt_idx = region.assign_advice(
                    || "assign new low leaf val",
                    self.config.advice[2],
                    2,
                    || new_leaf_idx,
                )?;
                Ok([new_low_leaf_val, new_low_leaf_nxt_val, new_low_leaf_nxt_idx].to_vec())
            },
        )?;
        Ok(new_low_leaf_assign)
    }
    //copy from the instance
    pub fn assign_default_leaf(
        &self,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let assigned_default_leaf = layouter.assign_region(
            || "copy default leaf from instance",
            |mut region| {
                region.assign_advice_from_instance(
                    || "assign the default leaf",
                    self.config.instances,
                    2,
                    self.config.advice[6],
                    0,
                )
            },
        )?;
        Ok(assigned_default_leaf)
    }
    pub fn constrian_new_root(
        &self,
        mut layouter: impl Layouter<Fr>,
        cell: &AssignedCell<Fr, Fr>,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instances, 3)
    }
    pub fn constrian_old_root(
        &self,
        mut layouter: impl Layouter<Fr>,
        cell: &AssignedCell<Fr, Fr>,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instances, 1)
    }
    //TODO:implement hash of the indexed leaf
}
