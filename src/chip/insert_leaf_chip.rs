use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
//use eth_types::Field;
use poseidon_circuit::Bn256Fr as Fr;

use crate::utils::IndexedMerkleTreeLeaf;

use super::{
    less_than_chip::{LtChip, LtConfig, LtInstruction},
    merkle_tree_chip::{MerkleTreeChip, MerkleTreeConfig},
};

//TODO: Change the selector names

//3 advice column for Inserting the indexed leaf
//4 advice column for Calculating the merkle root

#[derive(Debug, Clone)]
pub struct InsertLeafConfig {
    pub advice: [Column<Advice>; 7],
    pub instances: Column<Instance>,
    pub merkle_tree_config: MerkleTreeConfig,
    pub q_enable: Selector,
    pub q2_enable: Selector,
    pub less_than_chip: LtConfig<8>,
    pub greatest_new_leaf_lt: LtConfig<8>,
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
        let nxt_idx = advices[2];
        let hash_col = advices[6];


        // Enable Equality
        meta.enable_equality(val_col);
        meta.enable_equality(nxt_val);
        meta.enable_equality(nxt_idx);
        meta.enable_equality(hash_col);
        meta.enable_equality(instances);

        let q_enable = meta.complex_selector();
        let q2_enable = meta.complex_selector();
        let u8_table = meta.lookup_table_column();
        let u8_table2 = meta.lookup_table_column();

        let lt = LtChip::<8>::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| meta.query_advice(hash_col, Rotation::prev()),
            |meta| meta.query_advice(hash_col, Rotation::cur()),
            u8_table,
        );

        //Check is is new_value_greater | low_leaf_nxt_val = 0

        meta.create_gate("valid new leaf val ", |meta| {
            let s = meta.query_selector(q_enable);
            let valid = lt.is_lt(meta, None);
            vec![s * (valid - Expression::Constant(Fr::from(1)))]
        });

        let greatest_new_leaf_lt = LtChip::<8>::configure(
            meta,
            |meta| meta.query_selector(q2_enable),
            |meta| meta.query_advice(hash_col, Rotation::prev()),
            |meta| meta.query_advice(hash_col, Rotation::cur()),
            u8_table2,
        );

        meta.create_gate("is new leaf value greatest  ", |meta| {
            let s = meta.query_selector(q2_enable);

            let is_greatest = greatest_new_leaf_lt.is_lt(meta, None);

            let is_low_leaf_nxt_val_zero = meta.query_advice(hash_col, Rotation::prev());

            vec![s * (is_greatest + is_low_leaf_nxt_val_zero - Expression::Constant(Fr::from(1)))]
        });

    

        let merkle_tree_advices = [advices[3], advices[4], advices[5], hash_col];

        let merkle_tree_config = MerkleTreeChip::configure(meta, merkle_tree_advices);

        InsertLeafConfig {
            advice: [
                val_col, nxt_val, nxt_idx, advices[3], advices[4], advices[5], advices[6],
            ],
            instances,
            merkle_tree_config,
            q_enable,
            q2_enable,
            less_than_chip: lt,
            greatest_new_leaf_lt,
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

                let mut lhs = Fr::one();
                let mut rhs = Fr::one();
                let _ = low_leaf_nxt_val.value().map(|val| {
                    rhs = *val;
                });
                let _ = new_leaf_val.value().map(|val| {
                    lhs = *val;
                });

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

    pub fn assign_values_to_compare(
        &self,
        mut layouter: impl Layouter<Fr>,
        lhs: &AssignedCell<Fr, Fr>,
        rhs: &AssignedCell<Fr, Fr>,
    ) -> Result<(), Error> {
        let chip = LtChip::<8>::construct(self.config.less_than_chip);

        chip.dev_load(&mut layouter)?;

        layouter.assign_region(
            || "assign values to compare",
            |mut region| {
                let lhs = lhs
                    .copy_advice(|| "copy to hash col", &mut region, self.config.advice[6], 1)
                    .unwrap();
                let rhs = rhs
                    .copy_advice(|| "copy to hash col", &mut region, self.config.advice[6], 2)
                    .unwrap();

                self.config.q_enable.enable(&mut region, 2)?;
                let mut lhs_fr = Fr::one();
                let mut rhs_fr = Fr::one();
                let _ = lhs.value().map(|val| {
                    lhs_fr = *val;
                });
                let _ = rhs.value().map(|val| {
                    rhs_fr = *val;
                });
                chip.assign(&mut region, 2, lhs_fr, rhs_fr)?;
                Ok(())
            },
        )?;
        Ok(())
    }
    pub fn compare_low_leaf_nxt_val_and_new_leaf_val(
        &self,
        mut layouter: impl Layouter<Fr>,
        lhs: &AssignedCell<Fr, Fr>,
        rhs: &AssignedCell<Fr, Fr>,
    ) -> Result<(), Error> {
        let chip = LtChip::<8>::construct(self.config.greatest_new_leaf_lt);

        chip.dev_load(&mut layouter)?;

        layouter.assign_region(
            || "assign low leaf and new leaf value to compare",
            |mut region| {
                let lhs = lhs
                    .copy_advice(|| "copy to hash col", &mut region, self.config.advice[6], 3)
                    .unwrap();
                let rhs = rhs
                    .copy_advice(|| "copy to hash col", &mut region, self.config.advice[6], 4)
                    .unwrap();

                let mut lhs_fr = Fr::one();
                let mut rhs_fr = Fr::one();
                let _ = lhs.value().map(|val| {
                    lhs_fr = *val;
                });
                let _ = rhs.value().map(|val| {
                    rhs_fr = *val;
                });
                chip.assign(&mut region, 2, lhs_fr, rhs_fr)?;
                Ok(())
            },
        )?;
        Ok(())
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
}
