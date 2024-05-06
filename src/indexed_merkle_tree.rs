use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::ff::PrimeField,
    plonk::{Advice, Column, Error},
};

use crate::utils::assign_private_input;

#[derive(Debug, Clone, Default, Copy)]
pub struct IndexedMerkleTreeLeaf<F: PrimeField> {
    val: F,
    next_val: F,
    next_idx: F,
}
impl<F: PrimeField> IndexedMerkleTreeLeaf<F> {
    pub fn new(val: F, next_val: F, next_idx: F) -> Self {
        Self {
            val,
            next_val,
            next_idx,
        }
    }

    pub fn assign_leaf(
        &self,
        mut layouter: impl Layouter<F>,
        advices: [Column<Advice>; 3],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let val = assign_private_input(
            || "leaf val assign",
            layouter.namespace(|| "leaf val assign"),
            advices[0],
            Value::known(self.val),
            0,
        )?;
        let next_val = assign_private_input(
            || "leaf next_val assign",
            layouter.namespace(|| "leaf next_val assign"),
            advices[1],
            Value::known(self.next_val),
            0,
        )?;
        let next_idx = assign_private_input(
            || "leaf next_idx assign",
            layouter.namespace(|| "leaf next_idx assign"),
            advices[2],
            Value::known(self.next_idx),
            0,
        )?;
        Ok([val, next_val, next_idx].to_vec())
    }

    pub fn val(&self) -> F {
        self.val
    }
    pub fn next_val(&self) -> F {
        self.next_val
    }
    pub fn next_idx(&self) -> F {
        self.next_idx
    }
}
pub struct IndexedMerkleTreeLeafAssigned<F: PrimeField> {
    pub val: AssignedCell<F, F>,
    pub next_val: AssignedCell<F, F>,
    pub next_idx: AssignedCell<F, F>,
}
impl<F: PrimeField> IndexedMerkleTreeLeafAssigned<F> {
    pub fn new(
        val: AssignedCell<F, F>,
        next_val: AssignedCell<F, F>,
        next_idx: AssignedCell<F, F>,
    ) -> Self {
        Self {
            val,
            next_val,
            next_idx,
        }
    }
    pub fn from_vec(cells: Vec<AssignedCell<F, F>>) -> Self {
        Self {
            val: cells[0].clone(),
            next_val: cells[1].clone(),
            next_idx: cells[2].clone(),
        }
    }
}
