use std::marker::PhantomData;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use poseidon_circuit::Bn256Fr as Fr;

use crate::utils::{poseidon_hash_gadget, P128Pow5T3Fr, PoseidonChip, PoseidonConfig};

#[derive(Debug, Clone)]
pub struct MerkleTreeConfig {
    pub advice: [Column<Advice>; 4],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub poseidon_config: PoseidonConfig<Fr, 3, 2>,
    _marker: PhantomData<Fr>,
}
#[derive(Debug, Clone)]
pub struct MerkleTreeChip {
    config: MerkleTreeConfig,
}

impl MerkleTreeChip {
    pub fn construct(config: MerkleTreeConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        advice: [Column<Advice>; 4],
    ) -> MerkleTreeConfig {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let col_d = advice[3];

        let bool_selector = meta.selector();
        let swap_selector = meta.selector();

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);

        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * c.clone() * (Expression::Constant(Fr::from(1)) - c)]
        });

        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let l = meta.query_advice(col_a, Rotation::next());
            let r = meta.query_advice(col_b, Rotation::next());
            vec![
                s * (c * Expression::Constant(Fr::from(2)) * (b.clone() - a.clone())
                    - (l - a)
                    - (b - r)),
            ]
        });

        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        meta.enable_constant(lagrange_coeffs[0]);

        let poseidon_config = PoseidonChip::configure::<P128Pow5T3Fr>(
            meta,
            advice[0..3].try_into().unwrap(),
            advice[3],
            lagrange_coeffs[2..5].try_into().unwrap(),
            lagrange_coeffs[5..8].try_into().unwrap(),
        );

        MerkleTreeConfig {
            advice: [col_a, col_b, col_c, col_d],
            bool_selector,
            swap_selector,
            poseidon_config,
            _marker: PhantomData,
        }
    }

    pub fn assing_leaf(
        &self,
        mut layouter: impl Layouter<Fr>,
        leaf: Value<Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let node_cell = layouter.assign_region(
            || "assign leaf",
            |mut region| region.assign_advice(|| "assign leaf", self.config.advice[0], 0, || leaf),
        )?;

        Ok(node_cell)
    }

    pub fn compute_merkle_root_from_path(
        &self,
        mut layouter: impl Layouter<Fr>,
        node_cell: &AssignedCell<Fr, Fr>,
        path_element: Value<Fr>,
        index: Value<Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let (left, right) = layouter.assign_region(
            || "compute merkle root",
            |mut region| {
                // Row 0
                // self.config.bool_selector.enable(&mut region, 0)?;
                // self.config.swap_selector.enable(&mut region, 0)?;
                node_cell.copy_advice(
                    || "copy node cell from previous prove layer",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;
                region.assign_advice(
                    || "assign element",
                    self.config.advice[1],
                    0,
                    || path_element,
                )?;
                region.assign_advice(|| "assign index", self.config.advice[2], 0, || index)?;

                let node_cell_value = node_cell.value().map(|x| x.to_owned());
                let (mut l, mut r) = (node_cell_value, path_element);
                index.map(|x| {
                    (l, r) = if x == Fr::zero() { (l, r) } else { (r, l) };
                });

                let left = region.assign_advice(
                    || "assign left to be hashed",
                    self.config.advice[0],
                    1,
                    || l,
                )?;
                let right = region.assign_advice(
                    || "assign right to be hashed",
                    self.config.advice[1],
                    1,
                    || r,
                )?;

                Ok((left, right))
            },
        )?;
        //TODO:Try to re-use the sae config

        let digest =
            poseidon_hash_gadget(self.config.poseidon_config.clone(), layouter, [left, right])?;

        Ok(digest)
    }
}
