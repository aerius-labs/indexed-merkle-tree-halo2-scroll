use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error},
};

pub const WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const L: usize = 2;

pub fn assign_private_input<F: PrimeField, V: Copy, N: Fn() -> NR, NR: Into<String>>(
    name: N,
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: Value<V>,
    offect: usize,
) -> Result<AssignedCell<V, F>, Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    layouter.assign_region(name, |mut region| {
        region.assign_advice(|| "load advice", column, offect, || value)
    })
}
use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2curves::group::ff::PrimeField;
use std::marker::PhantomData;

#[derive(Debug, Clone)]

pub struct PoseidonConfig<F: PrimeField, const WIDTH: usize, const RATE: usize, const L: usize> {
    pow5_config: Pow5Config<F, WIDTH, RATE>,
}

#[derive(Debug, Clone)]

pub struct PoseidonChip<
    F: PrimeField,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<F, WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<
        F: PrimeField,
        S: Spec<F, WIDTH, RATE>,
        const WIDTH: usize,
        const RATE: usize,
        const L: usize,
    > PoseidonChip<F, S, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<F, WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    // Configuration of the PoseidonChip
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        hash_inputs: Vec<Column<Advice>>,
    ) -> PoseidonConfig<F, WIDTH, RATE, L> {
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        for i in 0..WIDTH {
            meta.enable_equality(hash_inputs[i]);
        }
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            hash_inputs.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig { pow5_config }
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        input_cells: [AssignedCell<F, F>; L],
    ) -> Result<AssignedCell<F, F>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());

        // initialize the hasher
        let hasher = Hash::<F, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), input_cells)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MySpec<F: PrimeField, const WIDTH: usize, const RATE: usize> {
    _marker: PhantomData<F>,
}

impl<F: PrimeField, const WIDTH: usize, const RATE: usize> Spec<F, WIDTH, RATE>
    for MySpec<F, WIDTH, RATE>
{
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: F) -> F {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }
    fn constants() -> (Vec<[F; WIDTH]>, Mds<F, WIDTH>, Mds<F, WIDTH>) {
        unimplemented!()
    }
}
