use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error},
};
use halo2curves::group::ff::PrimeField;
use poseidon_circuit::{
    poseidon::{
        primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3},
        Hash,
    },
    Hashable,
};

pub use poseidon_circuit::poseidon::{Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig};

pub type P128Pow5T3Fr = P128Pow5T3<Fr>;

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
pub fn hash_assigned<const L: usize>(
    config: PoseidonConfig<Fr, 3, 2>,
    mut layouter: impl Layouter<Fr>,
    messages: [AssignedCell<Fr, Fr>; L],
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let chip = PoseidonChip::construct(config);
    let hasher = Hash::<_, _, P128Pow5T3<Fr>, ConstantLength<L>, 3, 2>::init(
        chip,
        layouter.namespace(|| "initialize hasher"),
    )?;

    hasher.hash(layouter.namespace(|| "hash assigned values"), messages)
}

pub fn native_posedion<F: PrimeField, const L: usize>(message: [F; L]) -> F {
    PoseidonHash::<F, P128Pow5T3<F>, ConstantLength<L>, 3, 2>::init().hash(message)
}
