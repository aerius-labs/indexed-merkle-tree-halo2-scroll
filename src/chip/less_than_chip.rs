use super::utils::{bool_check, expr_from_bytes, pow_of_two, sum};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region, Value},
    halo2curves::group::ff::PrimeField,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, TableColumn, VirtualCells},
    poly::Rotation,
};
use poseidon_circuit::Bn256Fr as Fr;

/// Instruction that the Lt chip needs to implement.
pub trait LtInstruction {
    /// Assign the lhs and rhs witnesses to the Lt chip's region.
    type Config: Clone;
    fn assign(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        lhs: Fr,
        rhs: Fr,
    ) -> Result<(), Error>;

    /// Load the u8 lookup table.
    fn dev_load(
        &self,
        layouter: &mut impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error>;
}

/// Config for the Lt chip.
#[derive(Clone, Copy, Debug)]
pub struct LtConfig<const N_BYTES: usize> {
    /// Denotes the lt outcome. If lhs < rhs then lt == 1, otherwise lt == 0.
    pub lt: Column<Advice>,
    /// Denotes the bytes representation of the difference between lhs and rhs.
    pub diff: [Column<Advice>; N_BYTES],
    /// Denotes the range within which each byte should lie.
    pub u8_table: TableColumn,
    /// Denotes the range within which both lhs and rhs lie.
    pub range: Fr,
}

impl<const N_BYTES: usize> LtConfig<N_BYTES> {
    /// Returns an expression that denotes whether lhs < rhs, or not.
    pub fn is_lt(&self, meta: &mut VirtualCells<Fr>, rotation: Option<Rotation>) -> Expression<Fr> {
        meta.query_advice(self.lt, rotation.unwrap_or_else(Rotation::cur))
    }

    /// Returns an expression representing the difference between LHS and RHS.
    pub fn diff(&self, meta: &mut VirtualCells<Fr>, rotation: Option<Rotation>) -> Expression<Fr> {
        let rotation = rotation.unwrap_or_else(Rotation::cur);
        sum::expr(self.diff.iter().map(|c| meta.query_advice(*c, rotation)))
    }
}

/// Chip that compares lhs < rhs.
#[derive(Clone, Debug)]
pub struct LtChip<const N_BYTES: usize> {
    pub(crate) config: LtConfig<N_BYTES>,
}

impl<const N_BYTES: usize> LtChip<N_BYTES> {
    /// Configures the Lt chip.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        q_enable: impl (FnOnce(&mut VirtualCells<'_, Fr>) -> Expression<Fr>) + Clone,
        lhs: impl FnOnce(&mut VirtualCells<Fr>) -> Expression<Fr>,
        rhs: impl FnOnce(&mut VirtualCells<Fr>) -> Expression<Fr>,
        u8_table: TableColumn,
    ) -> LtConfig<N_BYTES> {
        let lt: Column<Advice> = meta.advice_column();
        let diff = [(); N_BYTES].map(|_| meta.advice_column());
        let range = pow_of_two(N_BYTES * 8);

        meta.create_gate("lt gate", |meta| {
            let q_enable = q_enable.clone()(meta);
            let lt = meta.query_advice(lt, Rotation::cur());

            let diff_bytes = diff
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect::<Vec<Expression<Fr>>>();

            let check_a = lhs(meta) - rhs(meta) - expr_from_bytes(&diff_bytes) + lt.clone() * range;

            let check_b = bool_check(lt);

            [check_a, check_b]
                .into_iter()
                .map(move |poly| q_enable.clone() * poly)
        });

        for cell_column in diff {
            meta.lookup("range check for u8", |meta| {
                let q_enable = q_enable.clone()(meta);
                vec![(
                    q_enable * meta.query_advice(cell_column, Rotation::cur()),
                    u8_table,
                )]
            });
        }

        LtConfig {
            lt,
            diff,
            u8_table,
            range,
        }
    }

    /// Constructs a Lt chip given a config.
    pub fn construct(config: LtConfig<N_BYTES>) -> LtChip<N_BYTES> {
        LtChip { config }
    }
}

impl<const N_BYTES: usize> LtInstruction for LtChip<N_BYTES> {
    type Config = LtConfig<N_BYTES>;
    fn assign(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        lhs: Fr,
        rhs: Fr,
    ) -> Result<(), Error> {
        let config = self.config.clone();

        let lt = lhs.lt(&rhs);
        region.assign_advice(
            || "lt chip: lt",
            config.lt,
            offset,
            || Value::known(Fr::from(lt as u64)),
        )?;

        let diff = lhs - rhs + (if lt { config.range } else { Fr::zero() });
        let diff_bytes = diff.to_repr();
        let diff_bytes = diff_bytes.as_ref();
        for (idx, diff_column) in config.diff.iter().enumerate() {
            region.assign_advice(
                || format!("lt chip: diff byte {idx}"),
                *diff_column,
                offset,
                || Value::known(Fr::from(diff_bytes[idx] as u64)),
            )?;
        }

        Ok(())
    }

    fn dev_load(
        &self,
        layouter: &mut impl halo2_proofs::circuit::Layouter<Fr>,
    ) -> Result<(), Error> {
        const RANGE: usize = u8::MAX as usize;

        layouter.assign_table(
            || "load u8 range check table",
            |mut table| {
                for i in 0..=RANGE {
                    table.assign_cell(
                        || "assign cell in fixed column",
                        self.config.u8_table,
                        i,
                        || Value::known(Fr::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

impl<Fr: FieldExt, const N_BYTES: usize> Chip<Fr> for LtChip<N_BYTES> {
    type Config = LtConfig<N_BYTES>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
#[cfg(test)]
mod test {
    use super::{LtChip, LtConfig, LtInstruction};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    };
    use poseidon_circuit::Bn256Fr as Fr;
    use std::marker::PhantomData;

    macro_rules! try_test_circuit {
        ($values:expr, $checks:expr, $result:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = (usize::BITS - $values.len().leading_zeros() + 2).max(9);
            let circuit = TestCircuit {
                values: Some($values),
                checks: Some($checks),
                _marker: PhantomData,
            };
            let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    macro_rules! try_test_circuit_error {
        ($values:expr, $checks:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = (usize::BITS - $values.len().leading_zeros() + 2).max(9);
            let circuit = TestCircuit {
                values: Some($values),
                checks: Some($checks),
                _marker: PhantomData,
            };
            let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    #[test]
    fn row_diff_is_lt() {
        #[derive(Clone, Debug)]
        struct TestCircuitConfig {
            q_enable: Selector,
            value: Column<Advice>,
            check: Column<Advice>,
            lt: LtConfig<8>,
        }

        #[derive(Default)]
        struct TestCircuit {
            values: Option<Vec<u64>>,
            // checks[i] = lt(values[i + 1], values[i])
            checks: Option<Vec<bool>>,
            _marker: PhantomData<Fr>,
        }

        impl Circuit<Fr> for TestCircuit {
            type Config = TestCircuitConfig;
            type FloorPlanner = SimpleFloorPlanner;
            #[cfg(feature = "circuit-params")]
            type Params = ();

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
                let q_enable = meta.complex_selector();
                let value = meta.advice_column();
                let check = meta.advice_column();
                let u8_table = meta.lookup_table_column();

                let lt = LtChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    |meta| meta.query_advice(value, Rotation::prev()),
                    |meta| meta.query_advice(value, Rotation::cur()),
                    u8_table,
                );

                let config = Self::Config {
                    q_enable,
                    value,
                    check,
                    lt,
                };

                meta.create_gate("check is_lt between adjacent rows", |meta| {
                    let q_enable = meta.query_selector(q_enable);

                    // This verifies lt(value::cur, value::next) is calculated correctly
                    let check = meta.query_advice(config.check, Rotation::cur());

                    vec![q_enable * (config.lt.is_lt(meta, None) - check)]
                });

                config
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fr>,
            ) -> Result<(), Error> {
                let chip = LtChip::construct(config.lt);

                let values: Vec<_> = self
                    .values
                    .as_ref()
                    .map(|values| values.iter().map(|value| Fr::from(*value)).collect())
                    .ok_or(Error::Synthesis)?;
                let checks = self.checks.as_ref().ok_or(Error::Synthesis)?;
                let (first_value, values) = values.split_at(1);
                let first_value = first_value[0];

                chip.dev_load(&mut layouter)?;

                layouter.assign_region(
                    || "witness",
                    |mut region| {
                        region.assign_advice(
                            || "first row value",
                            config.value,
                            0,
                            || Value::known(first_value),
                        )?;

                        let mut value_prev = first_value;
                        for (idx, (value, check)) in values.iter().zip(checks).enumerate() {
                            config.q_enable.enable(&mut region, idx + 1)?;
                            region.assign_advice(
                                || "check",
                                config.check,
                                idx + 1,
                                || Value::known(Fr::from(*check as u64)),
                            )?;
                            region.assign_advice(
                                || "value",
                                config.value,
                                idx + 1,
                                || Value::known(*value),
                            )?;
                            chip.assign(&mut region, idx + 1, value_prev, *value)?;

                            value_prev = *value;
                        }

                        Ok(())
                    },
                )
            }
        }

        // ok
        try_test_circuit!(vec![1, 2, 3, 4, 5], vec![true, true, true, true], Ok(()));
        try_test_circuit!(vec![1, 2, 1, 3, 2], vec![true, false, true, false], Ok(()));
        // error
        try_test_circuit_error!(vec![5, 4, 3, 2, 1], vec![true, true, true, true]);
        try_test_circuit_error!(vec![1, 2, 1, 3, 2], vec![false, true, false, true]);
    }
}
