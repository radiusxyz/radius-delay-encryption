pub mod chip;
mod instructions;
mod utils;

use std::marker::PhantomData;

pub use chip::*;
use ff::PrimeField;
use halo2wrong::halo2::arithmetic::Field;
use halo2wrong::halo2::circuit::Value;
pub use instructions::*;
use maingate::{fe_to_big, AssignedValue};
use num_bigint::BigUint;
pub use utils::*;

/// Trait for types representing a range of the limb.
pub trait RangeType: Clone {}

/// [`RangeType`] assigned to [`AssignedLimb`] and [`AssignedInteger`] that are not multiplied yet.
///
/// The maximum value of the [`Fresh`] type limb is defined in the chip implementing [`BigIntInstructions`] trait.
/// For example, [`BigIntChip`] has an `limb_width` parameter and limits the size of the [`Fresh`] type limb to be less than `2^(limb_width)`.
#[derive(Debug, Clone)]
pub struct Fresh {}
impl RangeType for Fresh {}

/// [`RangeType`] assigned to [`AssignedLimb`] and [`AssignedInteger`] that are already multiplied.
///
/// The value of the [`Muled`] type limb may overflow the maximum value of the [`Fresh`] type limb.
/// You can convert the [`Muled`] type integer to the [`Fresh`] type integer by calling [`BigIntInstructions::refresh`] function.
#[derive(Debug, Clone)]
pub struct Muled {}
impl RangeType for Muled {}

/// An assigned limb of an non native integer.
#[derive(Debug, Clone)]
pub struct AssignedLimb<F: Field, T: RangeType>(AssignedValue<F>, PhantomData<T>);

impl<F: Field, T: RangeType> From<AssignedLimb<F, T>> for AssignedValue<F> {
    /// [`AssignedLimb`] can be also represented as [`AssignedValue`].
    fn from(limb: AssignedLimb<F, T>) -> Self {
        limb.0
    }
}

impl<F: Field, T: RangeType> AssignedLimb<F, T> {
    /// Constructs new [`AssignedLimb`] from an assigned value.
    ///
    /// # Arguments
    /// * value - an assigned value representing a witness value.
    ///
    /// # Return values
    /// Returns a new [`AssignedLimb`].
    pub fn from(value: AssignedValue<F>) -> Self {
        AssignedLimb::<_, T>(value, PhantomData)
    }

    /// Returns the witness value as [`AssignedValue<F>`].
    pub fn assigned_val(&self) -> AssignedValue<F> {
        self.0.clone()
    }

    /// Converts the [`RangeType`] from [`Fresh`] to [`Muled`].
    pub fn to_muled(self) -> AssignedLimb<F, Muled> {
        AssignedLimb::<F, Muled>(self.0, PhantomData)
    }
}

/// Witness integer that is about to be assigned.
#[derive(Debug, Clone)]
pub struct UnassignedInteger<F: Field> {
    pub value: Value<Vec<F>>,
    pub num_limbs: usize,
}

impl<F: Field> From<Vec<F>> for UnassignedInteger<F> {
    /// Constructs new [`UnassignedInteger`] from a vector of witness values.
    fn from(value: Vec<F>) -> Self {
        let num_limbs = value.len();
        UnassignedInteger {
            value: Value::known(value),
            num_limbs,
        }
    }
}

impl<F: Field> UnassignedInteger<F> {
    /// Returns indexed limb as [`Value<F>`].
    ///
    /// # Arguments
    /// * idx - the index of the limb to retrieve.
    ///
    /// # Return values
    /// Returns the specified limb as [`Value<F>`].
    fn limb(&self, idx: usize) -> Value<F> {
        self.value.as_ref().map(|e| e[idx])
    }

    /// Returns the number of the limbs.
    fn num_limbs(&self) -> usize {
        self.num_limbs
    }
}

/// An assigned witness integer.
#[derive(Debug, Clone)]
pub struct AssignedInteger<F: Field, T: RangeType>(Vec<AssignedLimb<F, T>>);

impl<F: PrimeField, T: RangeType> AssignedInteger<F, T> {
    /// Creates a new [`AssignedInteger`].
    ///
    /// # Arguments
    /// * limbs - a vector of [`AssignedLimb`].
    ///
    /// # Return values
    /// Returns a new [`AssignedInteger`].
    pub fn new(limbs: &[AssignedLimb<F, T>]) -> Self {
        AssignedInteger(limbs.to_vec())
    }

    /// Returns assigned limbs.
    pub fn limbs(&self) -> Vec<AssignedLimb<F, T>> {
        self.0.clone()
    }

    /// Returns indexed limb as [`Value`].
    ///
    /// # Arguments
    /// * idx - the index of the limb to retrieve.
    ///
    /// # Return values
    /// Returns the specified limb as [`AssignedValue<F>`].
    pub fn limb(&self, idx: usize) -> AssignedValue<F> {
        self.0[idx].clone().into()
    }

    /// Returns the number of the limbs.
    pub fn num_limbs(&self) -> usize {
        self.0.len()
    }

    /// Returns the witness value as [`Value<BigUint>`].
    ///
    /// # Arguments
    /// * width - bit length of each limb.
    ///
    /// # Return values
    /// Returns the witness value as [`Value<BigUint>`].
    pub fn to_big_uint(&self, width: usize) -> Value<BigUint> {
        let num_limbs = self.num_limbs();
        (1..num_limbs).fold(self.limb(0).value().map(|f| fe_to_big(*f)), |acc, i| {
            acc + self.limb(i).value().map(|f| fe_to_big(*f) << (width * i))
        })
    }

    /// Replaces the specified limb to the given value.
    ///
    /// # Arguments
    /// * idx - index of the modified limb.
    /// * limb - new limb.
    pub fn replace_limb(&mut self, idx: usize, limb: AssignedLimb<F, T>) {
        self.0[idx] = limb;
    }

    /// Increases the number of the limbs by adding the given [`AssignedValue<F>`] representing zero.
    ///
    /// # Arguments
    /// * num_extend_limbs - the number of limbs to add.
    /// * zero_value - an assigned value representing zero.
    pub fn extend_limbs(&mut self, num_extend_limbs: usize, zero_value: AssignedValue<F>) {
        let pre_num_limbs = self.num_limbs();
        for _ in 0..num_extend_limbs {
            self.0.push(AssignedLimb::from(zero_value.clone()));
        }
        assert_eq!(pre_num_limbs + num_extend_limbs, self.num_limbs());
    }
}

impl<F: PrimeField> AssignedInteger<F, Fresh> {
    /// Converts the [`RangeType`] from [`Fresh`] to [`Muled`].
    ///
    /// # Arguments
    /// * zero_limb - an assigned limb representing zero.
    ///
    /// # Return values
    /// Returns the converted integer whose type is [`AssignedInteger<F, Muled>`].
    /// The number of limbs of the converted integer increases to `2 * num_limb - 1`.
    pub fn to_muled(&self, zero_limb: AssignedLimb<F, Muled>) -> AssignedInteger<F, Muled> {
        let num_limb = self.num_limbs();
        let mut limbs = self
            .limbs()
            .into_iter()
            .map(|limb| limb.to_muled())
            .collect::<Vec<AssignedLimb<F, Muled>>>();
        for _ in 0..(num_limb - 1) {
            limbs.push(zero_limb.clone())
        }
        AssignedInteger::<F, Muled>::new(&limbs[..])
    }
}

/// Auxiliary data for refreshing a [`Muled`] type integer to a [`Fresh`] type integer.
#[derive(Debug, Clone)]
pub struct RefreshAux {
    limb_width: usize,
    num_limbs_l: usize,
    num_limbs_r: usize,
    increased_limbs_vec: Vec<usize>,
}

impl RefreshAux {
    /// Creates a new [`RefreshAux`] corresponding to `num_limbs_l` and `num_limbs_r`.
    ///
    /// # Arguments
    /// * `limb_width` - bit length of the limb.
    /// * `num_limbs_l` - a parameter to specify the number of limbs.
    /// * `num_limbs_r` - a parameter to specify the number of limbs.
    ///
    /// If `a` (`b`) is the product of integers `l` and `r`, you must specify the lengths of the limbs of integers `l` and `r` as `num_limbs_l` and `num_limbs_l`, respectively.
    ///
    /// # Return values
    /// Returns a new [`RefreshAux`].
    pub fn new(limb_width: usize, num_limbs_l: usize, num_limbs_r: usize) -> Self {
        let max_limb = (BigUint::from(1usize) << limb_width) - BigUint::from(1usize);
        let l_max = vec![max_limb.clone(); num_limbs_l];
        let r_max = vec![max_limb.clone(); num_limbs_r];
        let d = num_limbs_l + num_limbs_r - 1;
        let mut muled = Vec::new();
        for i in 0..d {
            let mut j = if num_limbs_r > i + 1 {
                0
            } else {
                i + 1 - num_limbs_r
            };
            muled.push(BigUint::from(0usize));
            while j < num_limbs_l && j <= i {
                let k = i - j;
                muled[i] += &l_max[j] * &r_max[k];
                j += 1;
            }
        }
        let mut increased_limbs_vec = Vec::new();
        let mut cur_d = 0;
        let max_d = d;
        while cur_d <= max_d {
            let num_chunks = if muled[cur_d].bits() % (limb_width as u64) == 0 {
                muled[cur_d].bits() / (limb_width as u64)
            } else {
                muled[cur_d].bits() / (limb_width as u64) + 1
            } as usize;
            increased_limbs_vec.push(num_chunks - 1);
            // if max_d < cur_d + num_chunks - 1 {
            // max_d = cur_d + num_chunks - 1;
            // }
            let mut chunks = Vec::with_capacity(num_chunks);
            for _ in 0..num_chunks {
                chunks.push(&muled[cur_d] & &max_limb);
                muled[cur_d] = &muled[cur_d] >> limb_width;
            }
            assert_eq!(muled[cur_d], BigUint::from(0usize));
            for j in 0..num_chunks {
                if muled.len() <= cur_d + j {
                    muled.push(BigUint::from(0usize));
                }
                muled[cur_d + j] += &chunks[j];
            }
            cur_d += 1;
        }

        Self {
            limb_width,
            num_limbs_l,
            num_limbs_r,
            increased_limbs_vec,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn test_debug_and_clone_traits() {
        use halo2wrong::curves::pasta::Fp as F;

        let fresh = Fresh {};
        let fresh = fresh.clone();
        assert_eq!(format!("{fresh:?}"), "Fresh");
        let muled = Muled {};
        let muled = muled.clone();
        assert_eq!(format!("{muled:?}"), "Muled");

        let unassigned_int = UnassignedInteger::from(vec![F::one()]);
        let unassigned_int = unassigned_int.clone();
        assert_eq!(format!("{unassigned_int:?}"), "UnassignedInteger { value: Value { inner: Some([0x0000000000000000000000000000000000000000000000000000000000000001]) }, num_limbs: 1 }");

        let limb_width = 32;
        let num_limbs_l = 1usize;
        let num_limbs_r = 1usize;
        let aux = RefreshAux::new(limb_width, num_limbs_l, num_limbs_r);
        let aux = aux.clone();
        assert_eq!(format!("{aux:?}"),"RefreshAux { limb_width: 32, num_limbs_l: 1, num_limbs_r: 1, increased_limbs_vec: [1, 0] }");
    }

    #[test]
    fn test_refresh_aux_random() {
        let mut rng = thread_rng();
        let limb_width = 32;
        let num_limbs_l = rng.gen::<u8>() as usize + 1usize;
        let num_limbs_r = rng.gen::<u8>() as usize + 1usize;
        let refresh_aux_0 = RefreshAux::new(limb_width, num_limbs_l, num_limbs_r);
        let refresh_aux_1 = RefreshAux::new(limb_width, num_limbs_r, num_limbs_l);
        assert_eq!(
            refresh_aux_0.increased_limbs_vec.len(),
            refresh_aux_1.increased_limbs_vec.len()
        );
        let vec0 = refresh_aux_0.increased_limbs_vec;
        let vec1 = refresh_aux_1.increased_limbs_vec;
        for i in 0..vec0.len() {
            assert_eq!(vec0[i], vec1[i]);
        }
    }
}
