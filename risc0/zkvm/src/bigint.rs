// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Big integer interface. Provides a safe interface for using the RISC Zero
//! BigInt extension.

// TODO(victor): Provide a reduction method for use on the host.

use core::{cmp::Ordering, marker::PhantomData, mem::MaybeUninit};

use risc0_zkvm_platform::syscall::{bigint, sys_bigint};

// TODO(victor): Is there a better name for this type?
/// Fixed-width big integer supporting arithmetic including modular
/// multiplication.
///
/// BigInt provides a safe wrapper over the RISC Zero BigInt
/// accelerator circuit.
#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct BigInt(pub [u32; bigint::WIDTH_WORDS]);

impl BigInt {
    /// Create a new BigInt from an array of least-to-most significant limbs.
    pub const fn new(arr: [u32; bigint::WIDTH_WORDS]) -> Self {
        Self(arr)
    }

    /// BigInt value representing one, the multiplicative identity.
    pub const fn one() -> Self {
        Self::new([1, 0, 0, 0, 0, 0, 0, 0])
    }

    /// BigInt value representing zero, the additive identity.
    pub const fn zero() -> Self {
        Self::new([0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Add the given BigInt value to self, returning the carry bit.
    #[must_use]
    #[inline]
    pub fn add_assign(&mut self, other: &Self) -> bool {
        let mut carry = false;
        for i in 0..bigint::WIDTH_WORDS {
            let tmp = (self.0[i] as u64) + (other.0[i] as u64) + (carry as u64);
            self.0[i] = tmp as u32;
            carry = (tmp >> u32::BITS) != 0;
        }
        carry
    }

    /// Subtract the given BigInt value from self, returning the borrow bit.
    #[must_use]
    #[inline]
    pub fn sub_assign(&mut self, other: &Self) -> bool {
        let mut borrow = false;
        for i in 0..bigint::WIDTH_WORDS {
            let tmp =
                (1u64 << u32::BITS) + (self.0[i] as u64) - (other.0[i] as u64) - (borrow as u64);
            self.0[i] = tmp as u32;
            borrow = (tmp >> u32::BITS) == 0;
        }
        borrow
    }
}

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..bigint::WIDTH_WORDS).rev() {
            if self.0[i] == other.0[i] {
                continue;
            }
            return self.0[i].cmp(&other.0[i]);
        }
        Ordering::Equal
    }
}

impl PartialOrd<Self> for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Representation of the residue class of integers modulo a constant N.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Residue<N: Modulus>(BigInt, PhantomData<N>);

impl<N: Modulus> Residue<N> {
    /// Create a new BigInt from a BigInt of least-to-most significant limbs.
    pub const fn new(val: BigInt) -> Self {
        Self(val, PhantomData)
    }

    /// Residue value representing one, the multiplicative identity.
    pub const fn one() -> Self {
        Self(BigInt::one(), PhantomData)
    }

    /// Residue value representing zero, the additive identity.
    pub const fn zero() -> Self {
        Self(BigInt::zero(), PhantomData)
    }

    /// Calculates the modular multiplication self * other (mod N).
    #[inline(always)]
    pub fn mul(&self, other: &Self) -> Self {
        let mut result = MaybeUninit::<Self>::uninit();
        unsafe {
            sys_bigint(
                result.as_mut_ptr() as *mut [u32; bigint::WIDTH_WORDS],
                bigint::OP_MULTIPLY,
                &self.0 .0,
                &other.0 .0,
                &N::ARRAY,
            );
            result.assume_init()
        }
    }

    /// Calculates the modular multiplication self * other (mod N) and
    /// assigns the result.
    #[inline(always)]
    pub fn mul_assign(&mut self, other: &Self) {
        unsafe {
            sys_bigint(
                &mut self.0 .0,
                bigint::OP_MULTIPLY,
                &self.0 .0,
                &other.0 .0,
                &N::ARRAY,
            );
        }
    }

    /// Adds the given Residue value to self.
    #[inline]
    pub fn add_assign(&mut self, other: &Self) {
        let carry = self.0.add_assign(&other.0);
        if carry {
            let borrow = self.0.sub_assign(&N::BIGINT);

            // Assert that subtracting by the modulus brings the values back into the range
            // of representable numbers. Will always be true if the prover is
            // returns modular multiplication results in their reduced form, as should be
            // the case for a non-faulty prover.
            assert!(
                borrow == carry,
                "modular arithmetic inputs not in reduced form"
            );
        } else if &self.0 >= &N::BIGINT {
            self.reduce();
        }
    }

    /// Subtracts the given Residue value from self.
    #[inline]
    pub fn sub_assign(&mut self, other: &Self) {
        let borrow = self.0.sub_assign(&other.0);
        if borrow {
            let carry = self.0.add_assign(&N::BIGINT);

            // Assert that adding the modulus brings the values back into the range
            // of representable numbers. Will always be true if the prover is
            // returns modular multiplication results in their reduced form, as should be
            // the case for a non-faulty prover.
            assert!(carry, "modular arithmetic inputs not in reduced form");
        }
    }

    /// Unwraps the Residue value as a BigInt.
    ///
    /// Asserts that the underlying BigInt value is in fully reduced form. This
    /// will always be true if this code is running on the host, or in the
    /// guest with a cooperative prover. Ensures that a faulty prover cannot
    /// manipulate the result.
    pub fn into_bigint(self) -> BigInt {
        self.assert_reduced();
        self.0
    }

    #[inline]
    fn reduce(&mut self) {
        // Multiplying by one will result in an equivalent value in the residue class.
        // Cooperative provers will return the representative element in the
        // range [0, N).
        self.mul_assign(&Self::one());
    }

    #[inline]
    fn assert_reduced(&self) {
        assert!(
            &self.0 < &N::BIGINT,
            "modular arithmetic value not in reduced form"
        );
    }
}

impl From<[u32; bigint::WIDTH_WORDS]> for BigInt {
    fn from(arr: [u32; bigint::WIDTH_WORDS]) -> Self {
        Self(arr)
    }
}

impl<N: Modulus> From<Residue<N>> for BigInt {
    fn from(residue: Residue<N>) -> Self {
        residue.into_bigint()
    }
}

// TODO: Should a reduction happen here?
impl<N: Modulus> From<[u32; bigint::WIDTH_WORDS]> for Residue<N> {
    fn from(arr: [u32; bigint::WIDTH_WORDS]) -> Self {
        Self(arr.into(), PhantomData)
    }
}

impl<N: Modulus> From<BigInt> for Residue<N> {
    fn from(int: BigInt) -> Self {
        Self(int, PhantomData)
    }
}

/// Generic type used to specify a constant in modulus in a type signature.
/// Implements the [Modulus] trait.
pub struct ModulusTypeArr<
    const N0: u32,
    const N1: u32,
    const N2: u32,
    const N3: u32,
    const N4: u32,
    const N5: u32,
    const N6: u32,
    const N7: u32,
>;

/// Modulus trait for specifying a constant modulus as a type parameter.
pub trait Modulus {
    /// Modulus value represented as an array of u32 limbs in least-to-most
    /// significant order.
    const ARRAY: [u32; bigint::WIDTH_WORDS];

    /// Modulus value represented as a BigInt.
    const BIGINT: BigInt = BigInt::new(Self::ARRAY);
}

impl<
        const N0: u32,
        const N1: u32,
        const N2: u32,
        const N3: u32,
        const N4: u32,
        const N5: u32,
        const N6: u32,
        const N7: u32,
    > Modulus for ModulusTypeArr<N0, N1, N2, N3, N4, N5, N6, N7>
{
    const ARRAY: [u32; bigint::WIDTH_WORDS] = [N0, N1, N2, N3, N4, N5, N6, N7];
}

#[cfg(test)]
mod tests {
    use super::*;

    type Secp256k1P = ModulusTypeArr<
        0xfffffc2f,
        0xfffffffe,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
        0xffffffff,
    >;

    #[test]
    fn type_constant_resolves_to_array() {
        assert_eq!(
            Secp256k1P::ARRAY,
            [
                0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                0xffffffff,
            ]
        )
    }
}
