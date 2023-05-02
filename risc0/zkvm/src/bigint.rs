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

use core::{
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Add, Sub},
};

use num_traits::{One, Zero};
use risc0_zkvm_platform::syscall::{bigint, sys_bigint};

// TODO(victor): Is there a better name for this type?
/// Fixed-width big integer supporting arithmetic including modular
/// multiplication.
///
/// BigInt provides a safe wrapper over the RISC Zero BigInt
/// accelerator circuit.
#[derive(Debug)]
#[repr(transparent)]
pub struct BigInt([u32; bigint::WIDTH_WORDS]);

const ZERO: BigInt = BigInt([0, 0, 0, 0, 0, 0, 0, 0]);

const ONE: BigInt = BigInt([1, 0, 0, 0, 0, 0, 0, 0]);

#[derive(Debug)]
#[repr(transparent)]
struct Residue<N: Modulus>(BigInt, PhantomData<N>);

impl<N: Modulus> Residue<N> {
    /// Calculates the modular multiplication self * other (mod modulus).
    #[inline(always)]
    pub fn mulmod(&self, other: &Self, modulus: &Self) -> Self {
        let mut result = MaybeUninit::<Self>::uninit();
        unsafe {
            sys_bigint(
                result.as_mut_ptr() as *mut [u32; bigint::WIDTH_WORDS],
                bigint::OP_MULTIPLY,
                &self.0 .0,
                &other.0 .0,
                &modulus.0 .0,
            );
            result.assume_init()
        }
    }

    /// Calculates the modular multiplication self * other (mod modulus) and
    /// assigns the result.
    #[inline(always)]
    pub fn mulmod_assign(&mut self, other: &Self, modulus: &Self) {
        unsafe {
            sys_bigint(
                &mut self.0 .0,
                bigint::OP_MULTIPLY,
                &self.0 .0,
                &other.0 .0,
                &modulus.0 .0,
            );
        }
    }
}

impl From<[u32; bigint::WIDTH_WORDS]> for BigInt {
    fn from(arr: [u32; bigint::WIDTH_WORDS]) -> Self {
        Self(arr)
    }
}

// TODO: Should a reduction happen here?
impl<N: Modulus> From<[u32; bigint::WIDTH_WORDS]> for Residue<N> {
    fn from(arr: [u32; bigint::WIDTH_WORDS]) -> Self {
        Self(arr.into(), PhantomData)
    }
}

struct ModulusTypeArr<
    const N0: u32,
    const N1: u32,
    const N2: u32,
    const N3: u32,
    const N4: u32,
    const N5: u32,
    const N6: u32,
    const N7: u32,
>;

trait Modulus {
    const ARRAY: [u32; bigint::WIDTH_WORDS];
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
