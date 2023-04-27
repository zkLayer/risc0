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

use core::{marker::PhantomData, mem::MaybeUninit};

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

impl BigInt {
    // TODO(victor): I would like to provide some kind of check to ensure that the
    // inputs x and y are reduced relative to the intended modulus.
    // Unforcunately, the modulus is not known ahead of time.
    /// Creates a new BigInt from the provided array representation.
    pub fn new(arr: [u32; bigint::WIDTH_WORDS]) -> Self {
        Self(arr)
    }

    /// Calculates the modular multiplication self * other (mod modulus).
    #[inline(always)]
    pub fn mulmod(&self, other: &Self, modulus: &Self) -> Self {
        let mut result = MaybeUninit::<BigInt>::uninit();
        unsafe {
            sys_bigint(
                result.as_mut_ptr() as *mut [u32; bigint::WIDTH_WORDS],
                bigint::OP_MULTIPLY,
                &self.0,
                &other.0,
                &modulus.0,
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
                &mut self.0,
                bigint::OP_MULTIPLY,
                &self.0,
                &other.0,
                &modulus.0,
            );
        }
    }
}

trait Token {}

struct Nil;

impl Token for Nil {}

struct Num<T: Token, const N: u32>(PhantomData<T>);

impl<T: Token, const N: u32> Token for Num<T, N> {}

type NumDEADBEEF = Num<Num<Nil, 0xdead>, 0xbeef>;
