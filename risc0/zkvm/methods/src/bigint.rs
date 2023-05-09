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

use alloc::{vec, vec::Vec};
use core::mem;

use crypto_bigint::{
    rand_core::CryptoRngCore, CheckedMul, Encoding, NonZero, Random, RandomMod, U256,
};
use risc0_zkvm_platform::syscall::bigint;

use crate::multi_test::BigIntTestCase;

// Convert to little-endian u32 array. Only reinterprettation on LE machines.
fn bigint_to_arr(num: &U256) -> [u32; bigint::WIDTH_WORDS] {
    let mut arr: [u32; bigint::WIDTH_WORDS] = bytemuck::cast(num.to_le_bytes());
    for x in arr.iter_mut() {
        *x = x.to_le();
    }
    arr
}

// Convert from little-endian u32 array. Only reinterprettation on LE machines.
fn arr_to_bigint(mut arr: [u32; bigint::WIDTH_WORDS]) -> U256 {
    for x in arr.iter_mut() {
        *x = x.to_le();
    }
    U256::from_le_bytes(bytemuck::cast(arr))
}

impl BigIntTestCase {
    pub fn new(
        x: [u32; bigint::WIDTH_WORDS],
        y: [u32; bigint::WIDTH_WORDS],
        modulus: [u32; bigint::WIDTH_WORDS],
    ) -> Self {
        Self {
            x,
            y,
            modulus,
            expected: Self::expected(
                &arr_to_bigint(x),
                &arr_to_bigint(y),
                &arr_to_bigint(modulus),
            ),
        }
    }

    pub fn expected(x: &U256, y: &U256, n: &U256) -> [u32; bigint::WIDTH_WORDS] {
        // Compute modular multiplication, or simply multiplication if n == 0.
        let z: U256 = if n == &U256::ZERO {
            x.checked_mul(&y).unwrap()
        } else {
            let (z, valid) = U256::const_rem_wide(x.mul_wide(&y), &n);
            assert!(bool::from(valid));
            z
        };

        bigint_to_arr(&z)
    }

    // NOTE: Testing here could be significantly improved by creating a less uniform
    // test case generator. It is likely more important to test inputs of different
    // byte-lengths, with zero and 0xff bytes, and other boundary values than
    // testing values in the middle.
    fn sample(rng: &mut impl CryptoRngCore) -> BigIntTestCase {
        let modulus = NonZero::<U256>::random(rng);
        let mut x = U256::random(rng);
        let mut y = U256::random_mod(rng, &modulus);

        // x and y come from slightly different ranges because at least one input must
        // be less than the modulus, but it doesn't matter which one. Randomly swap.
        if (rng.next_u32() & 1) == 0 {
            mem::swap(&mut x, &mut y);
        }

        Self {
            x: bigint_to_arr(&x),
            y: bigint_to_arr(&y),
            modulus: bigint_to_arr(modulus.as_ref()),
            expected: Self::expected(&x, &y, modulus.as_ref()),
        }
    }
}

/// Generate the test cases for the BigInt accelerator circuit that are applied
/// to both the simulator and circuit implementations.
pub fn generate_bigint_test_cases(
    rng: &mut impl CryptoRngCore,
    rand_count: usize,
) -> Vec<BigIntTestCase> {
    let zero = [0, 0, 0, 0, 0, 0, 0, 0];
    let one = [1, 0, 0, 0, 0, 0, 0, 0];

    let mut cases = vec![
        BigIntTestCase::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            [9, 10, 11, 12, 13, 14, 15, 16],
            [17, 18, 19, 20, 21, 22, 23, 24],
        ),
        BigIntTestCase::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            zero,
            [17, 18, 19, 20, 21, 22, 23, 24],
        ),
        BigIntTestCase::new(
            [1, 2, 3, 4, 5, 6, 7, 8],
            one,
            [17, 18, 19, 20, 21, 22, 23, 24],
        ),
        BigIntTestCase::new(
            one,
            [9, 10, 11, 12, 13, 14, 15, 16],
            [1, 2, 3, 4, 5, 6, 7, 8],
        ),
        BigIntTestCase::new([1, 2, 3, 4, 0, 0, 0, 0], [9, 10, 11, 12, 0, 0, 0, 0], zero),
    ];

    cases.extend((0..rand_count).map(|_| BigIntTestCase::sample(rng)));
    cases
}
