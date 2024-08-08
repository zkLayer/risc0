// Copyright 2024 RISC Zero, Inc.
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

use crate::{BigIntClaim, BigIntProgram, BytePoly};
use num_bigint::BigUint;

// Re-export program info
#[stability::unstable]
#[allow(unused_imports)] // Needed for stability::unstable
pub use crate::generated::{RSA_256, RSA_3072};

/// Construct a bigint claim that (S^e = M (mod N)), where e = 65537.
#[stability::unstable]
pub fn claim(prog_info: &BigIntProgram, n: BigUint, s: BigUint, m: BigUint) -> BigIntClaim {
    let pub_witness: Vec<BytePoly> = [n, s, m]
        .into_iter()
        .zip(prog_info.witness_info.iter())
        .map(|(val, wit_info)| BytePoly::from_biguint(val, wit_info.coeffs()))
        .collect();
    BigIntClaim::new(pub_witness)
}
