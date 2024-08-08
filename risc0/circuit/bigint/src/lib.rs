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

pub(crate) mod byte_poly;
mod codegen_prelude;
#[cfg(feature = "prove")]
pub mod zkr;

#[cfg(not(target_os = "zkvm"))]
mod host;
#[cfg(not(target_os = "zkvm"))]
#[allow(unused_imports)] // Needed for stability::unstable
pub use host::*;

#[cfg(target_os = "zkvm")]
mod guest;
#[cfg(target_os = "zkvm")]
#[allow(unused_imports)] // Needed for stability::unstable
pub use guest::*;

use byte_poly::{BytePoly, BITS_PER_COEFF};
use num_bigint::BigUint;
use risc0_binfmt::Digestible;
use risc0_circuit_recursion::CHECKED_COEFFS_PER_POLY;
use risc0_zkp::core::{digest::Digest, hash::sha::Sha256};

// PO2 to use to execute bigint ZKRs.
#[stability::unstable]
pub const BIGINT_PO2: usize = 18;

#[derive(Default, Debug)]
#[stability::unstable]
pub struct BigIntContext {
    pub in_values: Vec<BigUint>,

    pub constant_witness: Vec<BytePoly>,
    pub public_witness: Vec<BytePoly>,
    pub private_witness: Vec<BytePoly>,
}

/// Information about a big integer included in a bigint witness.
#[derive(Debug)]
#[stability::unstable]
pub struct WitnessInfo {
    pub bits: usize,
    pub label: usize,
    pub public: bool,
    pub min_bits: usize,
}

impl WitnessInfo {
    // Number of coefficients/field elements used by this bigint
    pub fn coeffs(&self) -> usize {
        const ROUND_WIDTH: usize = BITS_PER_COEFF * CHECKED_COEFFS_PER_POLY;
        let polys = self.bits.div_ceil(ROUND_WIDTH);
        polys * CHECKED_COEFFS_PER_POLY
    }
}

#[stability::unstable]
pub struct BigIntProgram<'a> {
    pub name: &'a str,
    pub witness_info: &'a [WitnessInfo],
    pub unconstrained_eval_fn: fn(&mut BigIntContext) -> anyhow::Result<()>,
    // Control ID of this program
    pub control_id: Digest,
    // Control root of a merkle tree with a single element containing control_id
    pub control_root: Digest,
}

pub mod rsa;

#[derive(Debug, Clone)]
#[stability::unstable]
pub struct BigIntClaim {
    pub public_witness: Vec<BytePoly>,
}

impl BigIntClaim {
    pub fn new(public_witness: Vec<BytePoly>) -> Self {
        BigIntClaim { public_witness }
    }
}

impl Digestible for BigIntClaim {
    fn digest<S: Sha256>(&self) -> Digest {
        let mut u32s: Vec<u32> = Vec::new();

        for wit in self.public_witness.iter() {
            u32s.extend(wit.clone().into_padded_u32s())
        }

        tracing::trace!("digest of {} u32s: {:x?}", u32s.len(), u32s);
        *S::hash_raw_data_slice(&u32s)
    }
}

pub(crate) mod generated {
    #![allow(dead_code)]
    #![allow(clippy::all)]

    use crate::codegen_prelude::*;
    include! {"bigint.rs.inc"}
}

pub(crate) mod control_id;

#[cfg(test)]
#[cfg(feature = "prove")]
mod rsa_tests;
