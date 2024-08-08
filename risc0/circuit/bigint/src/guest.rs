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

use crate::{
    byte_poly::BytePoly, BigIntClaim, BigIntContext, BigIntProgram, CHECKED_COEFFS_PER_POLY,
};
use anyhow::Result;
use num_bigint::BigUint;
use risc0_binfmt::Digestible;
use risc0_zkp::{
    core::{digest::DIGEST_WORDS, hash::poseidon2::Poseidon2HashSuite},
    field::Elem,
};
use risc0_zkvm::{guest::env, guest::sha::Impl as Sha256};
use risc0_zkvm_platform::syscall;
use tracing::trace;

#[stability::unstable]
pub fn prove(claim: &BigIntClaim, prog: &BigIntProgram) -> Result<()> {
    let mut ctx = BigIntContext::default();
    ctx.in_values = claim
        .public_witness
        .iter()
        .map(|val| BigUint::from(val))
        .collect();

    let claim_digest = claim.digest::<Sha256>();
    trace!("claim_digest: {claim_digest:?}");

    let hash_suite = Poseidon2HashSuite::new_suite();

    env::run_unconstrained(|| {
        (prog.unconstrained_eval_fn)(&mut ctx).unwrap();

        // Calculate the evaluation point Z

        let mut all_coeffs: Vec<u32> = Vec::new();
        for witness in ctx
            .constant_witness
            .iter()
            .chain(ctx.public_witness.iter())
            .chain(ctx.private_witness.iter())
        {
            for chunk in witness.chunks(CHECKED_COEFFS_PER_POLY) {
                let mut bytes: Vec<u8> = chunk
                    .iter()
                    .map(|b| u8::try_from(*b).expect("Byte out of range in witness coeffs"))
                    .collect();
                while bytes.len() < CHECKED_COEFFS_PER_POLY {
                    bytes.push(0);
                }

                for word in bytes.chunks(4) {
                    all_coeffs.push(u32::from_le_bytes(
                        word.try_into().expect("Partial word present in witness?"),
                    ));
                }
            }
        }

        let public_digest = BytePoly::compute_digest(&*hash_suite.hashfn, &ctx.public_witness, 1);
        let private_digest = BytePoly::compute_digest(&*hash_suite.hashfn, &ctx.private_witness, 3);
        let folded = (&*hash_suite.hashfn).hash_pair(&public_digest, &private_digest);
        trace!("folded: {folded}");

        let mut rng = (&*hash_suite.rng).new_rng();
        rng.mix(&folded);
        let z = rng.random_ext_elem();
        let z_u32s = z.to_u32_words();

        trace!("evaluation point: {z:?}");

        let mut input: Vec<u32> =
            Vec::with_capacity(DIGEST_WORDS + z_u32s.len() + all_coeffs.len());
        input.extend(prog.control_root.as_words());
        input.extend(z_u32s);
        input.extend(all_coeffs);

        unsafe {
            syscall::sys_execute_zkr(prog.control_id.as_ref(), input.as_ptr(), input.len());
        }
    });

    env::verify_assumption(claim_digest, prog.control_root)?;

    Ok(())
}
