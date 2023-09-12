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

//! The prorata host is a command-line tool that can be used to compute
//! allocations and verify receipts.

use tfhe::{ConfigBuilder, generate_keys, FheUint8};
use tfhe::prelude::*;
use fhe_methods::{FHE_GUEST_ELF, FHE_GUEST_ID};
use fhe_core::KeyAndValues;
use risc0_zkvm::{
    default_prover,
    serde::{from_slice, to_vec},
    ExecutorEnv,
};

fn main() {
    // Obtain the default prover.
    let prover = default_prover();

    println!("Prover created");

    // Produce a receipt by proving the specified ELF binary.
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    println!("Config created");

    // Client-side
    let (client_key, server_key) = generate_keys(config);
    println!("Keys generated");

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);
    println!("Encrypted values");

    let input = KeyAndValues {
        server_key,
        a,
        b
    };

    let env = ExecutorEnv::builder()
        .add_input(
            &to_vec(&bincode::serialize(&input).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    println!("Env created");
    let receipt = prover.prove_elf(env, FHE_GUEST_ELF).expect("Failed to prove ELF");
    println!("Receipt created");

    //Client-side
    let result  = &from_slice::<FheUint8, _>(&receipt.journal).expect("Failed to deserialize journal");
    let decrypted_result: u8 = result.decrypt(&client_key);
    println!("Decrypted result: {}", decrypted_result);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);

    println!("Result verified");
    // Verify receipt to confirm that it is correctly formed. Not strictly
    // necessary.
    receipt.verify(FHE_GUEST_ID).expect("Failed to verify receipt");
    println!("Receipt verified");
}
