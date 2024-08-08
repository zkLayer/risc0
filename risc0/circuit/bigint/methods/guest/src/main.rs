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

use num_bigint::BigUint;
use risc0_circuit_bigint::rsa;
use risc0_zkvm::guest::env;

fn main() {
    // Read RSA input values
    let input: Vec<BigUint> = env::read();
    let [n, s, m]: [BigUint; 3] = input.try_into().unwrap();
    let rsa_claim = rsa::claim(&rsa::RSA_256, n, s, m);
    risc0_circuit_bigint::prove(
        &rsa_claim,
        &rsa::RSA_256,
    )
    .expect("Unable to compose with RSA");
}
