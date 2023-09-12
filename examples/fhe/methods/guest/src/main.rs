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

#![no_main]

use tfhe::set_server_key;
use fhe_core::KeyAndValues;

use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);

pub fn main() {
    env::log("Guest started");
    let raw: Vec<u8> = env::read();
    env::log("Guest read input");
    let KeyAndValues {
        server_key,
        a,
        b
    } = bincode::deserialize(&raw).unwrap();
    env::log("Guest deserialized input");

    set_server_key(server_key);
    env::log("Guest set server key");
    let result = a + b;
    env::log("Guest computed result");
    env::commit(&result);
    env::log("Guest committed result");
}
