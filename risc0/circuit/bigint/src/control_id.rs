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

use risc0_zkp::{core::digest::Digest, digest};

// TODO: Automatically calculate these.

// Control IDs for hashfn=poseidon2, po2=BIGINT_PO2 for all ZKRs we generate code for
pub const RSA_256_CONTROL_ID: Digest =
    digest!("4fa2a31647175a43fd600f16fd070843a00da7120e3c62023737ca20a640e753");
pub const RSA_3072_CONTROL_ID: Digest =
    digest!("1e84eb17928d5e02a0d8c71fded7381c0405e84f76c0ea3ffc8a402853fcc12f");

// Control group merkle tree roots for merkle trees that contain only one entry, namely the referenced bigint program.
pub const RSA_256_CONTROL_ROOT: Digest =
    digest!("d9b4b7081463a70351b3035dfee2b310a3304e4ad9af6c68bbe4b557d9ab6c40");
pub const RSA_3072_CONTROL_ROOT: Digest =
    digest!("d7c33418b39319049ad58b343a03eb5339ffaa436c46081338cbf4768d97c20b");
