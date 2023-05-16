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

#![no_std]
#![no_main]

use crypto_bigint::{const_residue, impl_modulus, modular::constant_mod::ResidueParams, U256};

risc0_zkvm::entry!(main);

// Copied from crypto-bigint src/uint/modular/constant_mod/const_pow.rs
// DO NOT MERGE(victor): Include proper attribution.

impl_modulus!(
    InvModulus,
    U256,
    "15477BCCEFE197328255BFA79A1217899016D927EF460F4FF404029D24FA4409"
);

fn test_self_inverse() {
    let x = U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");
    let x_mod = const_residue!(x, InvModulus);

    let (inv, is_some) = x_mod.invert();
    assert!(bool::from(is_some));
    let res = &x_mod * &inv;

    assert_eq!(res.retrieve(), U256::ONE);
}

impl_modulus!(
    PowModulus,
    U256,
    "9CC24C5DF431A864188AB905AC751B727C9447A8E99E6366E1AD78A21E8D882B"
);

fn test_powmod_small_base() {
    let base = U256::from(105u64);
    let base_mod = const_residue!(base, PowModulus);

    let exponent =
        U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");

    let res = base_mod.pow(&exponent);

    let expected =
        U256::from_be_hex("7B2CD7BDDD96C271E6F232F2F415BB03FE2A90BD6CCCEA5E94F1BFD064993766");
    assert_eq!(res.retrieve(), expected);
}

fn test_powmod_small_exponent() {
    let base =
        U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
    let base_mod = const_residue!(base, PowModulus);

    let exponent = U256::from(105u64);

    let res = base_mod.pow(&exponent);

    let expected =
        U256::from_be_hex("89E2A4E99F649A5AE2C18068148C355CA927B34A3245C938178ED00D6EF218AA");
    assert_eq!(res.retrieve(), expected);
}

fn test_powmod() {
    let base =
        U256::from_be_hex("3435D18AA8313EBBE4D20002922225B53F75DC4453BB3EEC0378646F79B524A4");
    let base_mod = const_residue!(base, PowModulus);

    let exponent =
        U256::from_be_hex("77117F1273373C26C700D076B3F780074D03339F56DD0EFB60E7F58441FD3685");

    let res = base_mod.pow(&exponent);

    let expected =
        U256::from_be_hex("3681BC0FEA2E5D394EB178155A127B0FD2EF405486D354251C385BDD51B9D421");
    assert_eq!(res.retrieve(), expected);
}

pub fn main() {
    test_self_inverse();
    test_powmod_small_base();
    test_powmod_small_exponent();
    test_powmod();
}
