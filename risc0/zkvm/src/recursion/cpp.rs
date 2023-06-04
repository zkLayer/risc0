// Copyright (c) 2023 RISC Zero, Inc.
//
// All rights reserved.

use anyhow::Result;
use risc0_zkp::{
    adapter::{CircuitDef, CircuitStep, CircuitStepContext, CircuitStepHandler, PolyFp},
    field::baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
    hal::cpu::SyncSlice,
};
//use risc0_zkvm::recursion::CircuitImpl;
use crate::recursion::CircuitImpl;

use crate::recursion::ffi::{
    call_step, risc0_circuit_recursion_poly_fp, risc0_circuit_recursion_step_compute_accum,
    risc0_circuit_recursion_step_exec, risc0_circuit_recursion_step_verify_accum,
    risc0_circuit_recursion_step_verify_bytes, risc0_circuit_recursion_step_verify_mem,
};

impl CircuitStep<BabyBearElem> for CircuitImpl {
    fn step_compute_accum<S: CircuitStepHandler<BabyBearElem>>(
        &self,
        ctx: &CircuitStepContext,
        handler: &mut S,
        args: &[SyncSlice<BabyBearElem>],
    ) -> Result<BabyBearElem> {
        call_step(
            ctx,
            handler,
            args,
            |err, ctx, trampoline, size, cycle, args_ptr, args_len| unsafe {
                risc0_circuit_recursion_step_compute_accum(
                    err, ctx, trampoline, size, cycle, args_ptr, args_len,
                )
            },
        )
    }

    fn step_verify_accum<S: CircuitStepHandler<BabyBearElem>>(
        &self,
        ctx: &CircuitStepContext,
        handler: &mut S,
        args: &[SyncSlice<BabyBearElem>],
    ) -> Result<BabyBearElem> {
        call_step(
            ctx,
            handler,
            args,
            |err, ctx, trampoline, size, cycle, args_ptr, args_len| unsafe {
                risc0_circuit_recursion_step_verify_accum(
                    err, ctx, trampoline, size, cycle, args_ptr, args_len,
                )
            },
        )
    }

    fn step_exec<S: CircuitStepHandler<BabyBearElem>>(
        &self,
        ctx: &CircuitStepContext,
        handler: &mut S,
        args: &[SyncSlice<BabyBearElem>],
    ) -> Result<BabyBearElem> {
        call_step(
            ctx,
            handler,
            args,
            |err, ctx, trampoline, size, cycle, args_ptr, args_len| unsafe {
                risc0_circuit_recursion_step_exec(
                    err, ctx, trampoline, size, cycle, args_ptr, args_len,
                )
            },
        )
    }

    fn step_verify_bytes<S: CircuitStepHandler<BabyBearElem>>(
        &self,
        ctx: &CircuitStepContext,
        handler: &mut S,
        args: &[SyncSlice<BabyBearElem>],
    ) -> Result<BabyBearElem> {
        call_step(
            ctx,
            handler,
            args,
            |err, ctx, trampoline, size, cycle, args_ptr, args_len| unsafe {
                risc0_circuit_recursion_step_verify_bytes(
                    err, ctx, trampoline, size, cycle, args_ptr, args_len,
                )
            },
        )
    }

    fn step_verify_mem<S: CircuitStepHandler<BabyBearElem>>(
        &self,
        ctx: &CircuitStepContext,
        handler: &mut S,
        args: &[SyncSlice<BabyBearElem>],
    ) -> Result<BabyBearElem> {
        call_step(
            ctx,
            handler,
            args,
            |err, ctx, trampoline, size, cycle, args_ptr, args_len| unsafe {
                risc0_circuit_recursion_step_verify_mem(
                    err, ctx, trampoline, size, cycle, args_ptr, args_len,
                )
            },
        )
    }
}

impl PolyFp<BabyBear> for CircuitImpl {
    fn poly_fp(
        &self,
        cycle: usize,
        steps: usize,
        mix: &BabyBearExtElem,
        args: &[&[BabyBearElem]],
    ) -> BabyBearExtElem {
        let args: Vec<*const BabyBearElem> = args.iter().map(|x| (*x).as_ptr()).collect();
        unsafe {
            risc0_circuit_recursion_poly_fp(
                cycle,
                steps,
                mix as *const BabyBearExtElem,
                args.as_ptr(),
                args.len(),
            )
        }
    }
}

impl<'a> CircuitDef<BabyBear> for CircuitImpl {}
