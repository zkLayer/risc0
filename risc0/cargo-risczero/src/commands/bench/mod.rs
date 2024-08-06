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

use std::{
    collections::BTreeMap,
    hint::black_box,
    path::PathBuf,
    time::{Duration, Instant},
};

use ::serde::Serialize;
use anyhow::Result;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, Prover, ProverOpts};
use serde_with::{serde_as, DurationSeconds};
use tabled::{
    settings::{Concat, Style},
    Table, Tabled,
};

// TODO: Get RAM use and page-in count from prover.
// TODO: Ask prover to simply execute.
// TODO: Ask prover to lift & join.

/// `cargo risczero bench`
#[derive(clap::Parser)]
#[non_exhaustive]
pub struct BenchCommand {
    #[arg(long, name = "PATH")]
    pub json: Option<PathBuf>,
}

impl BenchCommand {
    pub fn run(&self) -> Result<()> {
        // Get a prover backed by Bonsai, r0vm, or the current process.
        let prover: &dyn Prover = &*risc0_zkvm::default_prover();

        // Benchmark data grouped by benchmark name.
        let mut results: BTreeMap<&str, Vec<BenchData>> = BTreeMap::new();
        let mut push_result = |(name, data)| {
            results.entry(name).or_default().push(data);
        };

        // The buffer containing the loop ELF's binary data as 32-bit words.
        // This is patched on each access to change the loop iteration count.
        let mut elf_words: Box<[u32]> = elf::LOOP_ELF_WORDS.into();

        /// Returns an ELF that loops `$iter_count` times.
        ///
        /// This patches the instructions of the local `elf_words` buffer to
        /// loop `$count` times, and then returns the ELF buffer as `&[u8]`.
        ///
        /// This is a macro instead of a closure due to limitations around
        /// captures of mutable borrows.
        macro_rules! get_loop_elf {
            ($iter_count:expr) => {
                elf::patch_loop_elf(&mut elf_words, $iter_count)
            };
        }

        // Run warmup prior to proving to ensure GPU kernels are compiled and
        // ready to use.
        println!("warmup");
        _ = black_box(prover.prove_with_opts(
            ExecutorEnv::default(),
            get_loop_elf!(0),
            &ProverOpts::succinct(),
        )?);

        // Benchmark execution without proving.
        let execute_iters = 128 * 1024;
        push_result(benches::execute(
            execute_iters,
            get_loop_elf!(execute_iters),
        )?);

        // Benchmark proving with composite receipt.
        for hashfn in ["sha-256", "poseidon2"] {
            for iters in [
                1,         // 16, 64K
                4 * 1024,  // 17, 128K
                16 * 1024, // 18, 256K
                32 * 1024, // 19, 512K
                64 * 1024, // 20, 1M
            ] {
                push_result(benches::composite_receipt(
                    prover,
                    hashfn,
                    iters,
                    get_loop_elf!(iters),
                )?);
            }
        }

        // Benchmark proving with succinct receipt.
        let succinct_iters = 64 * 1024;
        push_result(benches::succinct_receipt(
            prover,
            succinct_iters,
            get_loop_elf!(succinct_iters),
        )?);

        // Emit results as pretty table.
        print_table(&results);

        // Emit results as JSON if requested.
        if let Some(json_path) = &self.json {
            let json = serde_json::to_string_pretty(&results)?;

            if let Some(parent_dir) = json_path.parent() {
                std::fs::create_dir_all(parent_dir)?;
            }

            std::fs::write(json_path, json)?;
        }

        Ok(())
    }
}

fn print_table(results: &BTreeMap<&str, Vec<BenchData>>) {
    // Names of benchmarks for each `PerformanceData` entry.
    let names_column = {
        #[derive(Tabled)]
        struct Name<'a> {
            name: &'a str,
        }

        results
            .iter()
            .flat_map(|(name, data)| data.iter().map(|_| Name { name }))
    };

    let data_columns = results.values().flat_map(|data| data.iter());

    println!(
        "{}",
        Table::new(names_column)
            .with(Concat::horizontal(Table::new(data_columns)))
            .with(Style::modern())
    );
}

#[serde_as]
#[derive(Debug, Serialize, Tabled)]
struct BenchData {
    hashfn: String,

    /// Cycles per second.
    #[tabled(display_with = "display::hertz")]
    throughput: f64,

    #[serde_as(as = "DurationSeconds")]
    #[tabled(display_with = "display::duration")]
    duration: Duration,

    /// Either user execution cycle count or the total cycle count.
    ///
    /// When this is the total cycle count, it includes overhead associated with
    /// continuations and padding up to the nearest power of 2.
    #[tabled(display_with = "display::cycles")]
    cycles: u64,

    #[tabled(display_with = "display::bytes")]
    ram: u64,

    #[tabled(display_with = "display::bytes")]
    seal: u64,
}

/// Benchmark implementations.
mod benches {
    use super::*;

    type BenchResult = Result<(&'static str, BenchData)>;

    pub fn execute(iters: u32, elf: &[u8]) -> BenchResult {
        println!("execute: {iters}");

        // TODO: This should be via `Prover`, not `ExecutorImpl`.
        let env = ExecutorEnv::default();
        let (session, duration) = try_time(|| {
            // NOTE: Also time `ExecutorImpl::from_elf` constructor since proof
            // benchmarks also time it.
            ExecutorImpl::from_elf(env, elf)?.run()
        })?;

        // NOTE: We use user cycles as the total because there is no proving.
        let cycles = session.user_cycles;

        Ok((
            "execute",
            BenchData {
                hashfn: "N/A".into(),
                throughput: cycles as f64 / duration.as_secs_f64(),
                duration,
                cycles,
                ram: 0,
                seal: 0,
            },
        ))
    }

    pub fn composite_receipt(
        prover: &dyn Prover,
        hashfn: &str,
        iters: u32,
        elf: &[u8],
    ) -> BenchResult {
        println!("rv32im ({hashfn}): {iters}");

        let opts = ProverOpts::default().with_hashfn(hashfn.to_string());
        let env = ExecutorEnv::default();
        let (info, duration) = try_time(|| prover.prove_with_opts(env, elf, &opts))?;

        // TODO: Make prover responsible for tracking RAM, perhaps in `SessionStats`.
        let ram = 0;

        let cycles = info.stats.total_cycles;

        Ok((
            "rv32im",
            BenchData {
                hashfn: hashfn.into(),
                seal: info.receipt.inner.composite()?.seal_size() as u64,
                throughput: cycles as f64 / duration.as_secs_f64(),
                duration,
                cycles,
                ram,
            },
        ))
    }

    pub fn succinct_receipt(prover: &dyn Prover, iters: u32, elf: &[u8]) -> BenchResult {
        println!("succinct: {iters}");

        let opts = ProverOpts::succinct();
        let env = ExecutorEnv::default();
        let (info, duration) = try_time(|| prover.prove_with_opts(env, elf, &opts))?;

        // TODO: Make prover responsible for tracking RAM, perhaps in `SessionStats`.
        let ram = 0;

        let cycles = info.stats.total_cycles;

        Ok((
            "succinct",
            BenchData {
                hashfn: opts.hashfn,
                seal: info.receipt.inner.succinct()?.seal_size() as u64,
                throughput: cycles as f64 / duration.as_secs_f64(),
                duration,
                cycles,
                ram,
            },
        ))
    }

    /// Measures the duration for executing `operation` once.
    fn time<T>(mut operation: impl FnOnce() -> T) -> (T, Duration) {
        // Make inputs opaque to the optimizer.
        operation = black_box(operation);

        let start = Instant::now();
        let mut output = operation();
        let duration = start.elapsed();

        // Make optimizer believe output is used.
        output = black_box(output);

        (output, duration)
    }

    /// Measures the duration for executing a fallible `operation` once.
    fn try_time<T>(operation: impl FnOnce() -> Result<T>) -> Result<(T, Duration)> {
        let (result, duration) = time(operation);
        Ok((result?, duration))
    }
}

/// Contains the loop ELF and utilities for patching the iteration count.
///
/// The loop ELF is located at `loop.bin`, which is compiled from `loop.s`. We
/// keep the pre-compiled binary checked into the repo since we can't assume
/// that `riscv32-unknown-elf-gcc` will be available when this crate is built.
///
/// The iteration count is provided by patching the ELF because this is much
/// simpler than providing it through `ExecutorEnv` and reading it from the
/// guest's environment.
mod elf {
    /// Converts a `&[u8; N]` constant into `&[u32; N / 4]`.
    ///
    /// This fails to compile if the number of bytes is not a multiple of 4.
    macro_rules! u32_array_from_bytes {
        ($bytes:expr) => {{
            const _BYTES: &[u8] = $bytes;

            {
                const RESULT: &[u32; _BYTES.len() / 4] = &unsafe {
                    let bytes: [u8; _BYTES.len()] = *_BYTES.as_ptr().cast();
                    ::std::mem::transmute(bytes)
                };

                RESULT
            }
        }};
    }

    /// The base loop ELF binary to be patched.
    pub const LOOP_ELF_WORDS: &[u32] = u32_array_from_bytes!(include_bytes!("loop.bin"));

    /// Overwrites the ELF's instructions for setting the loop iteration count
    /// and returns the patched ELF as bytes.
    pub fn patch_loop_elf(elf_words: &mut [u32], iter_count: u32) -> &[u8] {
        let [lui_a5, addi_a5] = enc_load_u32(Reg::A5, iter_count);

        elf_words[LOOP_ELF_INDEXES.lui_a5] = lui_a5;
        elf_words[LOOP_ELF_INDEXES.addi_a5] = addi_a5;

        bytemuck::cast_slice(elf_words)
    }

    struct ElfIndexes {
        lui_a5: usize,
        addi_a5: usize,
    }

    /// Indexes into `LOOP_ELF_WORDS` for patched instructions.
    const LOOP_ELF_INDEXES: ElfIndexes = {
        let mut result = ElfIndexes {
            lui_a5: usize::MAX,
            addi_a5: usize::MAX,
        };

        // Iterate through the ELF to find indexes to patch.
        let mut i = 0;
        while i < LOOP_ELF_WORDS.len() {
            let word = LOOP_ELF_WORDS[i];

            match word.to_le() {
                // lui a5, 0xfffff
                0xfffff7b7 => result.lui_a5 = i,

                // addi a5, a5, -1
                0xfff78793 => result.addi_a5 = i,

                _ => {}
            }

            i += 1;
        }

        if result.lui_a5 == usize::MAX {
            panic!("Could not find `lui a5, 0xfffff` (0xfffff7b7)");
        }

        if result.addi_a5 == usize::MAX {
            panic!("Could not find `addi a5, a5, -1` (0xfff78793)");
        }

        result
    };

    /// RISC-V register.
    #[derive(Clone, Copy)]
    enum Reg {
        A5 = 0b01111,
    }

    /// Encodes a pair of `lui` (Load Upper Imm) and `addi` (ADD Immediate)
    /// instructions for loading a 32-bit value into the given register.
    ///
    /// This is based off the instruction encoding for setting all 32 bits:
    /// - 0xfffff7b7: lui  a5, 0xfffff
    /// - 0xfff78793: addi a5, a5, -1
    fn enc_load_u32(reg: Reg, val: u32) -> [u32; 2] {
        // Decompose value into high 20 bits and low 12 bits:
        let val_hi = val & 0xfffff000;
        let val_lo = val & 0xfff;

        // Encode register in `rd` and `rs1` offsets:
        let out_reg = (reg as u32) << 7;
        let in_reg = (reg as u32) << 15;

        // `lui` clears the register and sets the high 20 bits, which is also
        // encoded in the instruction at the high 20 bits.
        let lui = 0b0110111 | out_reg | val_hi;

        // `addi` adds a 12-bit immediate value, which is encoded in the
        // instruction at the high 12 bits.
        let addi = 0b0010011 | out_reg | in_reg | (val_lo << 20);

        [lui, addi]
    }
}

/// Utilities to make data human-readable for displaying in a table.
mod display {
    use human_repr::*;

    use super::*;

    pub fn bytes(bytes: &u64) -> String {
        if *bytes == 0 {
            return "N/A".into();
        }
        bytes.human_count_bytes().to_string()
    }

    pub fn cycles(cycles: &u64) -> String {
        cycles.human_count_bare().to_string()
    }

    pub fn duration(duration: &Duration) -> String {
        duration.human_duration().to_string()
    }

    pub fn hertz(hertz: &f64) -> String {
        hertz.human_count("Hz").to_string()
    }
}
