use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Result};
use crypto_bigint::{CheckedMul, Encoding, NonZero, U256, U512};
use risc0_zkvm_platform::{
    syscall::{
        bigint, ecall, halt,
        reg_abi::{REG_A0, REG_A1, REG_A2, REG_A3, REG_A4, REG_T0},
    },
    PAGE_SIZE, WORD_SIZE,
};

use super::SyscallRecord;
use crate::{
    align_up,
    sha::{BLOCK_BYTES, BLOCK_WORDS, DIGEST_WORDS},
    ExecutorEnv, ExitCode, SyscallContext,
};
/// The number of cycles required to compress a SHA-256 block.
const SHA_CYCLES: usize = 72;

/// Number of cycles required to complete a BigInt operation.
const BIGINT_CYCLES: usize = 9;

#[derive(Default, Debug)]
pub struct ECallRecord {
    pub page_loads: BTreeSet<u32>,
    pub ram_writes: Vec<(u32, u32)>,
    pub reg_writes: Vec<(usize, u32)>,
    pub syscall: Option<SyscallRecord>,
    pub exit_code: Option<ExitCode>,
    pub cycles: usize,
}

struct ECallExecutor<'a, C: SyscallContext> {
    // TODO: Make it so SyscallContext doesn't need to be mut
    ctx: &'a C,
    exec: ECallRecord,
}

pub fn exec_ecall(ctx: &impl SyscallContext, env: &ExecutorEnv) -> Result<ECallRecord> {
    let reg = ctx.load_register(REG_T0);
    log::trace!("Ecall {reg:#x}");
    let mut ecall = ECallExecutor {
        ctx,
        exec: ECallRecord::default(),
    };
    match reg {
        ecall::HALT => ecall.do_halt(),
        ecall::INPUT => ecall.do_input(),
        ecall::SOFTWARE => ecall.do_software(env),
        ecall::SHA => ecall.do_sha(),
        ecall::BIGINT => ecall.do_bigint(),
        ecall => bail!("Unknown ecall {ecall:#x}"),
    }?;
    Ok(ecall.exec)
}

impl<'a, C: SyscallContext> ECallExecutor<'a, C> {
    fn load_registers<const N: usize>(&self, idxs: [usize; N]) -> [u32; N] {
        idxs.map(|idx| self.ctx.load_register(idx))
    }

    fn load_ram_words(&mut self, addr: u32, len: usize) -> Vec<u32> {
        if len != 0 {
            let first_idx = addr / PAGE_SIZE as u32;
            let last_idx = (addr + (len * WORD_SIZE) as u32 - 1) / PAGE_SIZE as u32;
            self.exec.page_loads.extend(first_idx..=last_idx);
        }

        (0..len)
            .map(|i| self.ctx.load_u32(addr + (i * WORD_SIZE) as u32))
            .collect()
    }
    fn load_ram(&mut self, addr: u32, len: usize) -> Vec<u8> {
        if len != 0 {
            if len != 0 {
                let first_idx = addr / PAGE_SIZE as u32;
                let last_idx = (addr + len as u32 - 1) / PAGE_SIZE as u32;
                self.exec.page_loads.extend(first_idx..=last_idx);
            }
        }

        self.ctx.load_region(addr, len as u32)
    }

    fn store_ram_words(&mut self, addr: u32, words: &[u32]) {
        self.exec.ram_writes.extend(
            words
                .iter()
                .enumerate()
                .map(|(i, word)| (addr + (i * WORD_SIZE) as u32, *word)),
        )
    }

    fn store_register(&mut self, reg: usize, word: u32) {
        self.exec.reg_writes.push((reg, word))
    }

    fn use_cycles(&mut self, cycles: usize) {
        self.exec.cycles += cycles
    }

    fn store_u32(&mut self, addr: u32, word: u32) {
        self.store_ram_words(addr, &[word])
    }

    fn do_halt(&mut self) -> Result<()> {
        let [tot_reg, output_ptr] = self.load_registers([REG_A0, REG_A1]);
        let halt_type = tot_reg & 0xff;
        let user_exit = (tot_reg >> 8) & 0xff;

        self.exec.exit_code = Some(match halt_type {
            halt::TERMINATE => ExitCode::Halted(user_exit),
            halt::PAUSE => ExitCode::Paused(user_exit),
            _ => bail!("Illegal halt type: {halt_type}"),
        });

        self.load_ram_words(output_ptr, DIGEST_WORDS);
        Ok(())
    }

    fn do_input(&mut self) -> Result<()> {
        log::debug!("ecall(input)");
        let [iin_addr] = self.load_registers([REG_A0]);
        self.load_ram_words(iin_addr, DIGEST_WORDS);
        Ok(())
    }

    fn do_sha(&mut self) -> Result<()> {
        let [out_state_ptr, in_state_ptr, mut block1_ptr, mut block2_ptr, count] =
            self.load_registers([REG_A0, REG_A1, REG_A2, REG_A3, REG_A4]);

        let in_state = self.load_ram_words(in_state_ptr, DIGEST_WORDS);
        let mut state: [u32; DIGEST_WORDS] = core::array::from_fn(|i| in_state[i].to_be());

        log::debug!("Initial sha state: {state:08x?}");
        for _ in 0..count {
            let mut block = [0u32; BLOCK_WORDS];
            block[..DIGEST_WORDS].clone_from_slice(&self.load_ram_words(block1_ptr, DIGEST_WORDS));
            block[DIGEST_WORDS..].clone_from_slice(&self.load_ram_words(block2_ptr, DIGEST_WORDS));
            log::debug!("Compressing block {block:02x?}");
            sha2::compress256(
                &mut state,
                &[*generic_array::GenericArray::from_slice(
                    bytemuck::cast_slice(&block),
                )],
            );
            block1_ptr += BLOCK_BYTES as u32;
            block2_ptr += BLOCK_BYTES as u32;
            self.use_cycles(SHA_CYCLES);
        }
        log::debug!("Final sha state: {state:08x?}");

        for word in &mut state {
            *word = u32::from_be(*word);
        }
        self.store_ram_words(out_state_ptr, &state);
        Ok(())
    }

    // Computes the state transitions for the BIGINT ecall.
    // Take reads inputs x, y, and N and writes output z = x * y mod N.
    // Note that op is currently ignored but must be set to 0.
    fn do_bigint(&mut self) -> Result<()> {
        let [z_ptr, op, x_ptr, y_ptr, n_ptr] =
            self.load_registers([REG_A0, REG_A1, REG_A2, REG_A3, REG_A4]);

        self.use_cycles(BIGINT_CYCLES);
        let mut load_bigint_le_bytes = |ptr: u32| -> [u8; bigint::WIDTH_BYTES] {
            let be_in = self.load_ram_words(ptr, bigint::WIDTH_WORDS);
            let mut arr = [0u32; bigint::WIDTH_WORDS];
            for i in 0..bigint::WIDTH_WORDS {
                arr[i] = be_in[i].to_le();
            }
            bytemuck::cast(arr)
        };

        if op != 0 {
            anyhow::bail!("ecall_bigint preflight: op must be set to 0");
        }

        // Load inputs.
        let x = U256::from_le_bytes(load_bigint_le_bytes(x_ptr));
        let y = U256::from_le_bytes(load_bigint_le_bytes(y_ptr));
        let n = U256::from_le_bytes(load_bigint_le_bytes(n_ptr));

        // Compute modular multiplication, or simply multiplication if n == 0.
        let z: U256 = if n == U256::ZERO {
            x.checked_mul(&y).unwrap()
        } else {
            let (w_lo, w_hi) = x.mul_wide(&y);
            let w = w_hi.concat(&w_lo);
            let z = w.rem(&NonZero::<U512>::from_uint(n.resize()));
            z.resize()
        };

        // Store result.
        for (i, word) in bytemuck::cast::<_, [u32; bigint::WIDTH_WORDS]>(z.to_le_bytes())
            .into_iter()
            .enumerate()
        {
            self.store_u32(z_ptr + (i * WORD_SIZE) as u32, word.to_le());
        }

        Ok(())
    }

    fn do_software(&mut self, env: &ExecutorEnv) -> Result<()> {
        // ecall_software reads are all done by the host, so there's no need to page in
        // any of the pages it references.
        let [to_guest_ptr, to_guest_words, name_ptr] =
            self.load_registers([REG_A0, REG_A1, REG_A2]);
        // No need to record RAM loads; this is all done in the host.
        let syscall_name = self.ctx.load_string(name_ptr)?;
        log::trace!("Guest called syscall {syscall_name:?} requesting {to_guest_words} words back");

        let chunks = align_up(to_guest_words as usize, WORD_SIZE);
        self.use_cycles(chunks + 2);
        let mut to_guest = vec![0; to_guest_words as usize];

        let handler = env
            .get_syscall(&syscall_name)
            .ok_or(anyhow!("Unknown syscall: {syscall_name:?}"))?;
        let (a0, a1) = (**handler)
            .borrow_mut()
            .syscall(&syscall_name, self.ctx, &mut to_guest)?;

        self.store_ram_words(to_guest_ptr, &to_guest);
        self.store_register(REG_A0, a0);
        self.store_register(REG_A1, a1);
        self.exec.syscall = Some(SyscallRecord {
            to_guest,
            regs: (a0, a1),
        });
        log::trace!("Syscall returned a0: {a0:#X}, a1: {a1:#X}, chunks: {chunks}");

        Ok(())
    }
}
