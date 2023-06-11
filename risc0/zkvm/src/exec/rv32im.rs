#![allow(missing_docs)]
use anyhow::{bail, Result};
use log::trace;
const WORD_SIZE: u32 = risc0_zkvm_platform::WORD_SIZE as u32;

pub trait MachineState {
    fn load_ram(&self, addr: u32) -> u32;
    fn load_reg(&self, reg_idx: usize) -> u32;
}

#[derive(Debug)]
pub enum InstRecord {
    MemoryLoad {
        addr: u32,
        val: u32,
        reg: usize,
    },
    MemoryStore {
        addr: u32,
        val: u32,
    },
    RegisterStore {
        reg: usize,
        val: u32,
        new_pc: u32,
        cycles: usize,
    },
    ECall,
}

use InstRecord::*;

// Extract bits in the same way as the RISC-V isa specified: high bit first,

// range is inclusive.
#[track_caller]
const fn extract_bits(val: u32, highest_bit: usize, lowest_bit: usize) -> u32 {
    let nbits = highest_bit + 1 - lowest_bit;
    let mask = (!0) << nbits;
    (val >> lowest_bit) & !mask
}

/// Extract bits and sign extend.
#[track_caller]
const fn extract_bits_signed(val: u32, highest_bit: usize, lowest_bit: usize) -> i32 {
    let nbits = highest_bit - lowest_bit + 1;
    // First shift it up so the sign bit is in the top bit.
    let signed = (val << (31 - highest_bit)) as i32;
    signed >> (32 - nbits)
}

pub fn exec_rv32im(pc: u32, state: &impl MachineState) -> Result<InstRecord> {
    if pc & (WORD_SIZE - 1) != 0 {
        bail!("Unaligned program counter {pc:#08x}");
    }
    let inst = state.load_ram(pc);

    let bits = |highest_bit, lowest_bit| extract_bits(inst, highest_bit, lowest_bit);
    let bits_signed = |highest_bit, lowest_bit| extract_bits_signed(inst, highest_bit, lowest_bit);

    let opcode = bits(6, 0);
    let funct7 = bits(31, 25);
    let rs2reg = bits(24, 20) as usize;
    let rs1reg = bits(19, 15) as usize;
    let funct3 = bits(14, 12);
    let rd = bits(11, 7) as usize;

    use rrs_lib::instruction_string_outputter::InstructionStringOutputter;
    log::trace!(
        "{:?}",
        rrs_lib::process_instruction(&mut InstructionStringOutputter { insn_pc: 0 }, inst)
    );

    macro_rules! bail_ctx {
        ($msg:literal) => {
            bail!("{} pc={pc:#08x} inst={inst:#08b} funct3={funct3:#03b} funct7={funct7:#07b} opcode={opcode:#07b}", $msg)
        };
    }

    match opcode {
        0b0110011 => {
            // R-format arithmetic ops
            let rs1 = state.load_reg(rs1reg);
            let rs2 = state.load_reg(rs2reg);
            let set_rd = |mnemonic: &str, val: u32, cycles: usize| {
                trace!("{mnemonic} x{rs1reg} = {rs1:#08x}, x{rs2reg} = {rs2:#08x} -> x{rd} = {val:#08x}");
                Ok(RegisterStore {
                    reg: rd,
                    new_pc: pc + WORD_SIZE,
                    val,
                    cycles,
                })
            };
            match (funct3, funct7) {
                (0b000, 0b0000000) => set_rd("add", rs1.wrapping_add(rs2), 1),
                (0b000, 0b0000001) => set_rd("mul", rs1.wrapping_mul(rs2), 2),
                (0b000, 0b0100000) => set_rd("sub", rs1.wrapping_sub(rs2), 1),
                (0b001, 0b0000000) => set_rd("sll", rs1.wrapping_shl(rs2), 2),
                (0b010, 0b0000000) => set_rd("slt", ((rs1 as i32) < (rs2 as i32)) as u32, 1),
                (0b011, 0b0000000) => set_rd("sltu", (rs1 < rs2) as u32, 1),
                (0b101, 0b0000000) => set_rd("srl", rs1.wrapping_shr(rs2), 2),
                (0b100, 0b0000000) => set_rd("xor", rs1 ^ rs2, 2),
                (0b101, 0b0100000) => set_rd("sra", (rs1 as i32).wrapping_shr(rs2) as u32, 2),
                (0b110, 0b0000000) => set_rd("or", rs1 | rs2, 2),
                (0b111, 0b0000000) => set_rd("and", rs1 & rs2, 2),
                (0b001, 0b0000001) => set_rd(
                    "mulh",
                    (((rs1 as i32 as i64).wrapping_mul(rs2 as i32 as i64)) >> 32) as u32,
                    2,
                ),
                (0b010, 0b0000001) => set_rd(
                    "mulhsu",
                    ((rs1 as i32 as u64).wrapping_mul(rs2 as u64) >> 32) as u32,
                    2,
                ),
                (0b011, 0b0000001) => set_rd(
                    "mulhu",
                    ((rs1 as u64).wrapping_mul(rs2 as u64) >> 32) as u32,
                    2,
                ),
                (0b100, 0b0000001) => set_rd(
                    "div",
                    if rs2 == 0 {
                        u32::MAX
                    } else {
                        ((rs1 as i32).wrapping_div(rs2 as i32)) as u32
                    },
                    2,
                ),
                (0b101, 0b0000001) => set_rd("divu", rs1.checked_div(rs2).unwrap_or(u32::MAX), 2),
                (0b110, 0b0000001) => set_rd(
                    "rem",
                    if rs2 == 0 {
                        rs1
                    } else {
                        ((rs1 as i32).wrapping_rem(rs2 as i32)) as u32
                    },
                    2,
                ),
                (0b111, 0b0000001) => set_rd("remu", rs1.checked_rem(rs2).unwrap_or(rs1), 2),
                _ => bail_ctx!("Invalid R-format arithmetic op"),
            }
        }
        0b0010011 => {
            // I-format arithmetic ops
            let rs1 = state.load_reg(rs1reg);
            let imm = bits_signed(31, 20) as u32;
            let set_rd = |mnemonic: &str, val: u32, cycles: usize| {
                let imm_signed = imm as i32;
                trace!(
                    "{mnemonic} x{rs1reg} = {rs1:#08x}, {imm_signed:#08x} -> x{rd} = {val:#08x}"
                );
                Ok(RegisterStore {
                    reg: rd,
                    new_pc: pc + WORD_SIZE,
                    val,
                    cycles,
                })
            };
            match (funct3, funct7) {
                (0b000, _) => set_rd("addi", rs1.wrapping_add(imm), 1),
                (0b001, 0b0000000) => set_rd("slli", rs1.wrapping_shl(imm), 2),
                (0b010, _) => set_rd("slti", if (rs1 as i32) < (imm as i32) { 1 } else { 0 }, 1),
                (0b011, _) => set_rd("sltiu", if rs1 < imm { 1 } else { 0 }, 1),
                (0b100, _) => set_rd("xori", rs1 ^ imm, 2),
                (0b101, 0b0000000) => set_rd("srli", rs1.wrapping_shr(imm), 2),
                (0b101, 0b0100000) => set_rd("srai", (rs1 as i32).wrapping_shr(imm) as u32, 2),
                (0b110, _) => set_rd("ori", rs1 | imm, 2),
                (0b111, _) => set_rd("andi", rs1 & imm, 2),
                _ => bail_ctx!("Invalid I-format arithmetic op"),
            }
        }
        0b0000011 => {
            // I-format memory loads
            let imm = bits_signed(31, 20) as u32;
            let rs1 = state.load_reg(rs1reg);
            let addr = rs1.wrapping_add(imm);
            let word_addr = addr & !(WORD_SIZE - 1);
            let offset = addr & (WORD_SIZE - 1);
            let mem_word = state.load_ram(word_addr);
            let shifted = mem_word >> (8 * offset);
            let set_rd = |mnemonic: &str, val: u32| {
                let imm_signed = imm as i32;
                trace!("{mnemonic} mem[(x{rs1reg} = {rs1:#08x}) + {imm_signed:#x} = {addr:#08x}] = {mem_word:#08x} -> x{rd} = {val:#08x}");
                Ok(MemoryLoad {
                    addr: word_addr,
                    val,
                    reg: rd,
                })
            };
            match funct3 {
                0b000 => set_rd("lb", (shifted & 0xFF) as i8 as u32),
                0b001 => set_rd("lh", (shifted & 0xFFFF) as i16 as u32),
                0b010 => set_rd("lw", mem_word),
                0b100 => set_rd("lbu", shifted & 0xFF),
                0b101 => set_rd("lhu", shifted & 0xFFFF),
                _ => bail_ctx!("Invalid I-format memory load"),
            }
        }
        0b0100011 => {
            // S-format memory stores
            let imm = ((bits_signed(31, 25) as u32) << 5) | bits(11, 7);
            let rs1 = state.load_reg(rs1reg);
            let rs2 = state.load_reg(rs2reg);
            let addr = rs1.wrapping_add(imm);
            let word_addr = addr & !(WORD_SIZE - 1);
            let offset = addr & (WORD_SIZE - 1);
            let old_word = state.load_ram(word_addr);
            let set_ram = |mnemonic: &str, bytes: u32, mask: u32| {
                if word_addr & (bytes - 1) != 0 {
                    bail_ctx!("Unaligned RAM read");
                }
                let val = (old_word & !(mask << (offset * 8))) | ((rs2 & mask) << (offset * 8));
                let imm_signed = imm as i32;
                trace!("{mnemonic} x{rs2reg} = {rs2:#08x} -> {mnemonic} mem[(x{rs1reg} = {rs1:#08x}) + {imm_signed:#x} = {addr:#08x}] = {val:#08x}");
                Ok(MemoryStore {
                    addr: word_addr,
                    val,
                })
            };
            match funct3 {
                0b000 => set_ram("sb", 1, 0xFF),
                0b001 => set_ram("sh", 2, 0xFFFF),
                0b010 => set_ram("sw", 4, 0xFFFFFFFF),
                _ => bail_ctx!("Invalid S-format memory store"),
            }
        }
        0b0110111 => {
            // U-format lui
            let imm = bits(31, 12);
            let val = imm << 12;
            trace!("lui {imm:#05x} << 12 = {val:#08x} -> x{rd}");
            Ok(RegisterStore {
                reg: rd,
                new_pc: pc + WORD_SIZE,
                val,
                cycles: 1,
            })
        }
        0b0010111 => {
            // U-format auipc
            let imm = bits(31, 12);
            let offset = imm << 12;
            let val = pc.wrapping_add(offset);
            trace!("auipc {imm:#05x} << 12 = {offset:#08x} + pc = {val:#08} -> x{rd}");
            Ok(RegisterStore {
                reg: rd,
                new_pc: pc + WORD_SIZE,
                val,
                cycles: 1,
            })
        }
        0b1100011 => {
            // B-format branch
            let imm = ((bits_signed(31, 31) as u32) << 12)
                | (bits(30, 25) << 5)
                | (bits(11, 8) << 1)
                | (bits(7, 7) << 11);
            let rs1 = state.load_reg(rs1reg);
            let rs2 = state.load_reg(rs2reg);
            let branch_if = |mnemonic: &str, do_branch: bool| {
                let new_pc: u32;
                if do_branch {
                    new_pc = pc.wrapping_add(imm);
                    trace!("{mnemonic} x{rs1reg} = {rs1:#08x}, x{rs2reg} = {rs2:#08x}? TRUE; imm {imm:#04x} + pc == {new_pc:#08x} -> pc");
                } else {
                    new_pc = pc + WORD_SIZE;
                    trace!("{mnemonic} x{rs1reg} = {rs1:#08x}, x{rs2reg} = {rs2:#08x}? FALSE; pc + 4== {new_pc:#08x} -> pc");
                }
                Ok(RegisterStore {
                    reg: 0,
                    val: 0,
                    new_pc,
                    cycles: 1,
                })
            };
            match funct3 {
                0b000 => branch_if("beq", rs1 == rs2),
                0b001 => branch_if("bne", rs1 != rs2),
                0b100 => branch_if("blt", (rs1 as i32) < (rs2 as i32)),
                0b101 => branch_if("bge", (rs1 as i32) >= (rs2 as i32)),
                0b110 => branch_if("bltu", rs1 < rs2),
                0b111 => branch_if("bgeu", rs1 >= rs2),
                _ => bail_ctx!("Invalid B-format branch"),
            }
        }
        0b1101111 => {
            // J-format jal
            let imm = ((bits_signed(31, 31) as u32) << 20)
                | (bits(30, 21) << 1)
                | (bits(20, 20) << 11)
                | (bits(19, 12) << 12);
            let imm_signed = imm as i32;
            let val = pc + WORD_SIZE;
            let new_pc = pc.wrapping_add(imm);
            trace!(
                "jal pc + 4 -> x{rd} == {val:#08x}; pc + {imm_signed:#05x} -> pc == {new_pc:#08x}"
            );
            Ok(RegisterStore {
                reg: rd,
                val,
                new_pc,
                cycles: 1,
            })
        }
        0b1100111 => {
            // I-format jalr
            if funct3 != 0b000 {
                bail_ctx!("Invalid I-format jalr");
            }
            let imm = bits_signed(31, 20) as u32;
            let rs1 = state.load_reg(rs1reg);
            let imm_signed = imm as i32;
            let val = pc + WORD_SIZE;
            let new_pc = rs1.wrapping_add(imm & !1);
            trace!("jal pc + 4 -> x{rd} == {val:#08x}; (x{rs1reg} == {rs1:#08x}) + {imm_signed:#05x} -> pc == {new_pc:#08x}");
            Ok(RegisterStore {
                reg: rd,
                val,
                new_pc,
                cycles: 1,
            })
        }
        0b1110011 => {
            // ECall
            Ok(ECall)
        }
        _ => bail_ctx!("Invalid opcode"),
    }
}
