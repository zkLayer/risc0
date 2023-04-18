use afl::fuzz;
use risc0_zkvm::{Program, MEM_SIZE};

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = Program::load_elf(data, MEM_SIZE as u32);
    });
}
