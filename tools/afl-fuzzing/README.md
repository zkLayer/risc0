# Fuzzing RISC Zero with AFL

Test harnesses for fuzzing different component of the risc0 system.

### Currently covers:

* ELF file parsing


## Setup

```bash
cargo install -f afl
cd tooling/afl-fuzzing/
mkdir out/
```

## Run fuzzer

```bash
cargo afl build --release
# Select the fuzzing harness in the last arg:
cargo afl fuzz -i ./corpus -o out ./target/release/elf_fuzzer
```