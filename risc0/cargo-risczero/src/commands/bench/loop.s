# riscv32-unknown-elf-gcc -nostdlib loop.s -o loop.bin
# riscv32-unknown-elf-strip loop.bin

.global _start
.text

_start:
    li      a4, 0         # i = 0u32
    lui     a5, 0xfffff   # 0xfffff7b7: Fill upper 20 bits of `count`
    addi    a5, a5, -1    # 0xfff78793: Fill lower 12 bits of `count`
loop:
    addi    a4, a4, 1     # i += 1
    bltu    a4, a5, loop  # if (i < count) goto loop
    la      a1, hash      # Set output digest
    ecall                 # Halt (and catch fire)

# SHA2-256 of the null journal & assumption.
.section .rodata
hash:
    .word 0x5c176f83, 0x53f3c062, 0x42651683, 0x340b8b7e, 0x19d2d1f6, 0xae4d7602, 0xb8c606b4, 0xb075b53d
