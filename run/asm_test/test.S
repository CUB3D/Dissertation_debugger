[bits 64]
SECTION .text
global _start
_start:

mov rax, 100000
foo:
    sub rax, 1
    jnz foo

loop:
    jmp loop

