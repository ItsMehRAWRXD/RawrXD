import sys

with open(r'd:\rawrxd\src\asm\dequant_simd.asm', 'r', encoding='utf-8') as f:
    text = f.read()

# Add RED ZONE
if 'RedZone_Guard' not in text:
    old_data = ".data\nalign 16"
    new_data = """.DATA?
ALIGN 16
RedZone_Start db 4096 dup(?)

.DATA
ALIGN 16
RedZone_Guard db 4096 dup(0CCh)
align 16"""
    text = text.replace(old_data, new_data)

# Refactor Dequant_Q4_0
old_q4_0 = """    mov rbx, rcx        ; block count
    mov r12, rdx         ; pWeight
    mov r13, r8          ; pScale
    mov r10, r9          ; pOut
    
    test rbx, rbx
    jz dq4_done
    
dq4_loop:"""

new_q4_0 = """    mov r12, rdx         ; pWeight
    mov r13, r8          ; pScale
    mov r10, r9          ; pOut
    
    test rcx, rcx
    jz dq4_done

    ; Pointer-End Walk Setup
    ; 16 bytes weights + 2 bytes scale = 18 bytes per block
    mov rax, 18
    imul rax, rcx
    lea rbx, [r12 + rax] ; rbx = End Pointer (exclusive)
    
dq4_loop:"""

text = text.replace(old_q4_0, new_q4_0)
text = text.replace("    dec rbx\n    jnz dq4_loop", "    cmp r12, rbx\n    jb dq4_loop")

# Refactor Dequant_Q4_1
old_q4_1 = """    mov rbx, rcx        ; block count
    mov r12, rdx        ; pWeight
    mov r13, r9         ; pOut

    test rbx, rbx
    jz dq41_done

dq41_blk:
    ; 32 packed 4-bit values -> 32 int32 baseline outputs
    mov ecx, 16
dq41_pair:"""

new_q4_1 = """    mov r12, rdx        ; pWeight
    mov r13, r9         ; pOut

    test rcx, rcx
    jz dq41_done

    ; Pointer-End Walk Setup for blocks
    ; Q4_1 block size: 32 values / 2 = 16 bytes + FP16 scale/min payload area (2 bytes) = 18 bytes
    mov rax, 18
    imul rax, rcx
    lea rbx, [r12 + rax] ; rbx = End Pointer (exclusive)

dq41_blk:
    ; Pointer-End Walk Setup for pairs
    lea rax, [r12 + 16]  ; rax = End Pointer for pairs in this block

dq41_pair:"""

text = text.replace(old_q4_1, new_q4_1)
text = text.replace("    dec ecx\n    jnz dq41_pair", "    cmp r12, rax\n    jb dq41_pair")
text = text.replace("    dec rbx\n    jnz dq41_blk", "    cmp r12, rbx\n    jb dq41_blk")

# Refactor Dequant_Q8_0
old_q8_0 = """    mov rbx, rcx        ; block count
    mov r12, rdx        ; pWeight
    mov r13, r9         ; pOut

    test rbx, rbx
    jz dq80_done

dq80_blk:
    mov ecx, 32
dq80_val:"""

new_q8_0 = """    mov r12, rdx        ; pWeight
    mov r13, r9         ; pOut

    test rcx, rcx
    jz dq80_done

    ; Pointer-End Walk Setup for blocks
    ; Q8_0 block size: 32 bytes + fp16 scale (2 bytes) = 34 bytes
    mov rax, 34
    imul rax, rcx
    lea rbx, [r12 + rax] ; rbx = End Pointer (exclusive)

dq80_blk:
    ; Pointer-End Walk Setup for values
    lea rax, [r12 + 32]  ; rax = End Pointer for values in this block

dq80_val:"""
text = text.replace(old_q8_0, new_q8_0)
text = text.replace("    dec ecx\n    jnz dq80_val", "    cmp r12, rax\n    jb dq80_val")
text = text.replace("    dec rbx\n    jnz dq80_blk", "    cmp r12, rbx\n    jb dq80_blk")


# Refactor Dequant_FP16
old_fp16 = """    ; RCX = element count, RDX = pIn(fp16), R8 = pOut(fp32)
    mov rbx, rcx
    mov r12, rdx
    mov r13, r8
    test rbx, rbx
    jz df16_done

df16_loop:"""

new_fp16 = """    ; RCX = element count, RDX = pIn(fp16), R8 = pOut(fp32)
    mov r12, rdx
    mov r13, r8
    test rcx, rcx
    jz df16_done

    ; Pointer-End Walk Setup
    ; fp16 array size: count * 2 bytes
    lea rbx, [r12 + rcx*2]

df16_loop:"""

text = text.replace(old_fp16, new_fp16)
text = text.replace("    dec rbx\n    jnz df16_loop", "    cmp r12, rbx\n    jb df16_loop")

with open(r'd:\rawrxd\src\asm\dequant_simd.asm', 'w', encoding='utf-8') as f:
    f.write(text)

print("Updated d:\\rawrxd\\src\\asm\\dequant_simd.asm successfully.")
