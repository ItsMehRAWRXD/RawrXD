import re

with open('d:/rawrxd/dequant_simd.asm', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Red Zone Guard Pages in DATA section
if 'RED_ZONE' not in text:
    old_data = """.data
align 16"""
    new_data = """.DATA?
ALIGN 16
RedZone_Start db 4096 dup(?)

.DATA
ALIGN 16
RedZone_Guard db 4096 dup(0CCh)
align 16"""
    text = text.replace(old_data, new_data)

# 2. vec_dot_q4_0
old_dot = """    xor     r8d, r8d            ; sum of products
    xor     r9d, r9d            ; byte index

@@dot_byte:
    cmp     r9d, 16
    jge     @@dot_accumulate

    movzx   eax, BYTE PTR [rsi+2+r9]
    movzx   edx, BYTE PTR [rdi+2+r9]"""

new_dot = """    xor     r8d, r8d            ; sum of products

    ; Pointer-End Walk setup for inner loop
    lea     rcx, [rsi+2]       ; A ptr
    lea     r12, [rsi+18]      ; A end ptr
    lea     rdx, [rdi+2]       ; B ptr

@@dot_byte:
    cmp     rcx, r12
    jae     @@dot_accumulate

    movzx   eax, BYTE PTR [rcx]
    movzx   edx, BYTE PTR [rdx]"""

text = text.replace(old_dot, new_dot)

old_dot_inc = """    inc     r9d
    jmp     @@dot_byte"""

new_dot_inc = """    inc     rcx
    inc     rdx
    jmp     @@dot_byte"""

text = text.replace(old_dot_inc, new_dot_inc)

# 3. dequant_q5_k_scalar
# outer
q5_outer_old = """    xor     r12d, r12d          ; sub-block index (0..7)

@@q5_subblock:
    cmp     r12d, 8
    jge     @@q5_done"""

q5_outer_new = """    lea     rcx, [rsi+48]       ; qs base
    lea     r12, [rsi+176]      ; qs end bounds

@@q5_subblock:
    cmp     rcx, r12
    jae     @@q5_done"""

text = text.replace(q5_outer_old, q5_outer_new)

# inner parameter fix outer loop logic
old_q5_scale = """    mov     eax, r12d
    shl     eax, 1              ; sub * 2
    cmp     eax, 12
    jge     @@q5_scale_zero     ; sub >= 6: scale array overflow
    movzx   r13d, BYTE PTR [rsi+4+rax]     ; raw scale byte"""

# compute subblock index correctly from pointer
new_q5_scale = """    ; reconstruct sub-block index
    mov     rax, rcx
    sub     rax, rsi
    sub     rax, 48
    shr     rax, 4              ; (rcx - base) / 16
    
    mov     rbx, rax
    shl     rbx, 1
    cmp     rbx, 12
    jge     @@q5_scale_zero     ; sub >= 6: scale array overflow
    movzx   r13d, BYTE PTR [rsi+4+rbx]     ; raw scale byte"""

text = text.replace(old_q5_scale, new_q5_scale)

# inner loop fixing
old_q5_qs = """    ; qs offset for this sub-block: 48 + sub*16
    mov     eax, r12d
    shl     eax, 4              ; sub * 16
    add     eax, 48
    mov     r14d, eax           ; qs_offset

    ; qh offset: 16 + sub*4
    mov     eax, r12d
    shl     eax, 2              ; sub * 4
    add     eax, 16
    mov     r15d, eax           ; qh_offset

    xor     ebx, ebx            ; value pair index (0..15)
@@q5_pair:
    cmp     ebx, 16
    jge     @@q5_next_sub

    ; Read quant byte (2 values packed)
    movzx   eax, BYTE PTR [rsi+r14]
    inc     r14d"""

new_q5_qs = """    ; qh offset: 16 + sub*4
    mov     r15d, ebx           ; rbx has sub*2
    shl     r15d, 1             ; sub*4
    add     r15d, 16
    
    mov     r14, rcx            ; pointer walk for qs
    lea     rbx, [rcx+16]       ; end pointer for this subblock

@@q5_pair:
    cmp     r14, rbx
    jae     @@q5_next_sub

    ; Read quant byte (2 values packed)
    movzx   eax, BYTE PTR [r14]
    inc     r14"""

text = text.replace(old_q5_qs, new_q5_qs)

# value calculations ...
old_q5_calc = """    ; Read 5th bit from qh
    mov     ecx, ebx
    shr     ecx, 3              ; qh byte index
    add     ecx, r15d
    movzx   edx, BYTE PTR [rsi+rcx]
    mov     ecx, ebx
    and     ecx, 7              ; bit position"""

new_q5_calc = """    ; ebx is block-end pointer for q5_pair now, so we need value pair index.
    ; ebx - rcx = 16, r14 - rcx = pair index (0-15)
    mov     r11, r14
    sub     r11, rcx
    dec     r11                 ; Since r14 was incremented 

    ; Read 5th bit from qh
    mov     r8, r11
    shr     r8, 3              ; qh byte index
    add     r8, r15
    movzx   edx, BYTE PTR [rsi+r8]
    mov     r8, r11
    and     r8, 7              ; bit position"""

text = text.replace(old_q5_calc, new_q5_calc)

old_bt1 = """    bt      edx, ecx"""
new_bt1 = """    bt      edx, r8d"""
text = text.replace(old_bt1, new_bt1)

old_store1 = """    ; Store
    mov     ecx, r12d
    shl     ecx, 5              ; sub * 32
    mov     r8d, ebx
    shl     r8d, 1              ; pair * 2
    add     ecx, r8d
    movss   DWORD PTR [rdi+rcx*4], xmm5"""

new_store1 = """    ; Store
    ; r11 is pair index
    ; sub * 32 = rax * 32
    mov     r8, rax
    shl     r8, 5
    mov     r9, r11
    shl     r9, 1
    add     r8, r9
    movss   DWORD PTR [rdi+r8*4], xmm5"""
text = text.replace(old_store1, new_store1)

old_store2 = """    ; 5th bit for high nibble — use next bit position
    mov     r8d, ebx
    add     r8d, 16             ; high nibble bits are in upper half
    mov     r9d, r8d
    shr     r9d, 3
    add     r9d, r15d
    movzx   r10d, BYTE PTR [rsi+r9]
    and     r8d, 7
    bt      r10d, r8d
    jnc     @@no_bit5_hi
    or      eax, 10h
@@no_bit5_hi:
    cvtsi2ss xmm5, eax
    mulss   xmm5, xmm2
    subss   xmm5, xmm3
    inc     ecx                 ; next value slot
    movss   DWORD PTR [rdi+rcx*4], xmm5

    inc     ebx
    jmp     @@q5_pair"""

new_store2 = """    ; 5th bit for high nibble — use next bit position
    mov     r9, r11
    add     r9, 16             ; high nibble bits are in upper half
    mov     r10, r9
    shr     r10, 3
    add     r10, r15
    movzx   r13d, BYTE PTR [rsi+r10]
    and     r9, 7
    bt      r13d, r9d
    jnc     @@no_bit5_hi
    or      eax, 10h
@@no_bit5_hi:
    cvtsi2ss xmm5, eax
    mulss   xmm5, xmm2
    subss   xmm5, xmm3
    inc     r8                 ; next value slot
    movss   DWORD PTR [rdi+r8*4], xmm5

    jmp     @@q5_pair"""
text = text.replace(old_store2, new_store2)

old_q5_end = """@@q5_next_sub:
    inc     r12d
    jmp     @@q5_subblock"""
new_q5_end = """@@q5_next_sub:
    add     rcx, 16
    jmp     @@q5_subblock"""
text = text.replace(old_q5_end, new_q5_end)

with open('d:/rawrxd/dequant_simd.asm', 'w', encoding='utf-8') as f:
    f.write(text)

print("success")
