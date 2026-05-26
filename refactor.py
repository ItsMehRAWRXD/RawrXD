import re

with open('d:/rawrxd/dequant_simd.asm', 'r', encoding='utf-8') as f:
    text = f.read()

# adding red zone
if '.DATA?' not in text:
    data_pat = r'\.data'
    red_zone = """.DATA?
ALIGN 4096
RED_ZONE_START db 4096 dup(?)

.DATA
ALIGN 4096
RED_ZONE_GUARD db 4096 dup(0CCh)
"""
    # Replace the first .data instruction (case insensitive)
    text = re.sub(r'\.data(?![\s\S]*\.data)', red_zone, text, count=1, flags=re.IGNORECASE)

# Refactoring vec_dot_q4_0 loop
vec_dot_byte = """@@dot_byte:
    cmp     r9d, 16
    jge     @@dot_accumulate

    movzx   eax, BYTE PTR [rsi+2+r9]
    movzx   edx, BYTE PTR [rdi+2+r9]"""

vec_dot_byte_new = """    ; Pointer-End Walk setup for inner loop
    lea     r14, [rsi+2]
    lea     r15, [rsi+18]
    lea     rdx, [rdi+2]

@@dot_byte:
    cmp     r14, r15
    jae     @@dot_accumulate

    movzx   eax, BYTE PTR [r14]
    movzx   edx, BYTE PTR [rdx]"""

text = text.replace(vec_dot_byte, vec_dot_byte_new)

text = text.replace('    inc     r9d\n    jmp     @@dot_byte', '    inc     r14\n    inc     rdx\n    jmp     @@dot_byte')
text = text.replace('movzx   eax, BYTE PTR [rsi+2+r9]', '')

# Refactoring dequant_q5_k_scalar loop
# Target 1: first level loop
# xor     r12d, r12d          ; sub-block index (0..7)
# @@q5_subblock:
#     cmp     r12d, 8
#     jge     @@q5_done

# Target 2: inner loop
# xor     ebx, ebx            ; value pair index (0..15)
# @@q5_pair:
#     cmp     ebx, 16
#     jge     @@q5_next_sub

with open('d:/rawrxd/dequant_simd_refactored.asm', 'w', encoding='utf-8') as f:
    f.write(text)

print("Done")