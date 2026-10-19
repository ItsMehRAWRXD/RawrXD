option casemap:none
include nilw_accounting.inc

.code
PUBLIC NilwU128MulLE

; eax = 1 iff unsigned (rcx * rdx) <= unsigned (r8 * r9).
; Each product is evaluated as the full 128-bit result of MUL.
NilwU128MulLE PROC
    mov rax,rcx
    mul rdx
    mov r10,rdx
    mov r11,rax

    mov rax,r8
    mul r9
    cmp r10,rdx
    jb  short u128_yes
    ja  short u128_no
    cmp r11,rax
    jbe short u128_yes

u128_no:
    xor eax,eax
    ret
u128_yes:
    mov eax,1
    ret
NilwU128MulLE ENDP

END
