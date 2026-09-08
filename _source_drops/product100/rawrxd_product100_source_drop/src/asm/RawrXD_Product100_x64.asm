; RawrXD_Product100_x64.asm
; Small no-dependency x64 MASM leaf routines for the Product Finish 100 overlay.
; These routines are deliberately simple and do not replace existing certified
; MASM kernel/runtime lanes.

OPTION CASEMAP:NONE

.code

PUBLIC P100_Fnv1a64
P100_Fnv1a64 PROC
    ; rcx = data, rdx = byte count, rax = FNV-1a 64-bit hash
    mov     rax, 0CBF29CE484222325h
    test    rcx, rcx
    jz      p100_fnv_done
    test    rdx, rdx
    jz      p100_fnv_done
    mov     r8, 00000100000001B3h
p100_fnv_loop:
    movzx   r9, byte ptr [rcx]
    xor     rax, r9
    imul    rax, r8
    inc     rcx
    dec     rdx
    jne     p100_fnv_loop
p100_fnv_done:
    ret
P100_Fnv1a64 ENDP

PUBLIC P100_CapAllows
P100_CapAllows PROC
    ; rcx = granted capability mask, rdx = required capability mask
    ; returns eax = 1 iff every required bit is present.
    mov     rax, rcx
    and     rax, rdx
    cmp     rax, rdx
    sete    al
    movzx   eax, al
    ret
P100_CapAllows ENDP

PUBLIC P100_FindByteSpan
P100_FindByteSpan PROC
    ; rcx = haystack, rdx = haystack bytes, r8 = needle, r9 = needle bytes
    ; returns rax = first zero-based index, or -1 if absent.
    test    rcx, rcx
    jz      p100_find_not_found
    test    r8, r8
    jz      p100_find_not_found
    test    r9, r9
    jz      p100_find_zero
    cmp     rdx, r9
    jb      p100_find_not_found

    mov     r10, rdx
    sub     r10, r9          ; last valid starting index
    xor     r11, r11         ; current starting index

p100_find_outer:
    mov     al, byte ptr [r8]
    cmp     byte ptr [rcx + r11], al
    jne     p100_find_next

    xor     rdx, rdx         ; compare index
p100_find_inner:
    cmp     rdx, r9
    jae     p100_find_found
    lea     rax, [rcx + r11]
    mov     al, byte ptr [rax + rdx]
    cmp     al, byte ptr [r8 + rdx]
    jne     p100_find_next
    inc     rdx
    jmp     p100_find_inner

p100_find_next:
    cmp     r11, r10
    jae     p100_find_not_found
    inc     r11
    jmp     p100_find_outer

p100_find_found:
    mov     rax, r11
    ret
p100_find_zero:
    xor     rax, rax
    ret
p100_find_not_found:
    or      rax, -1
    ret
P100_FindByteSpan ENDP

PUBLIC P100_CountLf
P100_CountLf PROC
    ; rcx = data, rdx = byte count, returns rax = number of '\n' bytes.
    xor     rax, rax
    test    rcx, rcx
    jz      p100_lf_done
    test    rdx, rdx
    jz      p100_lf_done
p100_lf_loop:
    cmp     byte ptr [rcx], 0Ah
    jne     p100_lf_skip
    inc     rax
p100_lf_skip:
    inc     rcx
    dec     rdx
    jne     p100_lf_loop
p100_lf_done:
    ret
P100_CountLf ENDP

PUBLIC P100_SecureZero
P100_SecureZero PROC
    ; rcx = data, rdx = byte count. Volatile byte scrub.
    test    rcx, rcx
    jz      p100_zero_done
    test    rdx, rdx
    jz      p100_zero_done
p100_zero_loop:
    mov     byte ptr [rcx], 0
    inc     rcx
    dec     rdx
    jne     p100_zero_loop
p100_zero_done:
    ret
P100_SecureZero ENDP

END
