; ============================================================================
; VwaRangeLineageX64.asm
; Observational RMV/VWA lineage helpers.
;
; ml64 /c VwaRangeLineageX64.asm
;
; No CRT. No allocator. No GGUF parsing. No mount. No file I/O.
; Microsoft x64 ABI.
; ============================================================================

OPTION CASEMAP:NONE

PUBLIC VwaRangeSetHash64
PUBLIC VwaRangeSetSumBytes64
PUBLIC VwaRangeSetEqual64

VR_SIZE             EQU 64
VR_BYTE_COUNT       EQU 32

K2R_FIRST_ROW       EQU 0
K2R_ROW_COUNT       EQU 8
K2R_COLS            EQU 16
K2R_BLOCK_ELEMS     EQU 24

K2O_FIRST_BLOCK     EQU 0
K2O_BLOCK_COUNT     EQU 8
K2O_BLOCKS_PER_ROW  EQU 16

_TEXT SEGMENT

; uint64_t VwaRangeSetHash64(const VwaLineageRange* ranges, uint64_t count)
; FNV-1a 64 over exact normalized receipt bytes.
VwaRangeSetHash64 PROC
    mov     rax, 0CBF29CE484222325h
    test    rdx, rdx
    jz      vrh_done
    test    rcx, rcx
    jz      vrh_null

    mov     r8, rdx
    shl     r8, 6
    jc      vrh_null
    add     r8, rcx
    jc      vrh_null

    mov     r9, 0100000001B3h
vrh_loop:
    movzx   edx, byte ptr [rcx]
    xor     rax, rdx
    imul    rax, r9
    inc     rcx
    cmp     rcx, r8
    jb      vrh_loop
vrh_done:
    ret
vrh_null:
    xor     eax, eax
    ret
VwaRangeSetHash64 ENDP


; uint64_t VwaRangeSetSumBytes64(const VwaLineageRange* ranges, uint64_t count)
; UINT64_MAX on invalid pointer/overflow.
VwaRangeSetSumBytes64 PROC
    xor     eax, eax
    test    rdx, rdx
    jz      vrs_done
    test    rcx, rcx
    jz      vrs_fail
vrs_loop:
    add     rax, qword ptr [rcx + VR_BYTE_COUNT]
    jc      vrs_fail
    add     rcx, VR_SIZE
    dec     rdx
    jnz     vrs_loop
vrs_done:
    ret
vrs_fail:
    mov     rax, -1
    ret
VwaRangeSetSumBytes64 ENDP


; uint32_t VwaRangeSetEqual64(a, b, count)
; Exact identity over normalized receipts.
VwaRangeSetEqual64 PROC
    test    r8, r8
    jz      vre_yes
    test    rcx, rcx
    jz      vre_no
    test    rdx, rdx
    jz      vre_no

    mov     r9, r8
    shl     r9, 3              ; qwords = count * 8
    jc      vre_no
vre_loop:
    mov     rax, qword ptr [rcx]
    cmp     rax, qword ptr [rdx]
    jne     vre_no
    add     rcx, 8
    add     rdx, 8
    dec     r9
    jnz     vre_loop
vre_yes:
    mov     eax, 1
    ret
vre_no:
    xor     eax, eax
    ret
VwaRangeSetEqual64 ENDP


; Correct implementation exported under the same semantic ABI.
; The C++ header aliases callers to this symbol when assembling this drop.
PUBLIC K2RowsToBlockRangeX64_Fixed
K2RowsToBlockRangeX64_Fixed PROC
    test    rcx, rcx
    jz      k2f_null
    test    rdx, rdx
    jz      k2f_null
    mov     r11, rdx

    xor     eax, eax
    mov     qword ptr [r11 + 0], rax
    mov     qword ptr [r11 + 8], rax
    mov     qword ptr [r11 + 16], rax
    mov     qword ptr [r11 + 24], rax

    mov     r8, qword ptr [rcx + K2R_ROW_COUNT]
    test    r8, r8
    jz      k2f_zero

    mov     rax, qword ptr [rcx + K2R_COLS]
    test    rax, rax
    jz      k2f_zero

    mov     r9, qword ptr [rcx + K2R_BLOCK_ELEMS]
    test    r9, r9
    jz      k2f_zero

    xor     edx, edx
    div     r9
    test    rdx, rdx
    jnz     k2f_not_integral
    test    rax, rax
    jz      k2f_zero
    mov     r10, rax
    mov     qword ptr [r11 + K2O_BLOCKS_PER_ROW], r10

    ; firstBlock = firstRow * blocksPerRow
    mov     rax, qword ptr [rcx + K2R_FIRST_ROW]
    mul     r10
    test    rdx, rdx
    jnz     k2f_overflow
    mov     qword ptr [r11 + K2O_FIRST_BLOCK], rax

    ; blockCount = rowCount * blocksPerRow
    mov     rax, qword ptr [rcx + K2R_ROW_COUNT]
    mul     r10
    test    rdx, rdx
    jnz     k2f_overflow
    mov     qword ptr [r11 + K2O_BLOCK_COUNT], rax

    xor     eax, eax
    ret
k2f_null:
    mov     eax, 1
    ret
k2f_zero:
    mov     eax, 2
    ret
k2f_not_integral:
    mov     eax, 3
    ret
k2f_overflow:
    mov     eax, 4
    ret
K2RowsToBlockRangeX64_Fixed ENDP

_TEXT ENDS
END
