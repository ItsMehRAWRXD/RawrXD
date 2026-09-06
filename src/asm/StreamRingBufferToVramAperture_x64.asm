; ============================================================================
; StreamRingBufferToVramAperture_x64.asm
; Host ring -> mapped VRAM aperture via AVX-512 non-temporal stores.
; Windows x64 ABI / no CRT / no imports
; ============================================================================

OPTION CASEMAP:NONE

.code

; uint64_t StreamRingBufferToVramAperture(const void* src, void* dst, uint64_t bytes)
; RCX = src (host ring)
; RDX = dst (mapped BAR / aperture)
; R8  = byte count
; RAX = 0 success, 1 bad args, 2 unaligned length
PUBLIC StreamRingBufferToVramAperture

StreamRingBufferToVramAperture PROC
    test    rcx, rcx
    jz      srb_bad_args
    test    rdx, rdx
    jz      srb_bad_args
    test    r8, r8
    jz      srb_ok

    ; Require 64-byte multiple for NT ZMM path.
    test    r8, 63
    jnz     srb_bad_align

    ; Pointers should be 64-byte aligned for vmovdqa64/vmovntdq.
    test    rcx, 63
    jnz     srb_bad_align
    test    rdx, 63
    jnz     srb_bad_align

    mov     r9, rcx              ; src
    mov     r10, rdx             ; dst
    mov     r11, r8              ; remaining

    mfence
    lfence

srb_loop:
    cmp     r11, 64
    jb      srb_done
    vmovdqa64 zmm0, zmmword ptr [r9]
    vmovntdq zmmword ptr [r10], zmm0
    add     r9, 64
    add     r10, 64
    sub     r11, 64
    jmp     short srb_loop

srb_done:
    sfence
    mfence

srb_ok:
    xor     eax, eax
    ret

srb_bad_args:
    mov     eax, 1
    ret

srb_bad_align:
    mov     eax, 2
    ret
StreamRingBufferToVramAperture ENDP

END
