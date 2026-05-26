; ==============================================================================
; Sovereign_Elite_Scanner.asm - Masked AVX-512 Pattern Scanner
; High-performance memory interrogation with zero-dependency x64 MASM logic.
; ==============================================================================

include Sovereign_Common.inc

.CODE

; ----------------------------------------------------------------------------
; Sovereign_SIMD_Scanner_Masked
; RCX = Buffer Base
; RDX = Buffer Size (Bytes)
; R8  = 4-byte Pattern to find
; Returns RAX = Pointer to match, or 0
; ----------------------------------------------------------------------------
PUBLIC Sovereign_SIMD_Scanner_Masked
Sovereign_SIMD_Scanner_Masked PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx            ; RSI = Current Pointer
    mov r10, rdx            ; R10 = Remaining Bytes
    
    ; Broadcast pattern to ZMM0
    vmovd xmm0, r8d
    vpbroadcastd zmm0, xmm0 ; ZMM0 now contains 16 copies of the pattern

@@ScanLoop:
    cmp r10, 64
    jb @@ProcessTail        ; If less than 64 bytes, handle with mask

    ; 1. Load 64 bytes (aligned or unaligned)
    vmovdqu32 zmm1, [rsi]
    
    ; 2. Compare against pattern
    ; vpcmpd returns a mask into k-register
    ; 0 = Equal
    vpcmpd k1, zmm0, zmm1, 0
    
    ; 3. Check mask
    kmovw eax, k1
    test eax, eax
    jnz @@MatchFound
    
    add rsi, 64
    sub r10, 64
    jmp @@ScanLoop

@@ProcessTail:
    test r10, r10
    jz @@NotFound
    
    ; Generate mask for remainder
    ; (1 << count) - 1
    ; But we need dword count (r10 / 4)
    mov rax, r10
    shr rax, 2              ; RAX = Dword count
    jz @@ByteByByte         ; If less than 4 bytes, fall back or ignore for scan
    
    mov rcx, rax
    mov rax, 1
    shl rax, cl
    dec rax
    kmovw k1, eax           ; K1 = Tail Mask
    
    ; Masked Load - ZEROING (z) outside mask
    vmovdqu32 zmm1 {k1}{z}, [rsi]
    
    vpcmpd k1, zmm0, zmm1, 0
    kmovw eax, k1
    test eax, eax
    jnz @@MatchFound

@@ByteByByte:
    ; Optional: handle remaining 1-3 bytes if pattern is smaller than 4 bytes
    ; For a dword scanner, we skip.
    jmp @@NotFound

@@MatchFound:
    ; Find which index in the mask was set
    bsf eax, eax            ; EAX = Index of first set bit
    shl rax, 2              ; Index * 4 = Byte Offset
    add rax, rsi            ; Final Address
    jmp @@Done

@@NotFound:
    xor rax, rax

@@Done:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_SIMD_Scanner_Masked ENDP

END
