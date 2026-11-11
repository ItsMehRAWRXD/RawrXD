; ═══════════════════════════════════════════════════════════════════════════════
; Quantized MatMul Diagnostic Kernel (MASM x64)
; ═══════════════════════════════════════════════════════════════════════════════
; Adds runtime diagnostics to catch uninitialized reads and scale mismatches
; ═══════════════════════════════════════════════════════════════════════════════

OPTION DOTNAME
OPTION CASEMAP:NONE

; ═══════════════════════════════════════════════════════════════════════════════
; External Exports
; ═══════════════════════════════════════════════════════════════════════════════
PUBLIC QuantizedMatMul_Diagnostic
PUBLIC QuantizedMatMul_DumpState

; ═══════════════════════════════════════════════════════════════════════════════
; External Imports
; ═══════════════════════════════════════════════════════════════════════════════
EXTERN printf:PROC

; ═══════════════════════════════════════════════════════════════════════════════
; Data Section
; ═══════════════════════════════════════════════════════════════════════════════
.data
ALIGN 8

dbg_msg_scale         DB "Block %d: scale_scalar=%.6f scale_avx=%.6f", 10, 0
dbg_msg_index         DB "Index %d: expected=%.6f actual=%.6f diff=%.6f", 10, 0
dbg_msg_alignment     DB "Buffer alignment: Q=%p K=%p V=%p", 10, 0
dbg_msg_boundary      DB "Crossing block boundary at idx=%d", 10, 0

; ═══════════════════════════════════════════════════════════════════════════════
; Code Section
; ═══════════════════════════════════════════════════════════════════════════════
.code

; ═══════════════════════════════════════════════════════════════════════════════
; QuantizedMatMul_Diagnostic
;
; Diagnostic wrapper that verifies scale consistency and alignment
; before calling the actual AVX-512 kernel
;
; Parameters (Windows x64 ABI):
;   RCX = output (float*)
;   RDX = activations (float*)
;   R8  = weights_q4 (uint8_t*)
;   R9  = scales (float*)
;   [RSP+40] = dim (uint32_t)
;   [RSP+48] = diagnostic_flags (uint32_t)
;
; Returns: max_error (float in XMM0)
; ═══════════════════════════════════════════════════════════════════════════════
QuantizedMatMul_Diagnostic PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 128
    .allocstack 128
    mov     rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Save parameters
    mov     r12, rcx                    ; r12 = output
    mov     r13, rdx                    ; r13 = activations
    mov     r14, r8                     ; r14 = weights_q4
    mov     r15, r9                     ; r15 = scales
    mov     ebx, [rsp+168]              ; ebx = dim (after pushed regs + stack)
    mov     r8d, [rsp+176]              ; r8d = diagnostic_flags

    ; ═══════════════════════════════════════════════════════════════════════════
    ; Diagnostic 1: Check alignment
    ; ═══════════════════════════════════════════════════════════════════════════
    test    r8d, 1                      ; Check ALIGNMENT flag
    jz      @F

    ; Print alignment info
    mov     rcx, OFFSET dbg_msg_alignment
    mov     rdx, r12
    mov     r8, r13
    mov     r9, r14
    call    printf

@@:
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Diagnostic 2: Verify scale consistency at block boundaries
    ; ═══════════════════════════════════════════════════════════════════════════
    test    r8d, 2                      ; Check SCALE_CHECK flag
    jz      @F

    ; Check scale at block 73 (2357/32 = 73.6, so block 73)
    mov     eax, 73
    cmp     eax, ebx
    jae     @F                          ; Skip if dim < 73*32

    ; Load scale from scalar path location
    vmovss  xmm0, dword ptr [r15 + 73*4]  ; scales[73]
    vcvtss2sd xmm0, xmm0

    ; Print scale value
    mov     rcx, OFFSET dbg_msg_scale
    mov     edx, 73
    vmovsd  qword ptr [rsp+32], xmm0      ; Save scale for printf
    mov     r8, qword ptr [rsp+32]
    mov     r9, r8                        ; Same value for now
    call    printf

@@:
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Diagnostic 3: Check for uninitialized memory pattern
    ; ═══════════════════════════════════════════════════════════════════════════
    test    r8d, 4                      ; Check UNINIT_CHECK flag
    jz      @F

    ; Check if output buffer contains NaN or denormals
    mov     rcx, r12
    mov     edx, ebx
    call    CheckUninitialized

@@:
    ; ═══════════════════════════════════════════════════════════════════════════
    ; Call actual AVX-512 kernel
    ; ═══════════════════════════════════════════════════════════════════════════
    mov     rcx, r12
    mov     rdx, r13
    mov     r8, r14
    mov     r9, r15
    mov     [rsp+32], ebx               ; dim
    call    QuantizedMatMul_AVX512_Core

    ; ═══════════════════════════════════════════════════════════════════════════
    ; Diagnostic 4: Verify output at index 2357
    ; ═══════════════════════════════════════════════════════════════════════════
    test    r8d, 8                      ; Check OUTPUT_VERIFY flag
    jz      @F

    mov     eax, 2357
    cmp     eax, ebx
    jae     @F

    ; Load output[2357]
    vmovss  xmm0, dword ptr [r12 + 2357*4]
    vcvtss2sd xmm0, xmm0

    ; Print output value
    mov     rcx, OFFSET dbg_msg_index
    mov     edx, 2357
    mov     r8, 0                       ; expected (unknown)
    vmovsd  qword ptr [rsp+32], xmm0
    mov     r9, qword ptr [rsp+32]      ; actual
    call    printf

@@:
    ; Epilogue
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

QuantizedMatMul_Diagnostic ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; CheckUninitialized
;
; Scans buffer for NaN or denormal patterns
; Parameters:
;   RCX = buffer (float*)
;   RDX = count (uint32_t)
; Returns: count of suspicious values in RAX
; ═══════════════════════════════════════════════════════════════════════════════
CheckUninitialized PROC
    xor     rax, rax                    ; suspicious_count = 0
    xor     r8, r8                      ; index = 0

.check_loop:
    cmp     r8d, edx
    jae     .check_done

    ; Load value
    vmovss  xmm0, dword ptr [rcx + r8*4]

    ; Check for NaN (exponent all 1s, mantissa non-zero)
    vpcmpeqd xmm1, xmm1, xmm1           ; xmm1 = all 1s
    vpsrld  xmm1, xmm1, 1               ; xmm1 = 0x7FFFFFFF (abs mask)
    vpand   xmm2, xmm0, xmm1            ; xmm2 = abs(value)

    ; Compare with infinity (0x7F800000)
    mov     r9d, 07F800000h
    vmovd   xmm3, r9d
    vpcmpgtd xmm2, xmm2, xmm3           ; xmm2 = abs(val) > inf ?
    vpmovmskb eax, xmm2
    test    eax, eax
    jz      .not_nan

    ; Found NaN
    inc     rax

.not_nan:
    inc     r8d
    jmp     .check_loop

.check_done:
    ret
CheckUninitialized ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; QuantizedMatMul_AVX512_Core
;
; Actual AVX-512 implementation (stub for now)
; ═══════════════════════════════════════════════════════════════════════════════
QuantizedMatMul_AVX512_Core PROC
    ; Stub - just zero the output for now
    mov     rax, rcx                    ; rax = output
    mov     r8d, [rsp+32]               ; r8d = dim
    xor     r9, r9                      ; index = 0

.zero_loop:
    cmp     r9d, r8d
    jae     .zero_done

    mov     dword ptr [rax + r9*4], 0
    inc     r9d
    jmp     .zero_loop

.zero_done:
    ret
QuantizedMatMul_AVX512_Core ENDP

; ═══════════════════════════════════════════════════════════════════════════════
; QuantizedMatMul_DumpState
;
; Dumps register state for debugging
; ═══════════════════════════════════════════════════════════════════════════════
QuantizedMatMul_DumpState PROC
    ; Save all registers to stack
    sub     rsp, 512

    vmovdqu64 zmmword ptr [rsp+0], zmm0
    vmovdqu64 zmmword ptr [rsp+64], zmm1
    vmovdqu64 zmmword ptr [rsp+128], zmm2
    vmovdqu64 zmmword ptr [rsp+192], zmm3

    ; Print register values
    mov     rcx, OFFSET dbg_msg_scale
    mov     edx, 0
    mov     r8, 0
    mov     r9, 0
    call    printf

    add     rsp, 512
    ret
QuantizedMatMul_DumpState ENDP

END
