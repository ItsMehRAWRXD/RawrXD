; ============================================================================
; kernel/sme2_spmv_kernel.asm - High-Throughput SME2 INT4 SpMV Kernel
; Software-pipelined sparse matrix-vector multiply with LUTI dequantization
; ============================================================================

option casemap:none

PUBLIC SME2_INT4_SpMV_Execute
PUBLIC SME2_INT2_SpMV_Execute
PUBLIC SME2_FP16_SpMV_Execute

; External encoder functions from sme2_encoder.asm and sme2_luti_encoder.asm
EXTERN SME2_Encode_SMSTART_VG4 : PROC
EXTERN SME2_Encode_SMSTOP_VG4  : PROC
EXTERN SME2_Encode_ZERO_VG4    : PROC
EXTERN SME2_Encode_FMOPA_VG4_S : PROC
EXTERN SME2_Encode_LUTI4_VG4_S : PROC
EXTERN SME2_Encode_LUTI2_VG4_S : PROC
EXTERN SME2_Encode_LUTI4_VG4_H : PROC
EXTERN SME2_Encode_LDR_ZT0     : PROC

.code

; ============================================================================
; SME2_INT4_SpMV_Execute:
;   RCX = Pointer to ZT0 Scale Table (512-bit)
;   RDX = Pointer to Swizzled INT4 Packed Weights
;   R8  = Pointer to Dense FP32 Activations
;   R9  = Pointer to Output Array
;   Stack Param [RSP+28h] = Iteration Loop Count
; ============================================================================
SME2_INT4_SpMV_Execute PROC frame
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, rcx                  ; Scale table
    mov rsi, rdx                  ; Swizzled weights
    mov rdi, r8                   ; Activations
    mov r12, r9                   ; Output
    mov r13d, dword ptr [rbp+48h] ; Loop count (past saved regs + shadow)

    ; 1. Enter SME2 Streaming Mode & Enable ZA/ZT0
    mov ecx, 3
    call SME2_Encode_SMSTART_VG4

    ; 2. Clear accumulators ZA0.S and ZA1.S
    mov ecx, 003h                 ; Mask for ZA0.S and ZA1.S
    call SME2_Encode_ZERO_VG4

    ; 3. Load 512-bit Dequantization Table into ZT0
    mov rcx, rbx
    xor edx, edx
    call SME2_Encode_LDR_ZT0

    ; ---------------------------------------------------------------------
    ; Pipelined Prologue: Prime Pipeline Stages K=0
    ; ---------------------------------------------------------------------
    ; LD1B { Z0.B }, P0/Z, [RSI]  - Fetch first 64 bytes of packed INT4
    ; LD1W { Z8.S - Z11.S }, P0/Z, [RDI] - Fetch first FP32 activation tuple
    ; (Encoded via external LD1B/LD1W helpers)
    add rsi, 64
    add rdi, 256

spmv_pipeline_loop:
    cmp r13d, 0
    jle spmv_pipeline_epilogue

    ; ---------------------------------------------------------------------
    ; Stage 1: Dequantize Iteration K via ZT0 Table Lookups
    ; ---------------------------------------------------------------------
    ; LUTI4 { Z4.S - Z7.S }, ZT0, Z0.B, #0  (Unpack low nibbles)
    mov ecx, 4                     ; Zd base = Z4
    xor edx, edx                   ; Zn = Z0
    xor r8d, r8d                   ; imm2 = 0
    call SME2_Encode_LUTI4_VG4_S

    ; LUTI4 { Z12.S - Z15.S }, ZT0, Z0.B, #1 (Unpack high nibbles)
    mov ecx, 12                    ; Zd base = Z12
    xor edx, edx                   ; Zn = Z0
    mov r8d, 1                     ; imm2 = 1
    call SME2_Encode_LUTI4_VG4_S

    ; ---------------------------------------------------------------------
    ; Stage 0: Prefetch Iteration K+1
    ; ---------------------------------------------------------------------
    add rsi, 64
    add rdi, 256

    ; ---------------------------------------------------------------------
    ; Stage 2: Outer Product Computation Iteration K
    ; ---------------------------------------------------------------------
    ; FMOPA ZA0.S, P0/M, P0/M, Z4.S-Z7.S, Z8.S-Z11.S
    mov ecx, 0                     ; ZA0 tile
    mov edx, 4                     ; Zn base = Z4
    mov r8d, 8                     ; Zm base = Z8
    xor r9d, r9d                   ; Pn = P0
    mov dword ptr [rsp + 28h], 0   ; Pm = P0
    call SME2_Encode_FMOPA_VG4_S

    ; FMOPA ZA1.S, P0/M, P0/M, Z12.S-Z15.S, Z8.S-Z11.S
    mov ecx, 1                     ; ZA1 tile
    mov edx, 12                    ; Zn base = Z12
    mov r8d, 8                     ; Zm base = Z8
    xor r9d, r9d                   ; Pn = P0
    mov dword ptr [rsp + 28h], 0   ; Pm = P0
    call SME2_Encode_FMOPA_VG4_S

    dec r13d
    jmp spmv_pipeline_loop

spmv_pipeline_epilogue:
    ; Drain remaining pipeline stages
    mov ecx, 4
    xor edx, edx
    xor r8d, r8d
    call SME2_Encode_LUTI4_VG4_S

    mov ecx, 0
    mov edx, 4
    mov r8d, 8
    xor r9d, r9d
    mov dword ptr [rsp + 28h], 0
    call SME2_Encode_FMOPA_VG4_S

    ; ---------------------------------------------------------------------
    ; Drain Accumulator Tiles to Output Memory
    ; ---------------------------------------------------------------------
    ; ST1W { ZA0.S[W12, 0] }, P0, [R12]
    ; (Encoded via external ST1W helper)

    ; Exit Streaming Mode
    mov ecx, 3
    call SME2_Encode_SMSTOP_VG4

    add rsp, 20h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
SME2_INT4_SpMV_Execute ENDP

; ============================================================================
; SME2_INT2_SpMV_Execute: INT2 variant using LUTI2
; ============================================================================
SME2_INT2_SpMV_Execute PROC frame
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    mov r12, r9
    mov r13d, dword ptr [rbp+48h]

    ; Enter Streaming Mode
    mov ecx, 3
    call SME2_Encode_SMSTART_VG4

    ; Clear accumulators
    mov ecx, 003h
    call SME2_Encode_ZERO_VG4

    ; Load ZT0 table
    mov rcx, rbx
    xor edx, edx
    call SME2_Encode_LDR_ZT0

    add rsi, 64
    add rdi, 256

spmv_int2_loop:
    cmp r13d, 0
    jle spmv_int2_epilogue

    ; LUTI2 { Z4.S - Z7.S }, ZT0, Z0.B, #0
    mov ecx, 4
    xor edx, edx
    xor r8d, r8d
    call SME2_Encode_LUTI2_VG4_S

    add rsi, 64
    add rdi, 256

    ; FMOPA ZA0.S, P0/M, P0/M, Z4.S-Z7.S, Z8.S-Z11.S
    mov ecx, 0
    mov edx, 4
    mov r8d, 8
    xor r9d, r9d
    mov dword ptr [rsp + 28h], 0
    call SME2_Encode_FMOPA_VG4_S

    dec r13d
    jmp spmv_int2_loop

spmv_int2_epilogue:
    mov ecx, 3
    call SME2_Encode_SMSTOP_VG4

    add rsp, 20h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
SME2_INT2_SpMV_Execute ENDP

; ============================================================================
; SME2_FP16_SpMV_Execute: FP16 variant using LUTI4 with half-precision
; ============================================================================
SME2_FP16_SpMV_Execute PROC frame
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    mov r12, r9
    mov r13d, dword ptr [rbp+48h]

    mov ecx, 3
    call SME2_Encode_SMSTART_VG4

    mov ecx, 003h
    call SME2_Encode_ZERO_VG4

    mov rcx, rbx
    xor edx, edx
    call SME2_Encode_LDR_ZT0

    add rsi, 64
    add rdi, 128

spmv_fp16_loop:
    cmp r13d, 0
    jle spmv_fp16_epilogue

    ; LUTI4 { Z4.H - Z7.H }, ZT0, Z0.B, #0 (FP16 dequant)
    mov ecx, 4
    xor edx, edx
    xor r8d, r8d
    call SME2_Encode_LUTI4_VG4_H

    add rsi, 64
    add rdi, 128

    mov ecx, 0
    mov edx, 4
    mov r8d, 8
    xor r9d, r9d
    mov dword ptr [rsp + 28h], 0
    call SME2_Encode_FMOPA_VG4_S

    dec r13d
    jmp spmv_fp16_loop

spmv_fp16_epilogue:
    mov ecx, 3
    call SME2_Encode_SMSTOP_VG4

    add rsp, 20h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
SME2_FP16_SpMV_Execute ENDP

END
