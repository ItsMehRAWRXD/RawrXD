; =============================================================================
; Sovereign_AMX_Kernels.asm
; Intel AMX (Advanced Matrix Extensions) Optimized Kernels
; Phase 17: Hybrid Auto / AMX Optimizations
;
; Target: Intel Sapphire Rapids+ (4th Gen Xeon Scalable)
; Requires: AMX-TILE, AMX-BF16 (CPUID leaf 7, EDX bit 24, 22)
;
; Performance Target: 4x speedup over AVX-512 for large GEMM
; =============================================================================

; External functions
EXTERN GetCurrentProcess:PROC
EXTERN SetThreadAffinityMask:PROC
EXTERN GetLastError:PROC

; =============================================================================
; Data Section
; =============================================================================

.data

; Tile configuration for 16×16 BF16 tiles
; Each tile: 16 rows × 16 cols × 2 bytes = 512 bytes
tile_config_struct LABEL BYTE
    db 64                 ; palette_id (64 bytes)
    db 1                  ; start_row
    db 0                  ; reserved
    db 0                  ; reserved
    ; Tile 0: 16×16
    dw 16                 ; rows
    dw 16                 ; cols
    ; Tile 1: 16×16
    dw 16
    dw 16
    ; Tile 2: 16×16
    dw 16
    dw 16
    ; Tile 3: 16×16
    dw 16
    dw 16
    ; Tile 4-7: 16×16 (output tiles)
    dw 16, 16, 16, 16, 16, 16, 16, 16
tile_config_struct_end:

TILE_CONFIG_SIZE EQU (tile_config_struct_end - tile_config_struct)

; Constants
AMX_TILE_ROWS       EQU 16
AMX_TILE_COLS       EQU 16
AMX_BF16_SIZE       EQU 2       ; 2 bytes per BF16
TILE_BYTES          EQU (AMX_TILE_ROWS * AMX_TILE_COLS * AMX_BF16_SIZE)  ; 512 bytes

; Error codes
AMX_SUCCESS         EQU 0
AMX_ERR_NO_CPUID    EQU 1
AMX_ERR_NO_AMX      EQU 2
AMX_ERR_NO_OS       EQU 3

; =============================================================================
; Code Section
; =============================================================================

.code

; =============================================================================
; Sovereign_AMX_Detect
; Detects Intel AMX support via CPUID
;
; Output:
;   EAX = 0 if AMX supported, error code otherwise
; =============================================================================

Sovereign_AMX_Detect PROC FRAME
    push    rbx
    .pushreg rbx
    push    rcx
    .pushreg rcx
    push    rdx
    .pushreg rdx
    .endprolog
    
    ; Check max CPUID leaf
    mov     eax, 0
    cpuid
    cmp     eax, 7
    jb      NO_CPUID
    
    ; Check for AMX-TILE (leaf 7, subleaf 0, EDX bit 24)
    mov     eax, 7
    mov     ecx, 0
    cpuid
    test    edx, (1 SHL 24)     ; AMX-TILE
    jz      NO_AMX
    
    ; Check for AMX-BF16 (EDX bit 22)
    test    edx, (1 SHL 22)     ; AMX-BF16
    jz      NO_AMX
    
    ; Check for OS support via XCR0
    ; AMX requires XCR0[17:18] = 11b (tile config + tile data)
    mov     ecx, 0
    xgetbv                      ; Read XCR0 into EDX:EAX
    and     eax, 060000h        ; Check bits 17-18
    cmp     eax, 060000h
    jne     NO_OS
    
    ; AMX is supported and enabled
    xor     eax, eax            ; Return AMX_SUCCESS
    jmp     DETECT_DONE
    
NO_CPUID:
    mov     eax, AMX_ERR_NO_CPUID
    jmp     DETECT_DONE
    
NO_AMX:
    mov     eax, AMX_ERR_NO_AMX
    jmp     DETECT_DONE
    
NO_OS:
    mov     eax, AMX_ERR_NO_OS
    
DETECT_DONE:
    pop     rdx
    pop     rcx
    pop     rbx
    ret
    
Sovereign_AMX_Detect ENDP

; =============================================================================
; Sovereign_AMX_Init
; Initialize AMX tile configuration
;
; Output:
;   EAX = 0 on success, error code on failure
; =============================================================================

Sovereign_AMX_Init PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    
    ; Load tile configuration
    lea     rax, tile_config_struct
    ldtilecfg [rax]             ; Load tile configuration
    
    xor     eax, eax            ; Success
    
    pop     rbx
    ret
    
Sovereign_AMX_Init ENDP

; =============================================================================
; Sovereign_AMX_AttentionQK
; Optimized attention Q×K^T using AMX BF16 tiles
;
; Input:
;   RCX = Q matrix pointer [seq_len × head_dim] BF16
;   RDX = K matrix pointer [seq_len × head_dim] BF16 (transposed)
;   R8  = Output scores pointer [seq_len × seq_len] FP32
;   R9  = seq_len
;   [RSP+0x28] = head_dim
;
; Clobbers: All except non-volatile registers
; =============================================================================

Sovereign_AMX_AttentionQK PROC FRAME
    ; Save non-volatile registers
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; Store parameters
    mov     r12, rcx            ; Q matrix
    mov     r13, rdx            ; K matrix (transposed)
    mov     r14, r8             ; Output
    mov     r15, r9             ; seq_len
    mov     rbx, [rsp+64+028h]  ; head_dim (from stack)
    
    ; Initialize tile configuration
    call    Sovereign_AMX_Init
    test    eax, eax
    jnz     AMX_QK_EXIT         ; Init failed
    
    ; Calculate strides
    mov     r8, rbx
    shl     r8, 1               ; head_dim * 2 (BF16 stride)
    
    ; Outer loop: iterate over Q tiles (rows)
    xor     r9, r9              ; q_row = 0
Q_ROW_LOOP:
    cmp     r9, r15
    jge     QK_DONE
    
    ; Load Q tile (16 rows × head_dim cols)
    ; tmm0 = Q[q_row:q_row+16, :]
    mov     rax, r9
    mul     r8                  ; rax = q_row * head_dim * 2
    lea     rsi, [r12 + rax]    ; rsi = &Q[q_row, 0]
    
    tileloadd tmm0, [rsi + r8]  ; Load Q tile
    
    ; Inner loop: iterate over K tiles (columns)
    xor     r10, r10            ; k_col = 0
K_COL_LOOP:
    cmp     r10, r15
    jge     NEXT_Q_ROW
    
    ; Load K^T tile (head_dim rows × 16 cols)
    ; tmm1 = K[:, k_col:k_col+16]
    mov     rax, r10
    shl     rax, 1              ; rax = k_col * 2
    lea     rsi, [r13 + rax]    ; rsi = &K[0, k_col]
    
    tileloadd tmm1, [rsi + r8]  ; Load K tile
    
    ; Compute Q × K^T using BF16 dot product
    ; tmm2 += tmm0 * tmm1
    tdpbf16ps tmm2, tmm0, tmm1  ; Tile dot product
    
    ; Store result tile to output
    mov     rax, r9
    mul     r15                 ; rax = q_row * seq_len
    add     rax, r10            ; rax = q_row * seq_len + k_col
    shl     rax, 2              ; rax *= 4 (FP32)
    lea     rdi, [r14 + rax]    ; rdi = &scores[q_row, k_col]
    
    tilestored [rdi], tmm2      ; Store result
    
    ; Zero output tile for next accumulation
    tilezero tmm2
    
    add     r10, AMX_TILE_COLS  ; k_col += 16
    jmp     K_COL_LOOP
    
NEXT_Q_ROW:
    add     r9, AMX_TILE_ROWS     ; q_row += 16
    jmp     Q_ROW_LOOP
    
QK_DONE:
    ; Release tile configuration
    tilerelease
    
    xor     eax, eax            ; Success
    
AMX_QK_EXIT:
    ; Restore stack and registers
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
    
Sovereign_AMX_AttentionQK ENDP

; =============================================================================
; Sovereign_AMX_FFN_GEMM
; Optimized Feed-Forward Network GEMM using AMX
;
; Input:
;   RCX = Input activations [batch × in_features] BF16
;   RDX = Weights [out_features × in_features] BF16
;   R8  = Output [batch × out_features] FP32
;   R9  = batch_size
;   [RSP+0x28] = in_features
;   [RSP+0x30] = out_features
; =============================================================================

Sovereign_AMX_FFN_GEMM PROC FRAME
    ; Save non-volatile registers
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 80
    .allocstack 80
    .endprolog
    
    ; Store parameters
    mov     r12, rcx            ; Input
    mov     r13, rdx            ; Weights
    mov     r14, r8             ; Output
    mov     r15, r9             ; batch_size
    mov     rbx, [rsp+80+028h]  ; in_features
    mov     r9, [rsp+80+030h]   ; out_features
    
    ; Initialize AMX
    call    Sovereign_AMX_Init
    test    eax, eax
    jnz     AMX_FFN_EXIT
    
    ; Calculate strides
    mov     r10, rbx
    shl     r10, 1              ; in_features * 2 (BF16)
    
    ; Outer loop: batch tiles
    xor     r11, r11            ; batch_idx = 0
BATCH_LOOP:
    cmp     r11, r15
    jge     FFN_DONE
    
    ; Load input tile
    mov     rax, r11
    mul     r10                 ; rax = batch_idx * in_features * 2
    lea     rsi, [r12 + rax]
    tileloadd tmm0, [rsi + r10]
    
    ; Inner loop: output features
    xor     r8, r8              ; out_idx = 0
OUT_LOOP:
    cmp     r8, r9
    jge     NEXT_BATCH
    
    ; Load weight tile
    mov     rax, r8
    mul     r10                 ; rax = out_idx * in_features * 2
    lea     rsi, [r13 + rax]
    tileloadd tmm1, [rsi + r10]
    
    ; GEMM: output += input × weights
    tdpbf16ps tmm2, tmm0, tmm1
    
    ; Store result
    mov     rax, r11
    mul     r9                  ; rax = batch_idx * out_features
    add     rax, r8             ; rax += out_idx
    shl     rax, 2              ; FP32
    lea     rdi, [r14 + rax]
    tilestored [rdi], tmm2
    
    tilezero tmm2               ; Clear for next
    
    add     r8, AMX_TILE_COLS   ; out_idx += 16
    jmp     OUT_LOOP
    
NEXT_BATCH:
    add     r11, AMX_TILE_ROWS    ; batch_idx += 16
    jmp     BATCH_LOOP
    
FFN_DONE:
    tilerelease
    xor     eax, eax
    
AMX_FFN_EXIT:
    add     rsp, 80
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
    
Sovereign_AMX_FFN_GEMM ENDP

; =============================================================================
; Sovereign_AMX_Cleanup
; Release AMX resources
; =============================================================================

Sovereign_AMX_Cleanup PROC FRAME
    .endprolog
    ; Release tile configuration
    tilerelease
    ret
Sovereign_AMX_Cleanup ENDP

; =============================================================================
; Export Table
; =============================================================================

PUBLIC Sovereign_AMX_Detect
PUBLIC Sovereign_AMX_Init
PUBLIC Sovereign_AMX_AttentionQK
PUBLIC Sovereign_AMX_FFN_GEMM
PUBLIC Sovereign_AMX_Cleanup

END
