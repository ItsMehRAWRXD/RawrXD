;=============================================================================
; Quantized Matrix Multiplication Kernels - DEBUG VERSION
; Fix #4: Fused Dequantization + MatMul for Q4_0 Weights
;=============================================================================
; This debug version includes instrumentation to diagnose inf/-nan issues
;=============================================================================

PUBLIC QuantizedMatMul_Debug_4K

; Debug output helper - prints register value to stdout
; Uses Windows WriteConsoleA for debugging
EXTERNDEF DebugPrintInt64:PROC
EXTERNDEF DebugPrintFloat:PROC
EXTERNDEF DebugPrintString:PROC

.data
    ; Debug strings
    dbg_row_start       db "=== Row ", 0
    dbg_row_end         db " ===", 13, 10, 0
    dbg_accum_pre       db "  Accum pre-dequant: ", 0
    dbg_accum_post      db "  Accum post-dequant: ", 0
    dbg_scale_val       db "  Scale value: ", 0
    dbg_weight_val      db "  Weight value: ", 0
    dbg_final           db "  Final result: ", 0
    dbg_newline         db 13, 10, 0
    
    ; Q4_0 block constants
    Q4_0_BLOCK_SIZE     equ 18          ; 16 nibbles + 2 bytes scale
    Q4_0_VALUES_PER_BLK equ 32          ; 32 values per block (16 bytes * 2 nibbles)

.code

;=============================================================================
; Debug Version - 4K Kernel with Instrumentation
;=============================================================================
QuantizedMatMul_Debug_4K PROC \
    output:QWORD, weights:QWORD, input:QWORD, scales:QWORD, M:DWORD, N:DWORD, K:DWORD
    
    ; Save non-volatile registers
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 128                    ; Shadow space + local vars
    
    ; Store parameters
    mov     r12, rcx                    ; output
    mov     r13, rdx                    ; weights
    mov     r14, r8                     ; input
    mov     r15, r9                     ; scales
    
    mov     [rbp-8], r12                ; output
    mov     [rbp-16], r13               ; weights
    mov     [rbp-24], r14               ; input
    mov     [rbp-32], r15               ; scales
    mov     [rbp-40], rcx               ; M (rows)
    mov     [rbp-48], rdx               ; N (cols) - should be 1 for MV
    mov     [rbp-56], r8                ; K (inner dim)
    
    ; Debug: Print entry
    lea     rcx, dbg_row_start
    call    DebugPrintString
    
    ; Calculate blocks per row = K / 32
    mov     eax, [rbp-56]               ; K
    shr     eax, 5                      ; K / 32
    mov     [rbp-64], eax               ; blocks_per_row
    
    ; Row loop
    xor     ebx, ebx                    ; row = 0
    
.row_loop:
    cmp     ebx, [rbp-40]
    jge     .done
    
    ; Debug: Print row number
    lea     rcx, dbg_row_start
    call    DebugPrintString
    mov     rcx, rbx
    call    DebugPrintInt64
    lea     rcx, dbg_row_end
    call    DebugPrintString
    
    ; Initialize accumulator to 0
    vxorps  xmm0, xmm0, xmm0            ; accum = 0.0
    vmovss  dword ptr [rbp-72], xmm0    ; Store accum
    
    ; Calculate row offset in weights
    ; row_offset = row * blocks_per_row * Q4_0_BLOCK_SIZE
    mov     eax, ebx                    ; row
    imul    eax, [rbp-64]               ; row * blocks_per_row
    imul    eax, Q4_0_BLOCK_SIZE       ; * block_size
    mov     r8d, eax                    ; row_offset
    
    ; Debug: Print row offset
    lea     rcx, dbg_row_start
    call    DebugPrintString
    mov     rcx, r8
    call    DebugPrintInt64
    lea     rcx, dbg_newline
    call    DebugPrintString
    
    ; Block loop
    xor     r9d, r9d                    ; block = 0
    
.block_loop:
    cmp     r9d, [rbp-64]
    jge     .row_done
    
    ; Calculate block pointer
    ; block_ptr = weights + row_offset + block * Q4_0_BLOCK_SIZE
    mov     eax, r9d
    imul    eax, Q4_0_BLOCK_SIZE
    add     eax, r8d                    ; + row_offset
    mov     r10, r13                    ; weights base
    add     r10, rax                    ; block_ptr
    
    ; Load scale (first 2 bytes of block)
    movzx   eax, word ptr [r10]         ; scale (half-precision or uint16)
    ; Convert to float - assume uint16 for now
    cvtsi2ss xmm1, eax                  ; scale as float
    movss   dword ptr [rbp-80], xmm1    ; store scale
    
    ; Debug: Print scale
    lea     rcx, dbg_scale_val
    call    DebugPrintString
    movss   xmm0, dword ptr [rbp-80]
    call    DebugPrintFloat
    lea     rcx, dbg_newline
    call    DebugPrintString
    
    ; Process 32 values in this block
    ; For each pair of nibbles, dequantize and accumulate
    add     r10, 2                      ; Skip scale, point to weights
    
    xor     r11d, r11d                  ; nibble pair index
    
.nibble_loop:
    cmp     r11d, 16                    ; 16 bytes = 32 nibbles
    jge     .block_done
    
    ; Load byte containing 2 nibbles
    movzx   eax, byte ptr [r10 + r11]   ; Load weight byte
    
    ; Extract low nibble (values 0-15)
    mov     edx, eax
    and     edx, 0x0F                   ; low nibble
    sub     edx, 8                      ; zero-point: (nibble - 8)
    cvtsi2ss xmm2, edx                  ; Convert to float
    
    ; Load corresponding input value
    ; input_idx = block * 32 + nibble * 2
    mov     edx, r9d
    shl     edx, 5                      ; block * 32
    mov     ecx, r11d
    shl     ecx, 1                      ; nibble * 2
    add     edx, ecx                    ; + offset
    
    ; Bounds check
    cmp     edx, [rbp-56]               ; Compare with K
    jge     .skip_low
    
    mov     r15, r14                    ; input base
    movss   xmm3, dword ptr [r15 + rdx*4] ; Load input[...]
    
    ; Dequantize: (nibble - 8) * scale * input
    mulss   xmm2, xmm3                  ; * input
    mulss   xmm2, dword ptr [rbp-80]    ; * scale
    
    ; Add to accumulator
    movss   xmm0, dword ptr [rbp-72]
    addss   xmm0, xmm2
    vmovss  dword ptr [rbp-72], xmm0
    
    ; Debug: Print intermediate
    lea     rcx, dbg_accum_post
    call    DebugPrintString
    movss   xmm0, dword ptr [rbp-72]
    call    DebugPrintFloat
    lea     rcx, dbg_newline
    call    DebugPrintString
    
.skip_low:
    
    ; Extract high nibble (values 0-15)
    mov     edx, eax
    shr     edx, 4                      ; high nibble
    and     edx, 0x0F
    sub     edx, 8                      ; zero-point
    cvtsi2ss xmm2, edx
    
    ; Load corresponding input value (nibble * 2 + 1)
    mov     edx, r9d
    shl     edx, 5                      ; block * 32
    mov     ecx, r11d
    shl     ecx, 1                      ; nibble * 2
    add     edx, ecx
    add     edx, 1                      ; + 1 for high nibble
    
    ; Bounds check
    cmp     edx, [rbp-56]
    jge     .skip_high
    
    mov     r15, r14
    movss   xmm3, dword ptr [r15 + rdx*4]
    
    ; Dequantize and accumulate
    mulss   xmm2, xmm3
    mulss   xmm2, dword ptr [rbp-80]
    
    movss   xmm0, dword ptr [rbp-72]
    addss   xmm0, xmm2
    vmovss  dword ptr [rbp-72], xmm0
    
.skip_high:
    
    inc     r11d
    jmp     .nibble_loop
    
.block_done:
    inc     r9d
    jmp     .block_loop
    
.row_done:
    ; Store result
    mov     eax, ebx                    ; row
    mov     r10, r12                    ; output
    movss   xmm0, dword ptr [rbp-72]
    movss   dword ptr [r10 + rax*4], xmm0
    
    ; Debug: Print final result
    lea     rcx, dbg_final
    call    DebugPrintString
    call    DebugPrintFloat
    lea     rcx, dbg_newline
    call    DebugPrintString
    
    inc     ebx
    jmp     .row_loop
    
.done:
    ; Restore registers
    add     rsp, 128
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
    
QuantizedMatMul_Debug_4K ENDP

END
