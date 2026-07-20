;===========================================================================
; quantized_matmul.asm - Minimal Working Implementation
; RawrXD Fix #4 - Fused Q4_0 Dequant + MatMul
;===========================================================================

OPTION DOTNAME
OPTION CASEMAP:NONE

Q4_0_BLOCK_SIZE EQU 18

PUBLIC QuantizedMatMul_Fused_4K
PUBLIC QuantizedMatMul_Fused_5K
PUBLIC QuantizedMatMul_Dynamic
PUBLIC RawrXD_QuantizedMatMul_Dispatch
PUBLIC RawrXD_KernelRegistry_Init
PUBLIC RawrXD_KernelTelemetry_Begin
PUBLIC RawrXD_KernelTelemetry_End

.CODE

;=============================================================================
; QuantizedMatMul_Fused_4K - Minimal scalar implementation
;=============================================================================
QuantizedMatMul_Fused_4K PROC FRAME
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rbp
    .pushreg rdi
    .pushreg rsi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog

    mov     rsi, rcx              ; RSI = weights
    mov     rdi, r8               ; RDI = output
    mov     r12d, 4096            ; N = 4096
    mov     r13, 128              ; blocks per row (4096/32)

    mov     r14, rdi              ; R14 = output pointer
    mov     r15, rsi              ; R15 = weights pointer
    xor     rbx, rbx              ; RBX = row index

RowLoop:
    vxorps  xmm0, xmm0, xmm0      ; Clear scalar accumulator
    mov     rcx, r13              ; RCX = blocks per row
    mov     rbp, rdx              ; RBP = activation pointer

BlockLoop:
    ; Load scale
    movss   xmm1, dword ptr [r15]
    
    ; Process 32 weights in this block
    mov     r8, r15
    add     r8, 4                 ; R8 = weights data
    mov     r9, 16                ; R9 = 16 bytes (32 nibbles)
    xor     r10, r10              ; R10 = byte index

WeightLoop:
    cmp     r10, r9
    jge     WeightDone
    
    ; Load byte containing 2 weights
    movzx   r11d, byte ptr [r8 + r10]
    
    ; Process lower nibble (weight 0)
    mov     r12d, r11d
    and     r12d, 0Fh             ; Lower 4 bits
    sub     r12d, 8               ; Center: 0-15 -> -8 to +7
    cvtsi2ss xmm2, r12d           ; Convert to float
    mulss   xmm2, xmm1            ; Scale
    movss   xmm3, dword ptr [rbp] ; Load activation
    mulss   xmm2, xmm3            ; Multiply
    addss   xmm0, xmm2            ; Accumulate
    
    ; Process upper nibble (weight 1)
    shr     r11d, 4               ; Upper 4 bits
    and     r11d, 0Fh
    sub     r11d, 8               ; Center
    cvtsi2ss xmm2, r11d
    mulss   xmm2, xmm1            ; Scale
    movss   xmm3, dword ptr [rbp + 4] ; Next activation
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    
    add     rbp, 8                ; 2 activations * 4 bytes
    inc     r10
    jmp     WeightLoop

WeightDone:
    add     r15, Q4_0_BLOCK_SIZE  ; Next block
    dec     rcx
    jnz     BlockLoop
    
    ; Store result
    movss   dword ptr [r14], xmm0
    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    mov     rax, 1
    ret
QuantizedMatMul_Fused_4K ENDP

QuantizedMatMul_Fused_5K PROC FRAME
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rbp
    .pushreg rdi
    .pushreg rsi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog

    mov     rsi, rcx
    mov     rdi, r8
    mov     r12d, 5120
    mov     r13, 160

    mov     r14, rdi
    mov     r15, rsi
    xor     rbx, rbx

RowLoop_5K:
    vxorps  xmm0, xmm0, xmm0
    mov     rcx, r13
    mov     rbp, rdx

BlockLoop_5K:
    movss   xmm1, dword ptr [r15]
    mov     r8, r15
    add     r8, 4
    mov     r9, 16
    xor     r10, r10

WeightLoop_5K:
    cmp     r10, r9
    jge     WeightDone_5K
    movzx   r11d, byte ptr [r8 + r10]
    mov     r12d, r11d
    and     r12d, 0Fh
    sub     r12d, 8
    cvtsi2ss xmm2, r12d
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    shr     r11d, 4
    and     r11d, 0Fh
    sub     r11d, 8
    cvtsi2ss xmm2, r11d
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp + 4]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    add     rbp, 8
    inc     r10
    jmp     WeightLoop_5K

WeightDone_5K:
    add     r15, Q4_0_BLOCK_SIZE
    dec     rcx
    jnz     BlockLoop_5K
    
    movss   dword ptr [r14], xmm0
    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop_5K

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    mov     rax, 1
    ret
QuantizedMatMul_Fused_5K ENDP

QuantizedMatMul_Dynamic PROC FRAME
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rbp
    .pushreg rdi
    .pushreg rsi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog

    mov     rsi, rcx
    mov     rdi, r8
    mov     r12, r9
    mov     r13, qword ptr [rsp+72]
    mov     rax, r13
    shr     rax, 5
    mov     r13, rax

    mov     r14, rdi
    mov     r15, rsi
    xor     rbx, rbx

test    r12, r12
    jz      Dynamic_Done

RowLoop_Dyn:
    vxorps  xmm0, xmm0, xmm0
    mov     rcx, r13
    mov     rbp, rdx

test    rcx, rcx
    jz      RowDone_Dyn

BlockLoop_Dyn:
    movss   xmm1, dword ptr [r15]
    mov     r8, r15
    add     r8, 4
    mov     r9, 16
    xor     r10, r10

WeightLoop_Dyn:
    cmp     r10, r9
    jge     WeightDone_Dyn
    movzx   r11d, byte ptr [r8 + r10]
    mov     eax, r11d
    and     eax, 0Fh
    sub     eax, 8
    cvtsi2ss xmm2, eax
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    shr     r11d, 4
    and     r11d, 0Fh
    sub     r11d, 8
    cvtsi2ss xmm2, r11d
    mulss   xmm2, xmm1
    movss   xmm3, dword ptr [rbp + 4]
    mulss   xmm2, xmm3
    addss   xmm0, xmm2
    add     rbp, 8
    inc     r10
    jmp     WeightLoop_Dyn

WeightDone_Dyn:
    add     r15, Q4_0_BLOCK_SIZE
    dec     rcx
    jnz     BlockLoop_Dyn

RowDone_Dyn:
    movss   dword ptr [r14], xmm0
    add     r14, 4
    inc     rbx
    cmp     rbx, r12
    jl      RowLoop_Dyn

Dynamic_Done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    mov     rax, 1
    ret
QuantizedMatMul_Dynamic ENDP

RawrXD_QuantizedMatMul_Dispatch PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog
    mov     rax, r9
    shr     rax, 10
    dec     rax
    cmp     rax, 7
    ja      Dispatch_Fallback
    cmp     rax, 3
    je      Dispatch_4K
    cmp     rax, 4
    je      Dispatch_5K
Dispatch_Fallback:
    pop     rbx
    jmp     QuantizedMatMul_Dynamic
Dispatch_4K:
    pop     rbx
    jmp     QuantizedMatMul_Fused_4K
Dispatch_5K:
    pop     rbx
    jmp     QuantizedMatMul_Fused_5K
RawrXD_QuantizedMatMul_Dispatch ENDP

RawrXD_KernelRegistry_Init PROC
    mov     rax, 1
    ret
RawrXD_KernelRegistry_Init ENDP

RawrXD_KernelTelemetry_Begin PROC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
RawrXD_KernelTelemetry_Begin ENDP

RawrXD_KernelTelemetry_End PROC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
RawrXD_KernelTelemetry_End ENDP

END
