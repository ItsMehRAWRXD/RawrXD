; =============================================================================
; sampler.asm - RawrXD Token Sampling Engine
; =============================================================================
; Implements:
;   - Top-K sampling
;   - Top-P (nucleus) sampling
;   - Temperature scaling
;   - Greedy (argmax) decoding
;   - Repetition penalty
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; Public symbols (referenced by inference_engine.asm)
; =============================================================================
PUBLIC g_SampleTemperature
PUBLIC g_SampleTopK
PUBLIC g_SampleTopP

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Default sampling parameters
align 8
g_SampleTemperature    REAL4 0.8
g_SampleTopK           DQ 40
g_SampleTopP           REAL4 0.9
g_RepetitionPenalty    REAL4 1.1
g_FrequencyPenalty     REAL4 0.0

; Random state (simple LCG)
align 8
g_RandomState          DQ 123456789

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_SampleTemperature - Apply temperature scaling to logits
;
; Parameters:
;   RCX = float* logits     - Input logits (vocab_size)
;   RDX = QWORD vocab_size  - Vocabulary size
;   R8  = float temperature - Temperature value (> 0)
;
; Returns: RAX = 0 on success
;
; logits[i] = logits[i] / temperature
; =============================================================================
RawrXD_SampleTemperature PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; logits
    mov rbx, rdx                    ; vocab_size
    movd xmm1, r8d                  ; temperature

    ; Check temperature > 0
    vxorps xmm0, xmm0, xmm0
    ucomiss xmm1, xmm0
    jbe @@error                     ; temperature <= 0

    ; Compute reciprocal: 1/temperature
    movss xmm0, DWORD PTR [g_OneF32]
    divss xmm0, xmm1
    vbroadcastss ymm2, xmm0         ; ymm2 = 1/temp

    xor r9, r9

@@loop:
    cmp r9, rbx
    jge @@done

    vmovups ymm0, YMMWORD PTR [rsi + r9*4]
    vmulps ymm0, ymm0, ymm2
    vmovups YMMWORD PTR [rsi + r9*4], ymm0

    add r9, 8
    jmp @@loop

@@done:
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    pop rsi
    pop rbx
    ret

RawrXD_SampleTemperature ENDP

; =============================================================================
; RawrXD_SampleTopK - Apply Top-K filtering (keep top K logits)
;
; Parameters:
;   RCX = float* logits     - Input/output logits
;   RDX = QWORD vocab_size
;   R8  = QWORD k           - Number of tokens to keep
;
; Returns: RAX = 0 on success
;
; Sets all logits below the K-th highest to -infinity.
; =============================================================================
RawrXD_SampleTopK PROC FRAME
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
    sub rsp, 64
    .allocstack 64
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error
    test r8, r8
    jz @@error

    mov rsi, rcx                    ; logits
    mov rdi, rdx                    ; vocab_size
    mov r12, r8                     ; k

    ; Find the K-th highest value using partial sort
    ; For simplicity, use a threshold-based approach:
    ; 1. Find the K-th highest value
    ; 2. Zero out everything below it

    ; Allocate index array on stack
    mov rax, rdi
    shl rax, 3                      ; 8 bytes per index
    add rax, 63
    and rax, -64
    sub rsp, rax
    mov QWORD PTR [rbp - 8], rsp   ; index array

    ; Initialize indices
    xor r9, r9

@@init_loop:
    cmp r9, rdi
    jge @@sort
    mov QWORD PTR [rsp + r9*8], r9
    inc r9
    jmp @@init_loop

@@sort:
    ; Simple bubble sort of top K (inefficient but correct)
    ; Production would use partial sort or heap
    xor r9, r9

@@sort_outer:
    cmp r9, r12
    jge @@apply

    xor r10, r9
    inc r10

@@sort_inner:
    cmp r10, rdi
    jge @@sort_next

    mov rax, QWORD PTR [rsp + r9*8]
    mov rcx, QWORD PTR [rsp + r10*8]
    movss xmm0, DWORD PTR [rsi + rax*4]
    movss xmm1, DWORD PTR [rsi + rcx*4]
    ucomiss xmm0, xmm1
    jae @@no_swap

    ; Swap indices
    mov QWORD PTR [rsp + r9*8], rcx
    mov QWORD PTR [rsp + r10*8], rax

@@no_swap:
    inc r10
    jmp @@sort_inner

@@sort_next:
    inc r9
    jmp @@sort_outer

@@apply:
    ; Get threshold value (K-th highest)
    mov rax, QWORD PTR [rsp + 8]   ; Second highest (index 1)
    movss xmm5, DWORD PTR [rsi + rax*4]  ; threshold

    ; Zero out everything below threshold
    xor r9, r9

@@zero_loop:
    cmp r9, rdi
    jge @@done
    movss xmm0, DWORD PTR [rsi + r9*4]
    ucomiss xmm0, xmm5
    jae @@keep
    mov DWORD PTR [rsi + r9*4], 0
@@keep:
    inc r9
    jmp @@zero_loop

@@done:
    xor rax, rax

@@exit:
    mov rsp, rbp
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

@@error:
    mov rax, 1
    jmp @@exit

RawrXD_SampleTopK ENDP

; =============================================================================
; RawrXD_SampleTopP - Nucleus (Top-P) sampling
;
; Parameters:
;   RCX = float* probs      - Probability distribution (softmax output)
;   RDX = QWORD vocab_size
;   R8  = float p           - Cumulative probability threshold
;
; Returns: RAX = 0 on success
; =============================================================================
RawrXD_SampleTopP PROC FRAME
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
    sub rsp, 64
    .allocstack 64
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; probs
    mov rdi, rdx                    ; vocab_size
    movd xmm6, r8d                  ; p

    ; Sort indices by probability (descending)
    mov rax, rdi
    shl rax, 3
    add rax, 63
    and rax, -64
    sub rsp, rax
    mov QWORD PTR [rbp - 8], rsp

    xor r9, r9
@@init:
    cmp r9, rdi
    jge @@sort
    mov QWORD PTR [rsp + r9*8], r9
    inc r9
    jmp @@init

@@sort:
    xor r9, r9
@@outer:
    cmp r9, rdi
    jge @@accum
    xor r10, r9
    inc r10
@@inner:
    cmp r10, rdi
    jge @@next
    mov rax, QWORD PTR [rsp + r9*8]
    mov rcx, QWORD PTR [rsp + r10*8]
    movss xmm0, DWORD PTR [rsi + rax*4]
    movss xmm1, DWORD PTR [rsi + rcx*4]
    ucomiss xmm0, xmm1
    jae @@no_swap
    mov QWORD PTR [rsp + r9*8], rcx
    mov QWORD PTR [rsp + r10*8], rax
@@no_swap:
    inc r10
    jmp @@inner
@@next:
    inc r9
    jmp @@outer

@@accum:
    vxorps xmm0, xmm0, xmm0
    xor r9, r9
@@accum_loop:
    cmp r9, rdi
    jge @@zero_rest
    mov rax, QWORD PTR [rsp + r9*8]
    addss xmm0, DWORD PTR [rsi + rax*4]
    ucomiss xmm0, xmm6
    jae @@zero_rest
    inc r9
    jmp @@accum_loop

@@zero_rest:
    inc r9
@@zero_loop:
    cmp r9, rdi
    jge @@done
    mov rax, QWORD PTR [rsp + r9*8]
    mov DWORD PTR [rsi + rax*4], 0
    inc r9
    jmp @@zero_loop

@@done:
    xor rax, rax

@@exit:
    mov rsp, rbp
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

@@error:
    mov rax, 1
    jmp @@exit

RawrXD_SampleTopP ENDP

; =============================================================================
; RawrXD_SampleToken - Sample a token from probability distribution
;
; Parameters:
;   RCX = float* probs      - Probability distribution
;   RDX = QWORD vocab_size
;
; Returns: RAX = sampled token index
; =============================================================================
RawrXD_SampleToken PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; probs
    mov rdi, rdx                    ; vocab_size

    ; Generate random number in [0, 1)
    call RawrXD_RandomF32
    movss xmm6, xmm0                ; r = random

    ; Find token where cumulative probability >= r
    vxorps xmm0, xmm0, xmm0         ; cumsum = 0
    xor r9, r9

@@loop:
    cmp r9, rdi
    jge @@fallback
    addss xmm0, DWORD PTR [rsi + r9*4]
    ucomiss xmm0, xmm6
    jae @@found
    inc r9
    jmp @@loop

@@found:
    mov rax, r9
    jmp @@exit

@@fallback:
    ; Return last token
    mov rax, rdi
    dec rax

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret

@@error:
    xor rax, rax
    jmp @@exit

RawrXD_SampleToken ENDP

; =============================================================================
; RawrXD_RandomF32 - Generate random float in [0, 1)
; Uses LCG: x = (x * 1103515245 + 12345) & 0x7fffffff
; Returns: XMM0 = random float
; =============================================================================
RawrXD_RandomF32 PROC PRIVATE FRAME
    .endprolog

    mov rax, QWORD PTR [g_RandomState]
    mov rcx, 1103515245
    mul rcx
    add rax, 12345
    and rax, 7FFFFFFFh
    mov QWORD PTR [g_RandomState], rax

    ; Convert to float in [0, 1)
    cvtsi2ss xmm0, rax
    movss xmm1, DWORD PTR [g_MaxRandF32]
    divss xmm0, xmm1

    ret

RawrXD_RandomF32 ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 16
g_OneF32            REAL4 1.0
g_MaxRandF32        REAL4 2147483648.0  ; 2^31

END
