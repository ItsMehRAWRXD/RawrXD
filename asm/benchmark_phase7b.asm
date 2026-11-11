; ============================================================================
; benchmark_phase7b.asm - Phase 7B Benchmark Harness
; ============================================================================
; Measures baseline performance for Q4_0_Q8_0_MatMul and FlashAttentionV2
; ============================================================================

.686p
.xmm
option casemap:none
option frame:auto
option win64:3
option align:64

; ----------------------------------------------------------------------------
; External Imports
; ----------------------------------------------------------------------------
EXTERN QueryPerformanceCounter:PROC
EXTERN QueryPerformanceFrequency:PROC

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data
ALIGN 64

; Benchmark configuration
BENCH_ITERATIONS EQU 100
WARMUP_ITERATIONS EQU 10

; Test matrix sizes (typical LLM dimensions)
TEST_M EQU 64
TEST_N EQU 64
TEST_K EQU 64

; Timing storage
qpc_start       QWORD 0
qpc_end         QWORD 0
qpc_freq        QWORD 0

; Results storage (cycles per operation)
result_q4q8_matmul      QWORD 0
result_flash_attn       QWORD 0

; Test buffers (simplified - in real benchmark would allocate dynamically)
ALIGN 64
test_buffer_A   BYTE 4096 DUP(0)   ; Q4_0 quantized
ALIGN 64
test_buffer_B   BYTE 8192 DUP(0)   ; Q8_0 quantized
ALIGN 64
test_buffer_C   REAL4 4096 DUP(0.0) ; Result matrix

; Flash attention buffers
ALIGN 64
test_Q          REAL4 4096 DUP(0.1)
ALIGN 64
test_K          REAL4 4096 DUP(0.1)
ALIGN 64
test_V          REAL4 4096 DUP(0.1)
ALIGN 64
test_attn_out   REAL4 4096 DUP(0.0)

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code
ALIGN 64

; ============================================================================
; BenchmarkEntry - Main benchmark routine
; ============================================================================
Sovereign_Benchmark_Phase7B PROC FRAME
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
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 128
    .allocstack 128
    .endprolog
    
    ; Get QPC frequency
    lea rcx, qpc_freq
    call QueryPerformanceFrequency
    
    ; ================================================================
    ; Benchmark 1: Q4_0_Q8_0_MatMul
    ; ================================================================
    call Benchmark_Q4Q8_MatMul
    mov result_q4q8_matmul, rax
    
    ; ================================================================
    ; Benchmark 2: FlashAttentionV2
    ; ================================================================
    call Benchmark_FlashAttentionV2
    mov result_flash_attn, rax
    
    ; Return results in RAX:RDX
    mov rax, result_q4q8_matmul
    mov rdx, result_flash_attn
    
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Benchmark_Phase7B ENDP

; ============================================================================
; Benchmark_Q4Q8_MatMul - Measure Q4_0_Q8_0_MatMul performance
; Returns: RAX = cycles per operation (approximate)
; ============================================================================
Benchmark_Q4Q8_MatMul PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 64
    .allocstack 64
    .endprolog
    
    ; Warmup
    mov r12, WARMUP_ITERATIONS
@@warmup_loop:
    lea rcx, test_buffer_A
    lea rdx, test_buffer_B
    lea r8, test_buffer_C
    mov r9, TEST_M
    mov r10, TEST_N
    mov r11, TEST_K
    call q4_0_q8_0_matmul
    dec r12
    jnz @@warmup_loop
    
    ; Start timing
    lea rcx, qpc_start
    call QueryPerformanceCounter
    
    ; Benchmark loop
    mov r12, BENCH_ITERATIONS
@@bench_loop:
    lea rcx, test_buffer_A
    lea rdx, test_buffer_B
    lea r8, test_buffer_C
    mov r9, TEST_M
    mov r10, TEST_N
    mov r11, TEST_K
    call q4_0_q8_0_matmul
    dec r12
    jnz @@bench_loop
    
    ; End timing
    lea rcx, qpc_end
    call QueryPerformanceCounter
    
    ; Calculate cycles (QPC difference)
    mov rax, qpc_end
    sub rax, qpc_start
    
    ; Divide by iterations
    xor edx, edx
    mov rcx, BENCH_ITERATIONS
    div rcx
    
    add rsp, 64
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Benchmark_Q4Q8_MatMul ENDP

; ============================================================================
; Benchmark_FlashAttentionV2 - Measure FlashAttentionV2 performance
; Returns: RAX = cycles per operation (approximate)
; ============================================================================
Benchmark_FlashAttentionV2 PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 64
    .allocstack 64
    .endprolog
    
    ; Warmup
    mov r12, WARMUP_ITERATIONS
@@warmup_loop:
    lea rcx, test_Q
    lea rdx, test_K
    lea r8, test_V
    lea r9, test_attn_out
    mov r10, 64     ; seq_len
    mov r11, 64     ; head_dim
    call flash_attention_v2_f32
    dec r12
    jnz @@warmup_loop
    
    ; Start timing
    lea rcx, qpc_start
    call QueryPerformanceCounter
    
    ; Benchmark loop
    mov r12, BENCH_ITERATIONS
@@bench_loop:
    lea rcx, test_Q
    lea rdx, test_K
    lea r8, test_V
    lea r9, test_attn_out
    mov r10, 64
    mov r11, 64
    call flash_attention_v2_f32
    dec r12
    jnz @@bench_loop
    
    ; End timing
    lea rcx, qpc_end
    call QueryPerformanceCounter
    
    ; Calculate cycles
    mov rax, qpc_end
    sub rax, qpc_start
    
    ; Divide by iterations
    xor edx, edx
    mov rcx, BENCH_ITERATIONS
    div rcx
    
    add rsp, 64
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Benchmark_FlashAttentionV2 ENDP

; ============================================================================
; External C API declarations (from resurrected kernels)
; ============================================================================
EXTERN flash_attention_v2_f32:PROC
EXTERN q4_0_q8_0_matmul:PROC

; ============================================================================
; End of Module
; ============================================================================
END
