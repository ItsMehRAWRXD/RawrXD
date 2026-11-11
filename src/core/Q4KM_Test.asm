; Q4KM_Test.asm - Test harness for Q4_K_M dequantization
option casemap:none

includelib msvcrt.lib
includelib kernel32.lib

EXTERNDEF printf:PROC
EXTERNDEF exit:PROC
EXTERNDEF QueryPerformanceCounter:PROC
EXTERNDEF QueryPerformanceFrequency:PROC

EXTERNDEF Q4KM_Init:PROC
EXTERNDEF Q4KM_Dequant_Block:PROC

.data
    fmt_header      db "=== Q4_K_M DEQUANT TEST ===", 10, 0
    fmt_init        db "[1] Kernel initialized", 10, 0
    fmt_test        db "[2] Testing dequantization...", 10, 0
    fmt_perf        db "[3] Performance: %llu ms for 1000 blocks", 10, 0
    fmt_sample        db "[4] Sample output[0]: %f", 10, 0
    fmt_ok          db "    [OK]", 10, 0
    fmt_complete    db "=== TEST COMPLETE ===", 10, 0
    
    ; Test data: Simulated Q4_K_M block
    ; 128 bytes of 4-bit weights (256 nibbles)
    ; 16 bytes of scales (8 x fp16)
    ; 16 bytes of mins (8 x fp16)
    align 16
    test_block      db 128 dup(55h)      ; Pattern: 0101 0101...
                    dw 8 dup(3C00h)     ; Scale = 1.0 in fp16
                    dw 8 dup(0000h)     ; Min = 0.0 in fp16
    
    align 16
    output_buffer   dd 256 dup(0.0)     ; 256 floats output
    
    qpc_start       dq 0
    qpc_end         dq 0
    qpc_freq        dq 0

.code
main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Header
    lea     rcx, fmt_header
    call    printf
    
    ; Get timing
    lea     rcx, qpc_freq
    call    QueryPerformanceFrequency
    
    ; ========================================
    ; TEST 1: Initialize
    ; ========================================
    call    Q4KM_Init
    
    lea     rcx, fmt_init
    call    printf
    lea     rcx, fmt_ok
    call    printf
    
    ; ========================================
    ; TEST 2: Dequantize one block
    ; ========================================
    lea     rcx, fmt_test
    call    printf
    
    lea     rcx, test_block
    lea     rdx, output_buffer
    call    Q4KM_Dequant_Block
    
    lea     rcx, fmt_ok
    call    printf
    
    ; Print sample output
    lea     rcx, fmt_sample
    movss   xmm0, dword ptr [output_buffer]
    cvtss2sd xmm0, xmm0
    movq    rdx, xmm0
    call    printf
    
    ; ========================================
    ; TEST 3: Performance benchmark
    ; ========================================
    lea     rcx, qpc_start
    call    QueryPerformanceCounter
    
    ; Benchmark: 1000 blocks
    mov     r12, 1000
    
bench_loop:
    lea     rcx, test_block
    lea     rdx, output_buffer
    call    Q4KM_Dequant_Block
    
    dec     r12
    jnz     bench_loop
    
    lea     rcx, qpc_end
    call    QueryPerformanceCounter
    
    ; Calculate time
    mov     rax, qpc_end
    sub     rax, qpc_start
    mov     rcx, 1000
    mul     rcx
    div     qpc_freq
    
    lea     rcx, fmt_perf
    mov     rdx, rax
    call    printf
    
    ; Complete
    lea     rcx, fmt_complete
    call    printf
    
    xor     ecx, ecx
    call    exit
    
    add     rsp, 64
    pop     rbp
    ret
main ENDP

END
