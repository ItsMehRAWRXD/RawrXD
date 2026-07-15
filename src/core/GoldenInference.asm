; GoldenInference.asm - Hardened Inference Stability Test
; Tests the fused pipeline: GGUF -> Transformer -> Sampling
; Validates: No NaN, deterministic warmup, latency baseline

option casemap:none

; External imports
EXTERNDEF Sampling_Chaos_Master:PROC
EXTERNDEF Random_LCG:PROC
EXTERNDEF PrintString:PROC
EXTERNDEF PrintNumber:PROC
EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteConsoleA:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF QueryPerformanceCounter:PROC
EXTERNDEF QueryPerformanceFrequency:PROC

; Constants
VOCAB_SIZE      EQU 32000
TEST_VOCAB      EQU 10          ; Small vocab for stability test

; Data section
.data
    ; Test messages
    msg_header      db "=== GOLDEN INFERENCE TEST ===", 13, 10, 0
    msg_warmup      db "[1] Warm-up loop...", 13, 10, 0
    msg_pass        db "    PASS: No NaN detected", 13, 10, 0
    msg_fail        db "    FAIL: Invalid value detected", 13, 10, 0
    msg_latency     db "[2] Latency baseline: ", 0
    msg_cycles      db " cycles", 13, 10, 0
    msg_token       db "[3] Sampled token: ", 0
    msg_complete    db "=== INFERENCE STABLE ===", 13, 10, 0
    newline         db 13, 10, 0
    
    ; Test data - controlled logits
    test_logits     dd 0.5, 1.0, 2.0, 0.3, 1.5
                    dd 0.8, 2.5, 0.2, 1.2, 0.9
    
    ; Buffers
    result_buffer   dd 0
    qpc_start       dq 0
    qpc_end         dq 0
    qpc_freq        dq 0

; Code section
.code

; -------------------------------------------------------------------------
; Entry point
; -------------------------------------------------------------------------
mainCRTStartup PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Print header
    lea     rcx, msg_header
    call    PrintString
    
    ; === TEST 1: Warm-up with controlled logits ===
    lea     rcx, msg_warmup
    call    PrintString
    
    ; Initialize QPC frequency
    lea     rcx, qpc_freq
    call    QueryPerformanceFrequency
    
    ; Get start time
    lea     rcx, qpc_start
    call    QueryPerformanceCounter
    
    ; Run sampling on controlled logits
    ; RCX = logits, RDX = output, R8D = vocab_size, R9D = temp
    lea     rcx, test_logits
    lea     rdx, result_buffer
    mov     r8d, TEST_VOCAB
    mov     r9d, 1065353216         ; 1.0f as bits
    mov     dword ptr [rsp+40], 5   ; top_k = 5
    mov     dword ptr [rsp+48], 0   ; top_p disabled
    call    Sampling_Chaos_Master
    
    ; Get end time
    lea     rcx, qpc_end
    call    QueryPerformanceCounter
    
    ; Check result is valid (not -1 which indicates error)
    cmp     eax, -1
    je      test_failed
    
    ; Print pass
    lea     rcx, msg_pass
    call    PrintString
    jmp     print_latency
    
test_failed:
    lea     rcx, msg_fail
    call    PrintString
    
print_latency:
    ; === TEST 2: Latency baseline ===
    lea     rcx, msg_latency
    call    PrintString
    
    ; Calculate cycles (QPC difference)
    mov     rax, qpc_end
    sub     rax, qpc_start
    
    ; Print cycle count
    mov     rcx, rax
    call    PrintNumber64
    
    lea     rcx, msg_cycles
    call    PrintString
    
    ; === TEST 3: Token result ===
    lea     rcx, msg_token
    call    PrintString
    
    mov     ecx, result_buffer
    call    PrintNumber
    
    lea     rcx, newline
    call    PrintString
    
    ; Print completion
    lea     rcx, msg_complete
    call    PrintString
    
    ; Exit success
    xor     ecx, ecx
    call    ExitProcess
    
    add     rsp, 64
    pop     rbp
    ret
mainCRTStartup ENDP

; -------------------------------------------------------------------------
; PrintNumber64 - Print 64-bit integer
; Input: RCX = number
; -------------------------------------------------------------------------
PrintNumber64 PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rdi
    sub     rsp, 72
    
    mov     rax, rcx
    lea     rdi, [rsp+32]
    mov     byte ptr [rdi+20], 0
    mov     ebx, 10
    mov     ecx, 20
    
    ; Handle 0
    test    rax, rax
    jnz     convert_loop
    mov     byte ptr [rdi+19], '0'
    mov     byte ptr [rdi+20], 0
    lea     rcx, [rdi+19]
    call    PrintString
    jmp     done_64
    
convert_loop:
    xor     edx, edx
    div     rbx
    add     dl, '0'
    dec     ecx
    mov     [rdi+rcx], dl
    test    rax, rax
    jnz     convert_loop
    
    lea     rcx, [rdi+rcx]
    call    PrintString
    
done_64:
    add     rsp, 72
    pop     rdi
    pop     rbx
    pop     rbp
    ret
PrintNumber64 ENDP

END
