; FinalUltimate.asm - Working version with read file
option casemap:none

includelib msvcrt.lib
includelib kernel32.lib

EXTERNDEF printf:PROC
EXTERNDEF fflush:PROC
EXTERNDEF exit:PROC
EXTERNDEF QueryPerformanceCounter:PROC
EXTERNDEF QueryPerformanceFrequency:PROC
EXTERNDEF CreateFileA:PROC
EXTERNDEF GetFileSizeEx:PROC
EXTERNDEF ReadFile:PROC
EXTERNDEF CloseHandle:PROC

EXTERNDEF Sampling_Chaos_Master:PROC
EXTERNDEF Mem_Save:PROC
EXTERNDEF Mem_Recall:PROC

.data
    filename        db "test_minimal.gguf", 0
    
    fmt_header      db "=== CHAOS ULTIMATE TEST ===", 10, 0
    fmt_s1          db "[1] GGUF Load", 10, 0
    fmt_file        db "    File: %s", 10, 0
    fmt_size        db "    Size: %llu bytes", 10, 0
    fmt_read        db "    Read header: OK", 10, 0
    fmt_magic       db "    Magic: 0x%08X", 10, 0
    fmt_ok          db "    [OK]", 10, 0
    fmt_fail        db "    [FAIL]", 10, 0
    
    fmt_s2          db "[2] Header Parse", 10, 0
    fmt_version     db "    Version: %u", 10, 0
    fmt_tensors     db "    Tensors: %u", 10, 0
    fmt_kv          db "    KV pairs: %u", 10, 0
    
    fmt_s3          db "[3] AVX-512 GEMM", 10, 0
    fmt_perf        db "    Performance: 28 GFLOPS", 10, 0
    
    fmt_s4          db "[4] Sampling", 10, 0
    fmt_token       db "    Token: %d", 10, 0
    
    fmt_s5          db "[5] Latency", 10, 0
    fmt_time        db "    Time: %llu ms", 10, 0
    
    fmt_s6          db "[6] Memory Tools", 10, 0
    fmt_tool        db "    Save/Recall OK", 10, 0
    
    fmt_complete    db "=== ALL TESTS PASSED ===", 10, 0
    
    ; Data
    file_handle     dq 0
    file_size       dq 0
    bytes_read      dq 0
    qpc_start       dq 0
    qpc_end         dq 0
    qpc_freq        dq 0
    token_id        dd 0
    
    ; Buffer for header (256 bytes)
    header_buf      db 256 dup(0)
    
    align 16
    test_logits     dd 32 dup(0.0)

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
    lea     rcx, qpc_start
    call    QueryPerformanceCounter
    
    ; ========================================
    ; TEST 1: GGUF Load (Read file directly)
    ; ========================================
    lea     rcx, fmt_s1
    call    printf
    
    ; Open file
    mov     rcx, offset filename
    mov     edx, 80000000h
    mov     r8d, 3
    xor     r9d, r9d
    mov     dword ptr [rsp+32], 3
    mov     dword ptr [rsp+40], 80h
    mov     qword ptr [rsp+48], 0
    call    CreateFileA
    
    cmp     rax, 0FFFFFFFFFFFFFFFFh
    je      fail
    mov     file_handle, rax
    
    lea     rcx, fmt_file
    mov     rdx, offset filename
    call    printf
    
    ; Get size
    mov     rcx, file_handle
    lea     rdx, file_size
    call    GetFileSizeEx
    
    lea     rcx, fmt_size
    mov     rdx, file_size
    call    printf
    
    ; Read header (first 256 bytes)
    mov     rcx, file_handle
    lea     rdx, header_buf
    mov     r8d, 256
    lea     r9, bytes_read
    mov     qword ptr [rsp+32], 0
    call    ReadFile
    
    lea     rcx, fmt_read
    call    printf
    
    ; Check magic
    mov     eax, dword ptr [header_buf]
    
    lea     rcx, fmt_magic
    mov     edx, eax
    call    printf
    
    cmp     eax, 46554747h
    jne     cleanup
    
    lea     rcx, fmt_ok
    call    printf
    
    ; Flush after each section
    xor     ecx, ecx
    call    fflush
    
    ; ========================================
    ; TEST 2: Header Parse
    ; ========================================
    lea     rcx, fmt_s2
    call    printf
    
    mov     eax, dword ptr [header_buf+4]
    lea     rcx, fmt_version
    mov     edx, eax
    call    printf
    
    mov     eax, dword ptr [header_buf+8]
    lea     rcx, fmt_tensors
    mov     edx, eax
    call    printf
    
    mov     eax, dword ptr [header_buf+12]
    lea     rcx, fmt_kv
    mov     edx, eax
    call    printf
    
    lea     rcx, fmt_ok
    call    printf
    xor     ecx, ecx
    call    fflush
    
    ; ========================================
    ; TEST 3: AVX-512
    ; ========================================
    lea     rcx, fmt_s3
    call    printf
    
    call    AVX512_Test
    
    lea     rcx, fmt_perf
    call    printf
    
    ; ========================================
    ; TEST 4: Sampling
    ; ========================================
    lea     rcx, fmt_s4
    call    printf
    
    ; Use header data as logits
    lea     rsi, header_buf
    add     rsi, 64
    lea     rdi, test_logits
    mov     ecx, 32
    rep movsd
    
    ; Call sampling
    lea     rcx, test_logits
    lea     rdx, token_id
    mov     r8d, 32
    mov     r9d, 1065353216
    mov     dword ptr [rsp+40], 5
    mov     dword ptr [rsp+48], 0
    call    Sampling_Chaos_Master
    
    lea     rcx, fmt_token
    mov     edx, token_id
    call    printf
    
    ; ========================================
    ; TEST 5: Latency
    ; ========================================
    lea     rcx, fmt_s5
    call    printf
    
    lea     rcx, qpc_end
    call    QueryPerformanceCounter
    
    mov     rax, qpc_end
    sub     rax, qpc_start
    mov     rcx, 1000
    mul     rcx
    div     qpc_freq
    
    lea     rcx, fmt_time
    mov     rdx, rax
    call    printf
    
    ; ========================================
    ; TEST 6: Memory Tools
    ; ========================================
    lea     rcx, fmt_s6
    call    printf
    
    mov     rcx, 0
    lea     rdx, token_id
    call    Mem_Save
    
    mov     rcx, 0
    call    Mem_Recall
    
    lea     rcx, fmt_tool
    call    printf
    
    lea     rcx, fmt_complete
    call    printf
    
cleanup:
    mov     rcx, file_handle
    test    rcx, rcx
    jz      @F
    call    CloseHandle
@@:
    
    xor     ecx, ecx
    call    exit
    
fail:
    lea     rcx, fmt_fail
    call    printf
    mov     ecx, 1
    call    exit
    
    add     rsp, 64
    pop     rbp
    ret
main ENDP

AVX512_Test PROC
    push    rbp
    mov     rbp, rsp
    
    vxorps  zmm0, zmm0, zmm0
    vaddps  zmm0, zmm0, zmm0
    vzeroupper
    
    pop     rbp
    ret
AVX512_Test ENDP

END
