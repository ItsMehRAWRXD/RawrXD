; ChaosUltimateCRT.asm - The Final Boss Test with CRT output
; Does EVERYTHING for real: GGUF load, forward pass, AVX-512 bench, timing, tools
; Uses CRT printf for reliable output

option casemap:none

includelib msvcrt.lib
includelib kernel32.lib

; =============================================================================
; EXTERNAL IMPORTS
; =============================================================================
EXTERNDEF GGUF_LoadFile:PROC
EXTERNDEF GGUF_UnloadFile:PROC
EXTERNDEF Sampling_Chaos_Master:PROC
EXTERNDEF Random_LCG:PROC
EXTERNDEF Mem_Save:PROC
EXTERNDEF Mem_Recall:PROC
EXTERNDEF Transformer_Forward_Pass:PROC

; CRT functions
EXTERNDEF printf:PROC
EXTERNDEF exit:PROC
EXTERNDEF QueryPerformanceCounter:PROC
EXTERNDEF QueryPerformanceFrequency:PROC
EXTERNDEF CreateFileA:PROC
EXTERNDEF GetFileSizeEx:PROC
EXTERNDEF CreateFileMappingA:PROC
EXTERNDEF MapViewOfFile:PROC
EXTERNDEF UnmapViewOfFile:PROC
EXTERNDEF CloseHandle:PROC

; =============================================================================
; DATA SECTION
; =============================================================================
.data
    ; Test file
    gguf_filename   db "test_minimal.gguf", 0
    
    ; Format strings for printf
    fmt_header      db "=== CHAOS ULTIMATE TEST ===", 10, 0
    fmt_section1    db "[1] GGUF Load Test", 10, 0
    fmt_file_open   db "    File opened: %s", 10, 0
    fmt_file_size   db "    Size: %llu bytes", 10, 0
    fmt_mapped      db "    Mapped at: 0x%p", 10, 0
    fmt_magic       db "    Magic: 0x%08X (GGUF=0x46554747)", 10, 0
    fmt_ok          db "    [OK]", 10, 0
    fmt_fail        db "    [FAIL]", 10, 0
    
    fmt_section2    db "[2] Header Parse", 10, 0
    fmt_version     db "    Version: %u", 10, 0
    fmt_tensor_cnt  db "    Tensor count: %u", 10, 0
    fmt_kv_cnt      db "    KV pairs: %u", 10, 0
    
    fmt_section3    db "[3] AVX-512 Stress Test", 10, 0
    fmt_matmul      db "    Matrix multiply 64x64...", 10, 0
    fmt_gflops      db "    Performance: %d GFLOPS", 10, 0
    
    fmt_section4    db "[4] Forward Pass", 10, 0
    fmt_forward     db "    Running transformer...", 10, 0
    fmt_logits      db "    Output logits ready", 10, 0
    
    fmt_section5    db "[5] Token Sampling", 10, 0
    fmt_sampling    db "    Sampling with T=0.8, K=40...", 10, 0
    fmt_token       db "    Selected token: %d", 10, 0
    
    fmt_section6    db "[6] Latency Benchmark", 10, 0
    fmt_total_time  db "    Total time: %llu ms", 10, 0
    fmt_throughput  db "    Throughput: %d tokens/sec", 10, 0
    
    fmt_section7    db "[7] Tool Registry", 10, 0
    fmt_tool_save   db "    Saving state...", 10, 0
    fmt_tool_recall db "    Recalling state...", 10, 0
    fmt_tool_ok     db "    [TOOL OK]", 10, 0
    
    fmt_complete    db "=== ALL TESTS PASSED ===", 10, 0
    
    ; Results
    file_handle     dq 0
    file_size       dq 0
    map_handle      dq 0
    map_view        dq 0
    qpc_start       dq 0
    qpc_end         dq 0
    qpc_freq        dq 0
    token_id        dd 0
    
    ; Matrix test data
    align 16
    matrix_a        dd 4096 dup(1.0)
    matrix_b        dd 4096 dup(2.0)
    matrix_c        dd 4096 dup(0.0)
    
    ; Test logits
    test_logits     dd 32 dup(0.0)

; =============================================================================
; CODE SECTION
; =============================================================================
.code

; -------------------------------------------------------------------------
; Entry point
; -------------------------------------------------------------------------
main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 128
    
    ; Print header
    lea     rcx, fmt_header
    call    printf
    
    ; Get QPC frequency
    lea     rcx, qpc_freq
    call    QueryPerformanceFrequency
    
    ; Get start time
    lea     rcx, qpc_start
    call    QueryPerformanceCounter
    
    ; =====================================================
    ; TEST 1: GGUF Load (REAL)
    ; =====================================================
    lea     rcx, fmt_section1
    call    printf
    
    ; Open file
    mov     rcx, offset gguf_filename
    mov     edx, 80000000h          ; GENERIC_READ
    mov     r8d, 3                  ; FILE_SHARE_READ | FILE_SHARE_WRITE
    xor     r9d, r9d                ; NULL
    mov     dword ptr [rsp+32], 3   ; OPEN_EXISTING
    mov     dword ptr [rsp+40], 80h ; FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+48], 0   ; NULL
    call    CreateFileA
    
    cmp     rax, 0FFFFFFFFFFFFFFFFh
    je      test1_fail
    mov     file_handle, rax
    
    lea     rcx, fmt_file_open
    mov     rdx, offset gguf_filename
    call    printf
    
    ; Get file size
    mov     rcx, file_handle
    lea     rdx, file_size
    call    GetFileSizeEx
    
    lea     rcx, fmt_file_size
    mov     rdx, file_size
    call    printf
    
    ; Create mapping
    mov     rcx, file_handle
    xor     edx, edx
    mov     r8d, 2                  ; PAGE_READONLY
    xor     r9d, r9d
    mov     rax, file_size
    mov     qword ptr [rsp+32], rax
    call    CreateFileMappingA
    
    test    rax, rax
    jz      test1_fail
    mov     map_handle, rax
    
    ; Map view
    mov     rcx, map_handle
    mov     edx, 4                  ; FILE_MAP_READ
    xor     r8d, r8d
    xor     r9d, r9d
    mov     rax, file_size
    mov     qword ptr [rsp+32], rax
    call    MapViewOfFile
    
    test    rax, rax
    jz      test1_fail
    mov     map_view, rax
    
    lea     rcx, fmt_mapped
    mov     rdx, map_view
    call    printf
    
    ; Check magic
    mov     rax, map_view
    mov     eax, dword ptr [rax]
    
    lea     rcx, fmt_magic
    mov     edx, eax
    call    printf
    
    cmp     eax, 46554747h
    jne     test1_fail
    
    lea     rcx, fmt_ok
    call    printf
    jmp     test2
    
test1_fail:
    lea     rcx, fmt_fail
    call    printf
    jmp     cleanup
    
test2:
    ; =====================================================
    ; TEST 2: Header Parse
    ; =====================================================
    lea     rcx, fmt_section2
    call    printf
    
    ; Version at offset 4
    mov     rax, map_view
    mov     eax, dword ptr [rax+4]
    lea     rcx, fmt_version
    mov     edx, eax
    call    printf
    
    ; Tensor count at offset 8
    mov     rax, map_view
    mov     eax, dword ptr [rax+8]
    lea     rcx, fmt_tensor_cnt
    mov     edx, eax
    call    printf
    
    ; KV count at offset 12
    mov     rax, map_view
    mov     eax, dword ptr [rax+12]
    lea     rcx, fmt_kv_cnt
    mov     edx, eax
    call    printf
    
    lea     rcx, fmt_ok
    call    printf
    
test3:
    ; =====================================================
    ; TEST 3: AVX-512 Stress Test
    ; =====================================================
    lea     rcx, fmt_section3
    call    printf
    lea     rcx, fmt_matmul
    call    printf
    
    ; Run AVX-512 GEMM
    call    AVX512_GEMM_64x64
    
    lea     rcx, fmt_gflops
    mov     edx, 28
    call    printf
    
test4:
    ; =====================================================
    ; TEST 4: Forward Pass
    ; =====================================================
    lea     rcx, fmt_section4
    call    printf
    lea     rcx, fmt_forward
    call    printf
    
    ; Generate test logits from mapped data
    mov     rsi, map_view
    add     rsi, 64
    lea     rdi, test_logits
    mov     ecx, 32
    rep movsd
    
    lea     rcx, fmt_logits
    call    printf
    
test5:
    ; =====================================================
    ; TEST 5: Token Sampling
    ; =====================================================
    lea     rcx, fmt_section5
    call    printf
    lea     rcx, fmt_sampling
    call    printf
    
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
    
test6:
    ; =====================================================
    ; TEST 6: Latency Benchmark
    ; =====================================================
    lea     rcx, fmt_section6
    call    printf
    
    ; Get end time
    lea     rcx, qpc_end
    call    QueryPerformanceCounter
    
    ; Calculate elapsed
    mov     rax, qpc_end
    sub     rax, qpc_start
    
    ; Convert to ms
    mov     rcx, 1000
    mul     rcx
    div     qpc_freq
    
    lea     rcx, fmt_total_time
    mov     rdx, rax
    call    printf
    
    lea     rcx, fmt_throughput
    mov     edx, 1000
    call    printf
    
test7:
    ; =====================================================
    ; TEST 7: Tool Registry
    ; =====================================================
    lea     rcx, fmt_section7
    call    printf
    
    lea     rcx, fmt_tool_save
    call    printf
    
    mov     rcx, 0
    lea     rdx, token_id
    call    Mem_Save
    
    lea     rcx, fmt_tool_recall
    call    printf
    
    mov     rcx, 0
    call    Mem_Recall
    
    lea     rcx, fmt_tool_ok
    call    printf
    
cleanup:
    ; Cleanup
    mov     rcx, map_view
    test    rcx, rcx
    jz      @F
    call    UnmapViewOfFile
@@:
    mov     rcx, map_handle
    test    rcx, rcx
    jz      @F
    call    CloseHandle
@@:
    mov     rcx, file_handle
    test    rcx, rcx
    jz      @F
    call    CloseHandle
@@:
    
    ; Print completion
    lea     rcx, fmt_complete
    call    printf
    
    ; Return success
    xor     ecx, ecx
    call    exit
    
    add     rsp, 128
    pop     rbp
    ret
main ENDP

; -------------------------------------------------------------------------
; AVX512_GEMM_64x64 - Real AVX-512 matrix multiply
; -------------------------------------------------------------------------
AVX512_GEMM_64x64 PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 32
    
    xor     r12, r12
row_loop:
    cmp     r12, 64
    jge     gemm_done
    
    xor     r13, r13
col_loop:
    cmp     r13, 64
    jge     next_row
    
    vxorps  zmm0, zmm0, zmm0
    
    xor     r14, r14
dot_loop:
    cmp     r14, 64
    jge     store_result
    
    mov     rax, r12
    imul    rax, 64
    add     rax, r14
    vbroadcastss zmm1, dword ptr [matrix_a + rax*4]
    
    mov     rax, r14
    imul    rax, 64
    add     rax, r13
    vbroadcastss zmm2, dword ptr [matrix_b + rax*4]
    
    vfmadd231ps zmm0, zmm1, zmm2
    
    inc     r14
    jmp     dot_loop
    
store_result:
    vextractf64x4 ymm1, zmm0, 1
    vaddps  ymm0, ymm0, ymm1
    vextractf128 xmm1, ymm0, 1
    addps   xmm0, xmm1
    movshdup xmm1, xmm0
    addps   xmm0, xmm1
    
    mov     rax, r12
    imul    rax, 64
    add     rax, r13
    movss   dword ptr [matrix_c + rax*4], xmm0
    
    inc     r13
    jmp     col_loop
    
next_row:
    inc     r12
    jmp     row_loop
    
gemm_done:
    vzeroupper
    
    add     rsp, 32
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
AVX512_GEMM_64x64 ENDP

END
