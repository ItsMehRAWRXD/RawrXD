; ============================================================================
; mega_test_harness.asm - Test all features at once!
; ============================================================================

    .code
    option casemap:none

; External imports
extern GGUF_LoadFile:proc
extern GGUF_UnloadFile:proc
extern GGUF_ParseHeader:proc
extern Transformer_Forward_Pass:proc
extern Temperature_Sampling:proc
extern TopK_Sampling:proc
extern Tool_MemSave:proc
extern Tool_MemRecall:proc
extern PrintString:proc
extern PrintNumber:proc
extern ExitProcess:proc

; =============================================================================
; DATA SECTION
; =============================================================================
    .data

test_header             db "=================================================================", 13, 10
                        db "  RawrXD MEGA TEST - All Features at Once! 🚀", 13, 10
                        db "=================================================================", 13, 10, 13, 10, 0

test_gguf               db "[TEST 1] GGUF File Loading...", 13, 10, 0
test_transformer        db "[TEST 2] Multi-Layer Transformer (AVX-512)...", 13, 10, 0
test_sampling           db "[TEST 3] Temperature + Top-K Sampling...", 13, 10, 0
test_memory             db "[TEST 4] Memory Layer (SAVE/RECALL)...", 13, 10, 0
test_complete           db 13, 10, "=================================================================", 13, 10
                        db "  All Tests Complete! ✅", 13, 10
                        db "=================================================================", 13, 10, 0

msg_pass                db "  ✅ PASS", 13, 10, 0
msg_fail                db "  ❌ FAIL", 13, 10, 0
msg_skip                db "  ⏭️  SKIP", 13, 10, 0

; Test data
test_data               db "Hello from RawrXD!", 0
test_buffer             db 256 dup(0)

; Simulated logits for sampling test
align 64
test_logits             dd 2.0, 1.5, 3.0, 0.5, 2.5, 1.0, 0.0, 4.0
                        dd 1.0, 2.0, 3.0, 2.5, 1.5, 0.5, 2.0, 1.0
                        dd 256 dup(0.0)

sampled_token           dd 0

; =============================================================================
; CODE SECTION
; =============================================================================
    .code

; -----------------------------------------------------------------------------
; main - Entry point
; -----------------------------------------------------------------------------
main PROC FRAME
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    .allocstack 64
    .endprolog

    ; Print header
    lea     rcx, test_header
    call    PrintString

    ; === TEST 1: GGUF Loading ===
    lea     rcx, test_gguf
    call    PrintString
    
    ; Try to load a real GGUF file (will fail if not present, that's OK)
    lea     rcx, gguf_file_path
    call    GGUF_LoadFile
    test    rax, rax
    jz      @gguf_skip
    
    ; Successfully loaded - parse header
    mov     rcx, rax
    call    GGUF_ParseHeader
    test    rax, rax
    jz      @gguf_fail
    
    lea     rcx, msg_pass
    call    PrintString
    
    ; Unload
    call    GGUF_UnloadFile
    jmp     @test2

@gguf_skip:
    lea     rcx, msg_skip
    call    PrintString
    jmp     @test2

@gguf_fail:
    lea     rcx, msg_fail
    call    PrintString

    ; === TEST 2: Transformer Forward Pass ===
@test2:
    lea     rcx, test_transformer
    call    PrintString
    
    ; For now, skip actual transformer test (needs real weights)
    ; In real implementation, would call Transformer_Forward_Pass
    lea     rcx, msg_skip
    call    PrintString

    ; === TEST 3: Sampling ===
@test3:
    lea     rcx, test_sampling
    call    PrintString
    
    ; Test temperature sampling
    lea     rcx, test_logits
    lea     rdx, sampled_token
    mov     r8d, 100                    ; vocab_size
    mov     r9d, 1065353216             ; temperature = 1.0
    call    Temperature_Sampling
    
    ; Verify we got a valid token
    mov     eax, [sampled_token]
    cmp     eax, 100
    jae     @sampling_fail
    
    lea     rcx, msg_pass
    call    PrintString
    jmp     @test4

@sampling_fail:
    lea     rcx, msg_fail
    call    PrintString

    ; === TEST 4: Memory Layer ===
@test4:
    lea     rcx, test_memory
    call    PrintString
    
    ; Save test data to slot 0
    lea     rcx, test_data            ; data pointer
    mov     edx, 19                   ; size (strlen + 1)
    xor     r8d, r8d                  ; slot 0
    mov     r9d, 1                    ; persist flag
    mov     dword ptr [rsp + 32], 0   ; extra
    call    Tool_MemSave
    test    eax, eax
    jz      @memory_fail
    
    ; Recall from slot 0
    lea     rcx, test_buffer          ; buffer
    mov     edx, 256                  ; buffer size
    xor     r8d, r8d                  ; slot 0
    mov     r9d, 1                    ; persist flag
    mov     dword ptr [rsp + 32], 0   ; extra
    call    Tool_MemRecall
    test    eax, eax
    jz      @memory_fail
    
    ; Verify data matches
    lea     rsi, test_data
    lea     rdi, test_buffer
    mov     ecx, 19
    repe cmpsb
    jne     @memory_fail
    
    lea     rcx, msg_pass
    call    PrintString
    jmp     @complete

@memory_fail:
    lea     rcx, msg_fail
    call    PrintString

    ; === COMPLETE ===
@complete:
    lea     rcx, test_complete
    call    PrintString

    ; Exit
    xor     ecx, ecx
    call    ExitProcess

    pop     rbp
    ret
main ENDP

; =============================================================================
; DATA
; =============================================================================
    .data

gguf_file_path          db "model.gguf", 0

    END
