; ChaosTest.asm - Test harness for chaos sampling
; Builds: ChaosTest.exe
; Pure MASM - no includes!

option casemap:none

; External functions
EXTERNDEF Sampling_Chaos_Master:PROC
EXTERNDEF Random_LCG:PROC
EXTERNDEF GGUF_LoadFile:PROC
EXTERNDEF GGUF_UnloadFile:PROC
EXTERNDEF Transformer_Forward_Pass:PROC
EXTERNDEF Mem_Save:PROC
EXTERNDEF Mem_Recall:PROC
EXTERNDEF Tool_Execute:PROC
EXTERNDEF PrintString:PROC
EXTERNDEF PrintNumber:PROC

; External data
EXTERNDEF logits_buffer:DWORD
EXTERNDEF softmax_buffer:DWORD
EXTERNDEF topk_indices:DWORD
EXTERNDEF topk_values:DWORD

; Windows API imports
EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteConsoleA:PROC
EXTERNDEF ExitProcess:PROC

; Constants
VOCAB_SIZE      EQU 32000
MAX_TOP_K       EQU 50

; Data section
.data
    test_prompt     db "Hello, world!", 0
    test_weights    db "model.gguf", 0
    
    ; Test logits (simulated)
    test_logits     dd 1.0, 2.0, 3.0, 4.0, 5.0
                    dd 2.5, 3.5, 4.5, 1.5, 0.5
                    dd 32000 dup(0.0)  ; Rest zeros
    
    ; Results
    result_token    dd 0
    result_prob     dd 0.0
    gguf_handle     dq 0
    
    ; Output strings
    msg_start       db "=== CHAOS SAMPLING TEST ===", 13, 10, 0
    msg_gguf_try    db "[GGUF] Attempting to load model...", 13, 10, 0
    msg_gguf_ok     db "[GGUF] SUCCESS: Weights loaded!", 13, 10, 0
    msg_mock        db "[GGUF] Using mock data (no file found)", 13, 10, 0
    msg_temp        db "Temperature: ", 0
    msg_topp        db "Top-P: ", 0
    msg_topk        db "Top-K: ", 0
    msg_result      db "Sampled token: ", 0
    msg_prob        db "Probability: ", 0
    msg_done        db "=== TEST COMPLETE ===", 13, 10, 0
    newline         db 13, 10, 0
    
    ; Test parameters
    test_temp       dd 0.8
    test_topp       dd 0.9
    test_topk       dd 40

; Code section
.code

; -------------------------------------------------------------------------
; Entry point - mainCRTStartup
; -------------------------------------------------------------------------
mainCRTStartup PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Print start message
    lea     rcx, msg_start
    call    PrintString
    
    ; === TEST 1: Temperature Scaling ===
    lea     rcx, msg_temp
    call    PrintString
    movss   xmm0, test_temp
    call    PrintFloat
    lea     rcx, newline
    call    PrintString
    
    ; === TEST 2: Try to load real GGUF weights ===
    lea     rcx, msg_gguf_try
    call    PrintString
    
    ; Try to load model.gguf
    lea     rcx, test_weights
    lea     rdx, gguf_handle
    call    GGUF_LoadFile
    
    test    rax, rax
    jz      use_mock_data
    
    ; GGUF loaded successfully!
    lea     rcx, msg_gguf_ok
    call    PrintString
    jmp     setup_sampling
    
use_mock_data:
    lea     rcx, msg_mock
    call    PrintString
    
    ; Copy test logits to buffer
    lea     rsi, test_logits
    lea     rdi, logits_buffer
    mov     ecx, 10         ; Only 10 test values
    rep movsd
    
setup_sampling:
    ; Call Sampling_Chaos_Master
    ; RCX = logits ptr, RDX = output ptr, R8D = vocab_size, R9D = temp
    lea     rcx, logits_buffer
    lea     rdx, result_token         ; FIX: Pass ADDRESS of result_token
    mov     r8d, 10                   ; 10 logits for test (safe size)
    mov     r9d, 1065353216           ; 1.0f as bits
    mov     dword ptr [rsp+40], 5     ; top_k = 5
    mov     dword ptr [rsp+48], 0     ; top_p disabled
    
    call    Sampling_Chaos_Master
    
    ; Result in EAX = sampled token
    mov     result_token, eax
    
    ; Print result
    lea     rcx, msg_result
    call    PrintString
    mov     ecx, result_token
    call    PrintNumber
    lea     rcx, newline
    call    PrintString
    
    ; === TEST 3: Random LCG ===
    call    Random_LCG
    mov     ecx, eax
    call    PrintNumber
    lea     rcx, newline
    call    PrintString
    
    ; === TEST 4: Memory Layer ===
    ; Save a test value
    mov     rcx, 42         ; slot 42
    lea     rdx, test_prompt
    call    Mem_Save
    
    ; Recall it
    mov     rcx, 42
    call    Mem_Recall
    ; RAX now points to recalled data
    
    ; === TEST 5: Tool Dispatcher ===
    mov     rcx, 8          ; TOOL_MEM_SAVE
    mov     rdx, 1          ; slot 1
    lea     r8, test_prompt
    call    Tool_Execute
    
    ; Print done
    lea     rcx, msg_done
    call    PrintString
    
    ; Exit
    xor     ecx, ecx
    call    ExitProcess
    
    add     rsp, 64
    pop     rbp
    ret
mainCRTStartup ENDP

; -------------------------------------------------------------------------
; PrintFloat - Print float to console (simple version)
; Input: XMM0 = float value
; -------------------------------------------------------------------------
PrintFloat PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Just print as integer for now (chaos mode!)
    cvttss2si ecx, xmm0
    call    PrintNumber
    mov     byte ptr [rsp+32], '.'
    mov     byte ptr [rsp+33], 0
    lea     rcx, [rsp+32]
    call    PrintString
    
    add     rsp, 64
    pop     rbp
    ret
PrintFloat ENDP

END