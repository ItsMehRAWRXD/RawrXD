; Titan_Streaming_Orchestrator_NoHTTP.asm
; Modified orchestrator: Direct native inference instead of llama-server.exe
; Replaces HTTP calls with direct Titan_RunInference calls in inference thread
;
; PRODUCTION NOTES:
;   - Single-session architecture: global state prevents concurrent inference.
;   - Caller must ensure Titan_StopInference_Native before starting a new session.
;   - Context layout expected by Titan_RunInference:
;       +0x00  model handle
;       +0x08  tokenizer handle
;       +0x10  KV cache pointer
;       +0x18  logits buffer pointer (vocab_size * sizeof(float))
;       +0x20  input token buffer
;       +0x28  output token ring buffer
;       +0x30  vocab_size (DWORD)
;       +0x34  max_seq_len (DWORD)
;       +0x38  current_seq_len (DWORD)
;       +0x3C  flags (DWORD)
;
; VERSION: 2026-08-16 — corrected token loop, argmax sampling, auto-reset events,
;                        handle cleanup, error limits, EOS detection.

OPTION CASEMAP:NONE

 includelib kernel32.lib
 includelib ntdll.lib

EXTERN Titan_RunInference : PROC
EXTERN Titan_ArgmaxToken : PROC
EXTERN Titan_EmitToken : PROC
EXTERN GGUF_LoadFile : PROC
EXTERN CreateThread : PROC
EXTERN WaitForSingleObject : PROC
EXTERN GetCurrentThread : PROC
EXTERN SetThreadPriority : PROC
EXTERN CloseHandle : PROC
EXTERN VirtualAlloc : PROC
EXTERN VirtualFree : PROC

.const
 THREAD_PRIORITY_HIGHEST EQU 2
 WAIT_OBJECT_0           EQU 0
 WAIT_TIMEOUT            EQU 258
 INFINITE                EQU 0FFFFFFFFh
 TOKEN_EOS               EQU 2       ; Typical GGML EOS token id (model-specific)
 MAX_CONSECUTIVE_ERRORS  EQU 3       ; Abort after 3 consecutive inference failures
 MEM_COMMIT              EQU 1000h
 MEM_RELEASE             EQU 8000h
 PAGE_READWRITE          EQU 4

; ============================================================================
; INFERENCE SESSION STATE (single-session globals)
; ============================================================================
.data?
 ALIGN 8
 hInferenceThread        QWORD ?
 hInferenceEvent         QWORD ?     ; Auto-reset: signals one token completed
 hStopEvent              QWORD ?     ; Manual-reset: signals thread shutdown
 pInferenceContext       QWORD ?     ; Passed to thread, also stored globally
 nCurrentToken           DWORD ?     ; Last generated token (updated each iteration)
 fInferenceRunning       DWORD ?     ; 1 = thread active, 0 = idle/stopped
 nConsecutiveErrors      DWORD ?     ; Error counter for abort logic

.data

 szInferenceStart        BYTE "[Titan] Starting native inference thread...", 0
 szInferenceComplete     BYTE "[Titan] Token inference complete", 0
 szInferenceError      BYTE "[Titan] Inference error — aborting generation", 0
 szInferenceEOS        BYTE "[Titan] EOS reached — generation complete", 0

; ============================================================================
; INFERENCE THREAD PROC
; ============================================================================
.code

EXTERN CreateEventA : PROC
EXTERN SetEvent : PROC
EXTERN ResetEvent : PROC
EXTERN WaitForSingleObject : PROC

; ----------------------------------------------------------------------------
; NativeInferenceThread
; RCX = pInferenceContext (must remain valid for thread lifetime)
; Loop: stop-check → decode → argmax → emit → advance → repeat
; ============================================================================
NativeInferenceThread PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 40h              ; 32B shadow + locals, 16B aligned
    .allocstack 40h
    .endprolog
    
    mov r12, rcx            ; Context (preserved across calls)
    mov r13, 0              ; Token counter
    mov DWORD PTR [nConsecutiveErrors], 0
    
    ; Set thread priority high for low-latency decode
    call GetCurrentThread
    mov rcx, rax
    mov edx, THREAD_PRIORITY_HIGHEST
    call SetThreadPriority
    
@@token_loop:
    ; --- Check for stop signal (non-blocking) ---
    mov rcx, [hStopEvent]
    mov edx, 0
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    je @@done
    
    ; --- Load current token from context ---
    ; Context+0x20 = input token buffer, offset by current_seq_len-1
    mov r14d, [nCurrentToken]
    
    ; --- Run one decode step ---
    ; Titan_RunInference(RCX=context, EDX=token, R8=logits_buffer)
    mov rcx, r12
    mov edx, r14d
    mov r8, [r12 + 18h]     ; logits buffer pointer from context
    call Titan_RunInference
    
    test eax, eax
    jz @@inference_error
    
    ; Success: reset error counter
    mov DWORD PTR [nConsecutiveErrors], 0
    
    ; --- Greedy argmax sampling ---
    ; Titan_ArgmaxToken(RCX=logits, EDX=vocab_size) → EAX=next_token
    mov rcx, [r12 + 18h]
    mov edx, [r12 + 30h]
    call Titan_ArgmaxToken
    
    ; --- EOS check ---
    cmp eax, TOKEN_EOS
    je @@eos_reached
    
    ; --- Save next token ---
    mov [nCurrentToken], eax
    
    ; --- Emit token to output ring buffer ---
    mov edx, eax
    call Titan_EmitToken
    
    ; --- Signal consumer that one token is ready ---
    ; Auto-reset event: single waiter wakes, event auto-clears
    mov rcx, [hInferenceEvent]
    call SetEvent
    
    ; --- Advance sequence length in context ---
    inc DWORD PTR [r12 + 38h]   ; current_seq_len++
    
    inc r13
    cmp r13, 1024
    jb @@token_loop
    jmp @@done
    
@@inference_error:
    inc DWORD PTR [nConsecutiveErrors]
    cmp DWORD PTR [nConsecutiveErrors], MAX_CONSECUTIVE_ERRORS
    jae @@done
    jmp @@token_loop
    
@@eos_reached:
    ; Signal completion before exiting
    mov rcx, [hInferenceEvent]
    call SetEvent
    jmp @@done
    
@@done:
    mov [fInferenceRunning], 0
    add rsp, 40h
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
NativeInferenceThread ENDP

; ============================================================================
; PUBLIC API: Start Inference
; ============================================================================

PUBLIC Titan_BeginStreamingInference_Native
Titan_BeginStreamingInference_Native PROC FRAME pszModelPath:QWORD, pszPrompt:QWORD, pContext:QWORD
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    sub rsp, 48h             ; 32B shadow + 16B for stack args
    .allocstack 48h
    .endprolog
    
    mov r12, pContext
    
    ; --- Guard: prevent double-start ---
    cmp DWORD PTR [fInferenceRunning], 0
    jne @@fail                ; Already running
    
    ; --- Load GGUF model ---
    mov rcx, pszModelPath
    mov rdx, r12
    call GGUF_LoadFile
    test eax, eax
    jz @@fail
    
    ; --- Allocate logits buffer if not present ---
    mov rbx, [r12 + 18h]      ; existing logits pointer
    test rbx, rbx
    jnz @@logits_ok
    mov ecx, [r12 + 30h]      ; vocab_size
    shl ecx, 2                ; * sizeof(float)
    mov edx, MEM_COMMIT
    mov r8d, PAGE_READWRITE
    xor r9, r9
    call VirtualAlloc
    test rax, rax
    jz @@fail
    mov [r12 + 18h], rax
    mov rbx, rax
@@logits_ok:
    
    ; --- Create auto-reset inference completion event ---
    xor rcx, rcx
    xor edx, edx              ; bManualReset = FALSE (auto-reset)
    mov r8d, 0
    xor r9, r9
    call CreateEventA
    test rax, rax
    jz @@fail_cleanup
    mov [hInferenceEvent], rax
    
    ; --- Create manual-reset stop event ---
    xor rcx, rcx
    mov edx, 1                ; bManualReset = TRUE
    mov r8d, 0
    xor r9, r9
    call CreateEventA
    test rax, rax
    jz @@fail_cleanup
    mov [hStopEvent], rax
    
    ; --- Store context and initialize token state ---
    mov [pInferenceContext], r12
    mov DWORD PTR [nCurrentToken], 1    ; BOS / first token
    mov DWORD PTR [nConsecutiveErrors], 0
    mov DWORD PTR [r12 + 38h], 1        ; current_seq_len = 1
    
    ; --- Create inference thread ---
    xor rcx, rcx
    xor edx, edx
    mov r8, OFFSET NativeInferenceThread
    mov r9, r12
    mov qword ptr [rsp+20h], 0
    mov qword ptr [rsp+28h], 0
    call CreateThread
    test rax, rax
    jz @@fail_cleanup
    
    mov [hInferenceThread], rax
    mov [fInferenceRunning], 1
    
    mov eax, 1
    add rsp, 48h
    pop r12
    pop rbx
    ret

@@fail_cleanup:
    ; Best-effort cleanup
    mov rcx, [hInferenceEvent]
    test rcx, rcx
    jz @F
    call CloseHandle
@@:
    mov QWORD PTR [hInferenceEvent], 0

    mov rcx, [hStopEvent]
    test rcx, rcx
    jz @F
    call CloseHandle
@@:
    mov QWORD PTR [hStopEvent], 0

    mov QWORD PTR [hInferenceThread], 0
    mov DWORD PTR [fInferenceRunning], 0
    jmp @@fail
    
@@fail:
    xor eax, eax
    add rsp, 48h
    pop r12
    pop rbx
    ret
Titan_BeginStreamingInference_Native ENDP

; ============================================================================
; PUBLIC API: Wait for one token to complete
; ============================================================================

PUBLIC Titan_WaitInferenceComplete_Native
Titan_WaitInferenceComplete_Native PROC FRAME dwTimeoutMs:DWORD
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    mov rcx, [hInferenceEvent]
    test rcx, rcx
    jz @@no_event
    mov edx, dwTimeoutMs
    call WaitForSingleObject
    ; Auto-reset event: no ResetEvent needed
    jmp @@done
    
@@no_event:
    mov eax, 0FFFFFFFFh       ; WAIT_FAILED
@@done:
    add rsp, 28h
    ret
Titan_WaitInferenceComplete_Native ENDP

; ============================================================================
; PUBLIC API: Stop inference and clean up handles
; ============================================================================

PUBLIC Titan_StopInference_Native
Titan_StopInference_Native PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    ; Signal stop
    mov rcx, [hStopEvent]
    test rcx, rcx
    jz @@close_handles
    call SetEvent
    
    ; Wait for thread
@@wait_thread:
    mov rcx, [hInferenceThread]
    test rcx, rcx
    jz @@close_handles
    mov edx, INFINITE
    call WaitForSingleObject
    
    ; Close thread handle
    mov rcx, [hInferenceThread]
    call CloseHandle
    mov QWORD PTR [hInferenceThread], 0
    
@@close_handles:
    ; Close inference event
    mov rcx, [hInferenceEvent]
    test rcx, rcx
    jz @F
    call CloseHandle
@@:
    mov QWORD PTR [hInferenceEvent], 0
    
    ; Close stop event
    mov rcx, [hStopEvent]
    test rcx, rcx
    jz @F
    call CloseHandle
@@:
    mov QWORD PTR [hStopEvent], 0
    
    mov DWORD PTR [fInferenceRunning], 0
    xor eax, eax
    add rsp, 28h
    ret
Titan_StopInference_Native ENDP

END
