; ==============================================================================
; Sovereign_Inference_Worker.asm - Background Inference Worker Thread
; ==============================================================================
; Bridges the orchestrator's non-blocking handoff to the existing streamer/loader.
; Waits on g_hInferenceTrigger, reads prompt from MMF, runs inference,
; streams tokens to output buffer, and resets state to READY.
;
; Integration Points:
;   - Waits on: g_hInferenceTrigger (manual reset event)
;   - Reads prompt from: OFF_CMD_PAYLOAD in shared memory
;   - Writes tokens to: OFF_RESP_PAYLOAD in shared memory
;   - Calls: SOVEREIGN_LOAD_MODEL, STREAMER_INIT, STREAMER_PUSH_TOKEN, STREAMER_FLUSH
;   - Updates: g_ModelState (INFERENCE_ACTIVE -> READY)
;
; Memory Map (from SOVEREIGN_MMF_PROTOCOL_V1.md):
;   OFF_CMD_PAYLOAD    EQU 0x0018  ; Input prompt
;   OFF_RESP_PAYLOAD   EQU 0x1018  ; Output tokens
;   OFF_TELEM_TOKENS   EQU 0x2020  ; Token count telemetry
;   OFF_TELEM_PROGRESS EQU 0x2028  ; Progress percentage
; ==============================================================================

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN WaitForSingleObject : PROC
EXTERN WaitForMultipleObjects : PROC
EXTERN SetEvent : PROC
EXTERN ResetEvent : PROC
EXTERN GetTickCount64 : PROC
EXTERN Sleep : PROC

; External Sovereign components
EXTERN SOVEREIGN_LOAD_MODEL : PROC
EXTERN SOVEREIGN_UNLOAD_MODEL : PROC
EXTERN SOVEREIGN_IS_MODEL_READY : PROC
EXTERN SOVEREIGN_GET_MODEL_INFO : PROC
EXTERN SOVEREIGN_GET_TENSOR_COUNT : PROC
EXTERN SOVEREIGN_GET_TENSOR_BY_INDEX : PROC
EXTERN STREAMER_INIT : PROC
EXTERN STREAMER_PUSH_TOKEN : PROC
EXTERN STREAMER_FLUSH : PROC

; ==============================================================================
; External Orchestrator Data
; ==============================================================================
EXTERN g_hInferenceTrigger : QWORD
EXTERN g_hCancelEvent : QWORD
EXTERN g_hRespEvent : QWORD
EXTERN g_pShMem : QWORD
EXTERN g_ModelState : DWORD
EXTERN g_Running : DWORD

; ==============================================================================
; Constants
; ==============================================================================
WAIT_OBJECT_0         EQU 0
WAIT_TIMEOUT          EQU 102h
WAIT_FAILED           EQU 0FFFFFFFFh
INFINITE              EQU -1

; MMF Offsets (must match SovereignOrchestrator_Hardened.asm)
OFF_STATE             EQU 00h
OFF_CMD_ID            EQU 04h
OFF_CMD_TYPE          EQU 08h
OFF_PAYLOAD_LEN       EQU 0Ch
OFF_RESP_STATUS       EQU 10h
OFF_RESP_LEN          EQU 14h
OFF_CMD_PAYLOAD       EQU 18h
OFF_RESP_PAYLOAD      EQU 1018h
OFF_TELEM_TOKENS      EQU 2020h
OFF_TELEM_PROGRESS    EQU 2028h
OFF_MODEL_STATE       EQU 2030h

; Buffer bounds
MAX_RESPONSE_SIZE     EQU 0EFD8h    ; ~38KB max response payload
MAX_TOKENS            EQU 0FFFh     ; ~4095 tokens max

; Async SPSC ring (worker producer -> orchestrator consumer)
ASYNC_RING_SIZE       EQU 64
ASYNC_RING_MASK       EQU (ASYNC_RING_SIZE - 1)
ASYNC_PAYLOAD_BYTES   EQU 256
ASYNC_FLAG_CANCELLED  EQU 1

; Model states
MODEL_STATE_UNLOADED         EQU 0
MODEL_STATE_LOADING          EQU 1
MODEL_STATE_READY            EQU 2
MODEL_STATE_INFERENCE_ACTIVE EQU 3
MODEL_STATE_CANCEL_PENDING   EQU 4

; Response codes
RESP_OK               EQU 0
RESP_INTERNAL_ERROR   EQU 4
RESP_CANCELLED        EQU 8
RESP_MODEL_NOT_LOADED EQU 6

; EOS marker
EOS_TOKEN             EQU 0h

; Async response slot format
RESPONSE_SLOT STRUCT
    CmdId           DD ?
    Status          DD ?
    PayloadLen      DD ?
    Flags           DD ?
    TimestampQpc    DQ ?
    Payload         DB ASYNC_PAYLOAD_BYTES DUP(?)
RESPONSE_SLOT ENDS

; ==============================================================================
; Data Section
; ==============================================================================
.DATA
ALIGN 16

g_WorkerRunning       DD 1
g_TokensGenerated     DQ 0
g_ProgressPercent     DD 0
PUBLIC g_StreamerEnabled
g_DebugMode           DD 1    ; 0 = performance mode (pause), 1 = debug mode (Sleep) — currently forced to 1 for starvation test
g_StreamerEnabled     DD 0    ; 0 = bypass streamer calls, 1 = call streamer bridge
DebugCheckpoint       DQ 0
g_LastKernelStatus    DD RESP_OK

PUBLIC g_RingHead
PUBLIC g_RingTail
PUBLIC g_RingDropped
PUBLIC g_RingBackpressure
g_RingHead            DQ 0
g_RingTail            DQ 0
g_RingDropped         DQ 0
g_RingBackpressure    DQ 0
ALIGN 16
g_ResponseRing        RESPONSE_SLOT ASYNC_RING_SIZE DUP(<>)


; ==============================================================================
; Code Section
; ==============================================================================
.CODE

; ==============================================================================
; EnqueueAsyncResponse - SPSC producer enqueue (worker thread)
; In:  ECX=CmdId, EDX=Status, R8D=PayloadLen, R9D=Flags
; Out: EAX=0 success, EAX=1 full/backpressure
; ==============================================================================
PUBLIC EnqueueAsyncResponse
EnqueueAsyncResponse PROC
    mov rax, [g_RingTail]
    lea r11, [rax + 1]
    and r11, ASYNC_RING_MASK
    cmp r11, [g_RingHead]
    je enqueue_full

    lea r10, [g_ResponseRing]
    imul rax, SIZEOF RESPONSE_SLOT
    add r10, rax

    mov dword ptr [r10 + RESPONSE_SLOT.CmdId], ecx
    mov dword ptr [r10 + RESPONSE_SLOT.Status], edx
    mov dword ptr [r10 + RESPONSE_SLOT.PayloadLen], r8d
    mov dword ptr [r10 + RESPONSE_SLOT.Flags], r9d

    sub rsp, 28h
    call GetTickCount64
    add rsp, 28h
    mov qword ptr [r10 + RESPONSE_SLOT.TimestampQpc], rax

    ; Minimal payload metadata for diagnostics
    mov rax, [g_TokensGenerated]
    mov qword ptr [r10 + RESPONSE_SLOT.Payload], rax
    mov eax, dword ptr [g_ModelState]
    mov dword ptr [r10 + RESPONSE_SLOT.Payload + 8], eax
    mov rax, [DebugCheckpoint]
    mov qword ptr [r10 + RESPONSE_SLOT.Payload + 16], rax

    ; Publish tail last (x64 TSO publish-after-write discipline)
    mov [g_RingTail], r11
    xor eax, eax
    ret

enqueue_full:
    lock inc qword ptr [g_RingBackpressure]
    lock inc qword ptr [g_RingDropped]
    mov eax, 1
    ret
EnqueueAsyncResponse ENDP

; ==============================================================================
; DequeueAsyncResponse - SPSC consumer dequeue (orchestrator thread)
; In:  RCX=target slot ptr (optional, may be 0)
; Out: EAX=0 success, EAX=1 empty
; ==============================================================================
PUBLIC DequeueAsyncResponse
DequeueAsyncResponse PROC
    mov rax, [g_RingHead]
    cmp rax, [g_RingTail]
    je dequeue_empty

    lea r10, [g_ResponseRing]
    imul r11, rax, SIZEOF RESPONSE_SLOT
    add r10, r11

    test rcx, rcx
    jz dequeue_advance

    ; Copy fixed header
    mov edx, dword ptr [r10 + RESPONSE_SLOT.CmdId]
    mov dword ptr [rcx + RESPONSE_SLOT.CmdId], edx
    mov edx, dword ptr [r10 + RESPONSE_SLOT.Status]
    mov dword ptr [rcx + RESPONSE_SLOT.Status], edx
    mov edx, dword ptr [r10 + RESPONSE_SLOT.PayloadLen]
    cmp edx, ASYNC_PAYLOAD_BYTES
    jbe dequeue_payload_len_ok
    mov edx, ASYNC_PAYLOAD_BYTES
dequeue_payload_len_ok:
    mov dword ptr [rcx + RESPONSE_SLOT.PayloadLen], edx
    mov edx, dword ptr [r10 + RESPONSE_SLOT.Flags]
    mov dword ptr [rcx + RESPONSE_SLOT.Flags], edx
    mov rdx, qword ptr [r10 + RESPONSE_SLOT.TimestampQpc]
    mov qword ptr [rcx + RESPONSE_SLOT.TimestampQpc], rdx

    ; Copy bounded payload before advancing head.
    push rsi
    push rdi
    lea rsi, [r10 + RESPONSE_SLOT.Payload]
    lea rdi, [rcx + RESPONSE_SLOT.Payload]
    mov ecx, dword ptr [rcx + RESPONSE_SLOT.PayloadLen]
    mov r8d, ecx
    shr ecx, 3
    rep movsq
    mov ecx, r8d
    and ecx, 7
    rep movsb
    pop rdi
    pop rsi

dequeue_advance:
    lea rax, [rax + 1]
    and rax, ASYNC_RING_MASK
    mov [g_RingHead], rax
    xor eax, eax
    ret

dequeue_empty:
    mov eax, 1
    ret
DequeueAsyncResponse ENDP

; ==============================================================================
; ExecuteGGUFKernel - Hardened compute kernel with streaming, cancellation, bounds
; Input:  MMF mapped at g_pShMem, model loaded via SOVEREIGN_LOAD_MODEL
; Output: Tokens streamed via STREAMER_PUSH_TOKEN, telemetry updated
; Invariant: Respects g_Running, g_hCancelEvent, MAX_TOKENS
; ==============================================================================
PUBLIC ExecuteGGUFKernel
ExecuteGGUFKernel PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 48h
    .allocstack 48h
    .endprolog

    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; ------------------------------------------------------------------------
    ; PHASE 0: Setup
    ; ------------------------------------------------------------------------
    mov r12, [g_pShMem]           ; R12 = MMF base (stable throughout)
    test r12, r12
    jz kernel_no_mmf

    mov r13, [g_TokensGenerated]  ; R13 = token counter snapshot
    mov dword ptr [g_LastKernelStatus], RESP_OK

    ; Validate model is loaded
    call SOVEREIGN_IS_MODEL_READY
    test eax, eax
    jz kernel_no_model

    ; ------------------------------------------------------------------------
    ; PHASE 1: Tokenize Prompt (future: call SOVEREIGN_TOKENIZE)
    ; ------------------------------------------------------------------------
    ; For now, prompt is raw bytes. Future: convert to token IDs via tokenizer.
    ; lea rcx, [r15]
    ; lea rdx, [TokenIdBuffer]
    ; call SOVEREIGN_TOKENIZE

    ; ------------------------------------------------------------------------
    ; PHASE 2: Inference Loop (token generation)
    ; ------------------------------------------------------------------------
    ; For each output token:
    ;   1. Check cancellation (g_hCancelEvent, non-blocking)
    
     ; Win64 ABI: provide 32-byte shadow space for every call made from this
     ; frame after saving extra non-volatile registers.
     sub rsp, 20h
    ;   2. Check bounds (MAX_TOKENS)
    ;   3. Check worker shutdown (g_Running)
    ;   4. Generate token (demo: echo prompt char; future: GGUF matmul)
    ;   5. Push token to streamer
    ;   6. Update telemetry

kernel_token_loop:
    ; --- Cancellation check (non-blocking poll) ---
    mov rcx, [g_hCancelEvent]
    xor rdx, rdx                  ; dwMilliseconds = 0 (immediate)
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    je kernel_cancelled

    ; --- Prompt boundary and bounds checks ---
    ; Reload length from shared memory each iteration to avoid stale/clobbered state.
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz kernel_no_mmf
    mov eax, dword ptr [rbx + OFF_PAYLOAD_LEN]
    cmp r13d, eax
    jae kernel_eos

    cmp r13, MAX_TOKENS
    jae kernel_bounds_hit

    ; --- Worker shutdown check ---
    cmp byte ptr [g_Running], 0
    je kernel_shutdown

    ; ========================================================================
    ; PHASE 2a: Token Generation (STUB — replace with real GGUF kernel)
    ; ========================================================================
    ; Current: echo prompt character as token (preserves existing behavior)
    ; Future: call GGUF matmul + softmax + sampling here
    ;
    ; Example future integration:
    ;   lea rcx, [TokenIdBuffer]
    ;   mov edx, r13d
    ;   call GGUF_DECODE_TOKEN
    ;   mov cl, al
    ; ========================================================================

    mov rdi, r13                  ; token index
    movzx ecx, byte ptr [rbx + OFF_CMD_PAYLOAD + rdi]
    test cl, cl
    jz kernel_eos                 ; EOS reached (null byte)

    ; --- Stream token (optional fail-open path) ---
    ; RCX = token byte (already in CL)
    cmp dword ptr [g_StreamerEnabled], 0
    je kernel_skip_stream
    mov edx, 03F4CCCCDh           ; confidence 0.8f
    call STREAMER_PUSH_TOKEN

kernel_skip_stream:

    ; --- Atomic increment ---
    lock inc qword ptr [g_TokensGenerated]
    inc r13

    ; --- Update telemetry ---
    mov rbx, [g_pShMem]
    mov rax, [g_TokensGenerated]
    mov [rbx + OFF_TELEM_TOKENS], rax

    ; Progress: tokens / prompt_len * 100
    mov ecx, dword ptr [rbx + OFF_PAYLOAD_LEN]
    test ecx, ecx
    jz kernel_progress_full
    mov eax, r13d
    imul eax, 100
    cdq
    idiv ecx
    mov [rbx + OFF_TELEM_PROGRESS], eax
    jmp kernel_progress_done

kernel_progress_full:
    mov dword ptr [rbx + OFF_TELEM_PROGRESS], 100

kernel_progress_done:

    ; --- Yield policy: performance mode uses PAUSE, debug mode uses Sleep(1) ---
    cmp dword ptr [g_DebugMode], 0
    jne kernel_do_sleep
    pause
    jmp kernel_skip_sleep

kernel_do_sleep:
    mov ecx, 1
    call Sleep

kernel_skip_sleep:

    jmp kernel_token_loop

kernel_eos:
    ; End of sequence reached naturally
    jmp kernel_finalize

kernel_bounds_hit:
    mov dword ptr [g_LastKernelStatus], RESP_INTERNAL_ERROR
    jmp kernel_finalize

kernel_cancelled:
    mov dword ptr [g_LastKernelStatus], RESP_CANCELLED
    jmp kernel_finalize

kernel_shutdown:
    mov dword ptr [g_LastKernelStatus], RESP_OK
    jmp kernel_finalize

kernel_no_model:
    mov dword ptr [g_LastKernelStatus], RESP_MODEL_NOT_LOADED
    jmp kernel_finalize

kernel_no_mmf:
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz kernel_exit
    jmp kernel_finalize

kernel_finalize:
    ; Flush streamer only when enabled.
    cmp dword ptr [g_StreamerEnabled], 0
    je kernel_skip_flush
    call STREAMER_FLUSH

kernel_skip_flush:

    ; Copy response to MMF (echo prompt as response for now)
    mov rbx, [g_pShMem]
    mov rax, [g_TokensGenerated]
    cmp rax, MAX_RESPONSE_SIZE
    jbe kernel_resp_ok
    mov rax, MAX_RESPONSE_SIZE
kernel_resp_ok:
    mov dword ptr [rbx + OFF_RESP_LEN], eax
    add rsp, 20h

    ; Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx

kernel_exit:
    leave
    ret
ExecuteGGUFKernel ENDP

; ==============================================================================
; InferenceWorkerThread - Background worker (thin dispatcher)
; Waits on trigger, validates state, dispatches to ExecuteGGUFKernel
; ==============================================================================
PUBLIC InferenceWorkerThread
InferenceWorkerThread PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 50h
    .allocstack 50h
    .endprolog

    ; Save param (unused but reserved for future context)
    mov [rsp+40h], rcx

worker_loop:
    ; Check if we should continue running
    cmp byte ptr [g_Running], 0
    je worker_exit

    ; Wait only for inference trigger.
    ; Cancellation is polled inside ExecuteGGUFKernel.
    mov rcx, [g_hInferenceTrigger]
    mov edx, INFINITE
    call WaitForSingleObject
    cmp eax, WAIT_OBJECT_0
    jne worker_loop

inference_triggered:
    ; Reset the trigger event FIRST (before state check)
    ; This prevents infinite re-trigger if state check fails
    mov rcx, [g_hInferenceTrigger]
    call ResetEvent

    ; Verify we are in INFERENCE_ACTIVE state (spurious wake protection)
    mov eax, dword ptr [g_ModelState]
    cmp eax, MODEL_STATE_INFERENCE_ACTIVE
    je inference_dispatch
    cmp eax, MODEL_STATE_CANCEL_PENDING
    je inference_cancel_pending
    jmp worker_loop                  ; Wrong state, go back to sleep

inference_cancel_pending:
    ; Cancel won the race before dispatch. Clear cancel signal and recover.
    mov rcx, [g_hCancelEvent]
    test rcx, rcx
    jz reset_state
    call ResetEvent
    jmp reset_state

inference_dispatch:

    ; Initialize token counter
    mov qword ptr [g_TokensGenerated], 0
    mov dword ptr [g_ProgressPercent], 0

    ; Validate shared memory
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz worker_loop

    ; Initialize streamer
    call STREAMER_INIT
    test eax, eax
    jz worker_error

    ; ------------------------------------------------------------------------
    ; DISPATCH TO COMPUTE KERNEL
    ; ------------------------------------------------------------------------
    ; ExecuteGGUFKernel handles:
    ;   - Token generation (currently demo echo; future GGUF matmul)
    ;   - Cancellation polling
    ;   - Bounds checking
    ;   - Telemetry updates
    ;   - Streaming via STREAMER_PUSH_TOKEN
    ;   - Final status write to MMF
    ; ------------------------------------------------------------------------
    call ExecuteGGUFKernel

    ; Kernel has written status and flushed streamer.
    ; Reset orchestrator state to READY for next request.
    jmp reset_state

worker_error:
    ; Set error status
    mov rbx, [g_pShMem]
    mov dword ptr [rbx + OFF_RESP_STATUS], RESP_INTERNAL_ERROR
    mov dword ptr [rbx + OFF_RESP_LEN], 0
    mov dword ptr [g_LastKernelStatus], RESP_INTERNAL_ERROR

reset_state:
    ; Completion checkpoint for hang triage.
    mov qword ptr [DebugCheckpoint], 0DEADBEEFh

    ; Reset orchestrator state to READY with atomic publication.
    mov eax, MODEL_STATE_READY
    xchg dword ptr [g_ModelState], eax
    
    ; Mirror state to MMF for external polling with atomic publication.
    mov rbx, [g_pShMem]
    test rbx, rbx
    jz reset_state_done
    mov eax, MODEL_STATE_READY
    xchg dword ptr [rbx + OFF_MODEL_STATE], eax

    ; Publish completion record to async SPSC ring.
    mov ecx, dword ptr [rbx + OFF_CMD_ID]
    mov edx, dword ptr [g_LastKernelStatus]
    mov r8d, dword ptr [rbx + OFF_RESP_LEN]
    xor r9d, r9d
    cmp edx, RESP_CANCELLED
    jne reset_publish
    mov r9d, ASYNC_FLAG_CANCELLED
reset_publish:
    call EnqueueAsyncResponse
    
    ; Signal response event so main dispatch loop knows we're done
    mov rcx, [g_hRespEvent]
    test rcx, rcx
    jz reset_state_done
    call SetEvent
    
reset_state_done:
    ; Loop back to wait for next inference request
    jmp worker_loop

worker_exit:
    ; Thread cleanup
    xor eax, eax
    leave
    ret
InferenceWorkerThread ENDP

; ==============================================================================
; InferenceWorker_Stop - Signal worker thread to stop
; ==============================================================================
PUBLIC InferenceWorker_Stop
InferenceWorker_Stop PROC
    mov dword ptr [g_WorkerRunning], 0
    ret
InferenceWorker_Stop ENDP

; ==============================================================================
; InferenceWorker_GetProgress - Get current inference progress
; Returns: RAX = tokens generated, EDX = progress percent
; ==============================================================================
PUBLIC InferenceWorker_GetProgress
InferenceWorker_GetProgress PROC
    mov rax, [g_TokensGenerated]
    mov edx, [g_ProgressPercent]
    ret
InferenceWorker_GetProgress ENDP

END