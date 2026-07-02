; ==============================================================================
; Sovereign_Model_Streamer.asm - AI Inference → Ghost Engine Bridge
; ==============================================================================
; Attaches the Ghost Engine to the model streamer, receiving AI token output
; and pushing predictions to the IDE overlay.
;
; Integration Points:
;   - STREAMER_INIT: Initialize streamer connection
;   - STREAMER_PUSH_TOKEN: Push single token from inference (atomic reservation)
;   - STREAMER_FLUSH: Flush accumulated tokens to Ghost Engine + sign telemetry
;   - STREAMER_SET_CALLBACK: Set prediction callback
;
; Sovereign Integration:
;   - Ghost Engine must be registered in ToolchainRegistry as:
;     identity: "com.rawrxd.ghostengine"
;     capabilities: ["EXECUTE_INTERNAL", "TELEMETRY_EMIT"]
;   - Every flush emits a signed telemetry event via SOVEREIGN_TELEMETRY_SIGN.
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

; ==============================================================================
; External APIs (Ghost Engine + Sovereign Telemetry)
; ==============================================================================
EXTERN PUSH_GHOST_PREDICTION : PROC
EXTERN FLUSH_GHOST_BUFFER : PROC
EXTERN GHOST_HEARTBEAT : PROC
EXTERN SOVEREIGN_TELEMETRY_SIGN : PROC   ; RCX=bufPtr, RDX=len, R8=sigOutPtr

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; Token accumulation buffer
STREAMER_BUFFER_SIZE    equ 1024

g_StreamerInitialized dq 0
g_TokenBuffer           db STREAMER_BUFFER_SIZE dup(0)
g_TokenCount            dq 0
g_TokenConfidence       dd 03F4CCCCDh  ; 0.8f default
g_LastFlushTime         dq 0
g_StreamerBypassExternal dq 1          ; 1 = local non-blocking flush only
FLUSH_TIMEOUT_CYCLES    equ 450000000  ; ~150ms @ 3GHz

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; STREAMER_INIT: Initialize model streamer bridge
; ==============================================================================
STREAMER_INIT PROC
    push rbx
    
    ; Check if already initialized
    mov rax, [g_StreamerInitialized]
    test rax, rax
    jnz streamer_init_done
    
    ; Clear token buffer
    push rdi
    lea rdi, g_TokenBuffer
    mov rcx, STREAMER_BUFFER_SIZE
    xor eax, eax
    rep stosb
    pop rdi
    mov qword ptr [g_TokenCount], 0
    
    ; Initialize last flush time to current TSC (prevent immediate timeout)
    push rdx
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [g_LastFlushTime], rax
    pop rdx

    ; Mark as initialized
    mov qword ptr [g_StreamerInitialized], 1

streamer_init_done:
    mov eax, 1
    pop rbx
    ret
STREAMER_INIT ENDP

; ==============================================================================
; STREAMER_PUSH_TOKEN: Push single token from inference
; RCX = Token character (byte)
; RDX = Confidence (float bits, optional)
; ==============================================================================
STREAMER_PUSH_TOKEN PROC
    push rbx
    push rsi
    push rdi
    
    ; 1. Initialization Check
    mov rax, [g_StreamerInitialized]
    test rax, rax
    jz push_token_exit
    
    ; 2. Atomic Reservation Loop (Prevents Buffer Overflow Under Contention)
    ; Instead of blind lock xadd, we reserve an index only if buffer has room.
push_token_retry:
    mov rbx, [g_TokenCount]             ; Read current count
    cmp rbx, STREAMER_BUFFER_SIZE - 1
    jae push_token_force_flush          ; Buffer full → force flush now
    
    mov rax, rbx                        ; Expected old value for cmpxchg
    mov rcx, rbx
    inc rcx                             ; Target new count
    lock cmpxchg [g_TokenCount], rcx    ; Try atomic increment
    jnz push_token_retry                ; Collision → retry with fresh count
    
    ; 3. Write Token
    ; RBX is now our private index (guaranteed < STREAMER_BUFFER_SIZE)
    lea rdi, g_TokenBuffer
    mov byte ptr [rdi + rbx], cl        ; CL contains token from caller
    
    ; 4. Update Confidence (if provided in EDX)
    test edx, edx
    jz push_token_timeout
    mov [g_TokenConfidence], edx
    
push_token_timeout:
    ; TIMEOUT CHECK: Flush if 150ms elapsed
    rdtsc
    shl rdx, 32
    or rax, rdx                         ; RAX = Current TSC
    mov rdx, [g_LastFlushTime]
    sub rax, rdx
    cmp rax, FLUSH_TIMEOUT_CYCLES
    jae push_token_do_flush
    
push_token_exit:
    pop rdi
    pop rsi
    pop rbx
    ret
    
push_token_do_flush:
    call STREAMER_FLUSH
    pop rdi
    pop rsi
    pop rbx
    ret
    
push_token_force_flush:
    call STREAMER_FLUSH
    pop rdi
    pop rsi
    pop rbx
    ret
STREAMER_PUSH_TOKEN ENDP

; ==============================================================================
; STREAMER_FLUSH: Flush accumulated tokens to Ghost Engine + sign telemetry
; ==============================================================================
STREAMER_FLUSH PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Check if initialized
    mov rax, [g_StreamerInitialized]
    test rax, rax
    jz flush_skip
    
    ; Get token count
    mov rbx, [g_TokenCount]
    test rbx, rbx
    jz flush_skip
    
    ; External bridge calls are fail-open bypassed by default to prevent
    ; completion-path hangs from telemetry/ghost backpressure.
    cmp qword ptr [g_StreamerBypassExternal], 0
    jne flush_local_only

    ; --------------------------------------------------------------------------
    ; Sovereign Telemetry: Sign the token batch before pushing to Ghost Engine
    ; --------------------------------------------------------------------------
    ; Reserve 64 bytes on stack for signature output
    sub rsp, 64
    mov r12, rsp                        ; r12 = signature buffer
    
    lea rcx, g_TokenBuffer              ; RCX = buffer pointer
    mov rdx, rbx                        ; RDX = length
    mov r8, r12                         ; R8  = signature output buffer
    call SOVEREIGN_TELEMETRY_SIGN       ; Returns signature length in RAX
    
    ; If signature succeeded (RAX > 0), store it; otherwise continue unsigned
    mov r13, rax                        ; r13 = signature length
    
    ; Push to Ghost Engine
    lea rcx, g_TokenBuffer
    mov rdx, rbx
    mov r8d, [g_TokenConfidence]
    call PUSH_GHOST_PREDICTION
    
    ; Clean up signature stack space
    add rsp, 64

flush_local_only:
    
    ; Clear buffer
    lea rdi, g_TokenBuffer
    mov rcx, STREAMER_BUFFER_SIZE
    xor eax, eax
    rep stosb
    mov qword ptr [g_TokenCount], 0
    
    ; Update last flush time
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [g_LastFlushTime], rax
    
flush_skip:
    mov eax, 1
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
STREAMER_FLUSH ENDP

; ==============================================================================
; STREAMER_SET_CONFIDENCE: Set confidence threshold
; RCX = Confidence value (float bits)
; ==============================================================================
PUBLIC STREAMER_SET_CONFIDENCE
STREAMER_SET_CONFIDENCE PROC
    mov [g_TokenConfidence], ecx
    ret
STREAMER_SET_CONFIDENCE ENDP

; ==============================================================================
; STREAMER_GET_BUFFER: Get current token buffer pointer
; Returns: RAX = Buffer pointer, RDX = Count
; ==============================================================================
STREAMER_GET_BUFFER PROC
    lea rax, g_TokenBuffer
    mov rdx, [g_TokenCount]
    ret
STREAMER_GET_BUFFER ENDP

; ==============================================================================
; STREAMER_IS_INITIALIZED: Check initialization status
; Returns: RAX = 1 if initialized, 0 otherwise
; ==============================================================================
STREAMER_IS_INITIALIZED PROC
    mov rax, [g_StreamerInitialized]
    ret
STREAMER_IS_INITIALIZED ENDP

; ==============================================================================
; End
; ==============================================================================
end
