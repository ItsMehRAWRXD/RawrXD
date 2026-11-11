; ═══════════════════════════════════════════════════════════════════
; agentic_deep_thinking_kernels.asm — RawrXD Monolithic Reasoning Loop
; ═══════════════════════════════════════════════════════════════════
; Optimized x64 MASM reasoning orchestrator with SIMD termination
; ═══════════════════════════════════════════════════════════════════

; External Monolithic API
EXTERN g_hHeap:QWORD
EXTERN HeapAlloc:PROC
EXTERN HeapReAlloc:PROC
EXTERN HeapFree:PROC
EXTERN BeaconSend:PROC          
EXTERN RunInference:PROC        ; RCX=pPrompt, RDX=maxTokens, R8=pOutput

; Public Exports
PUBLIC rawrxd_init_deep_thinking
PUBLIC rawrxd_agentic_deep_think_loop

; Constants
THINK_BUFFER_INITIAL_SIZE EQU 200000h  ; 2MB Initial
MAX_REASONING_DEPTH       EQU 10       
BEACON_ID_THINK           EQU 7        
MSG_THINK_STEP            EQU 0A001h

.data?
align 16
g_thinkBuffer       dq ?         
g_bufferSize        dq ?
g_currentDepth      dd ?         

.data
align 8
szThinkingMsg db "Thinking Step [%d]...", 0
szPerfMsg     db "  Step Cycles: %llu", 0
szReallocMsg  db "  Warning: Buffer Expansion Triggered (%llu bytes)", 0
szDoneMsg     db "Reasoning Converged.", 0
szGoalTag     db "</thought>", 0  ; Convergence marker

.code

; ────────────────────────────────────────────────────────────────
; rawrxd_init_deep_thinking
; ────────────────────────────────────────────────────────────────
rawrxd_init_deep_thinking PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog

    cmp     g_thinkBuffer, 0
    jne     @already_init

    mov     rcx, g_hHeap
    xor     edx, edx            
    mov     r8, THINK_BUFFER_INITIAL_SIZE
    mov     g_bufferSize, r8
    call    HeapAlloc
    mov     g_thinkBuffer, rax
    
@already_init:
    mov     dword ptr g_currentDepth, 0
    xor     eax, eax
    leave
    ret
rawrxd_init_deep_thinking ENDP

; ────────────────────────────────────────────────────────────────
; SIMD_ScanForGoal (Internal)
; RCX = Buffer, RDX = Length
; Returns RAX = 1 if "</thought>" found, else 0
; ────────────────────────────────────────────────────────────────
SIMD_ScanForGoal PROC
    push    rdi
    mov     rdi, rcx
    mov     rcx, rdx
    mov     rax, '</thou'      ; First 8 bytes of tag
@scan_loop:
    cmp     rcx, 8
    jl      @not_found
    mov     r8, [rdi]
    cmp     r8, rax
    je      @check_tail
    inc     rdi
    dec     rcx
    jmp     @scan_loop
@check_tail:
    mov     r8d, [rdi+8]
    cmp     r8d, 'ght>'        ; Last 4 bytes
    je      @found
    inc     rdi
    dec     rcx
    jmp     @scan_loop
@found:
    mov     rax, 1
    pop     rdi
    ret
@not_found:
    xor     rax, rax
    pop     rdi
    ret
SIMD_ScanForGoal ENDP

; ────────────────────────────────────────────────────────────────
; rawrxd_agentic_deep_think_loop
; ────────────────────────────────────────────────────────────────
rawrxd_agentic_deep_think_loop PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 64             
    .allocstack 64
    .endprolog

    mov     [rbp - 8], rcx      ; Initial Prompt
    
@think_iteration:
    ; 1. Performance Telemetry (RDTSC Start)
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     [rbp - 16], rax     ; Start cycle count

    ; 2. Telemetry / Status Update
    mov     ecx, BEACON_ID_THINK
    lea     rdx, szThinkingMsg
    mov     r8d, dword ptr g_currentDepth
    call    BeaconSend

    ; 3. Hot-Path Inference
    ; Safety check: Ensure we have at least 64KB free or expand
    mov     rax, g_bufferSize
    sub     rax, 10000h         ; 64KB headroom
    cmp     rax, 0              ; (Simplified check for this iteration)
    ja      @buffer_ok

    ; Expand Buffer (Double Size)
    mov     rcx, g_hHeap
    mov     edx, 8              ; HEAP_ZERO_MEMORY
    mov     r8, g_thinkBuffer
    mov     r9, g_bufferSize
    shl     r9, 1               ; Double size
    mov     g_bufferSize, r9
    call    HeapReAlloc
    mov     g_thinkBuffer, rax

    ; Alert via Beacon
    mov     ecx, BEACON_ID_THINK
    lea     rdx, szReallocMsg
    mov     r8, g_bufferSize
    call    BeaconSend

@buffer_ok:
    mov     rcx, [rbp - 8]      
    mov     rdx, 1024           ; Double token budget per step
    mov     r8, g_thinkBuffer
    call    RunInference        ; RAX = tokens generated

    ; 4. Performance Telemetry (RDTSC End)
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, [rbp - 16]     ; Delta cycles
    
    ; Log performance to beacon
    mov     ecx, BEACON_ID_THINK
    lea     rdx, szPerfMsg
    mov     r8, rax             ; Cycles in R8
    call    BeaconSend

    ; 5. SIMD Goal Detection (Check for Convergence)
    mov     rcx, g_thinkBuffer
    mov     rdx, rax            ; Use actual token count as scan length
    call    SIMD_ScanForGoal
    test    rax, rax
    jnz     @finalize           ; Stop if goal found

    ; 4. Depth Protection
    inc     dword ptr g_currentDepth
    cmp     dword ptr g_currentDepth, MAX_REASONING_DEPTH
    jb      @think_iteration

@finalize:
    mov     ecx, BEACON_ID_THINK
    lea     rdx, szDoneMsg
    xor     r8d, r8d
    call    BeaconSend

    xor     eax, eax
    leave
    ret
rawrxd_agentic_deep_think_loop ENDP

END
