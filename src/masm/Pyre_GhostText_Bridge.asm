;============================================================================
; Pyre_GhostText_Bridge.asm
; 
; MASM64 bridge between Pyre token generation and IDE Ghost Text
; 
; This module provides the glue between Pyre's pure assembly inference
; and the C++ GhostText_PyreBridge ring buffer.
; 
; Key functions:
;   - PyreGhost_Init: Initialize bridge with editor HWND
;   - PyreGhost_SubmitToken: Submit token from Pyre to ring buffer
;   - PyreGhost_CheckStop: Check if generation should stop
;   - PyreGhost_Shutdown: Cleanup
;============================================================================

include Pyre_Macros.inc

;============================================================================
; External C++ functions (from GhostText_PyreBridge.cpp)
;============================================================================
EXTERN GhostText_PyreBridge_Instance:PROC
EXTERN GhostText_PyreBridge_Initialize:PROC
EXTERN GhostText_PyreBridge_SubmitToken:PROC
EXTERN GhostText_PyreBridge_RequestStop:PROC
EXTERN GhostText_PyreBridge_IsStopRequested:PROC
EXTERN GhostText_PyreBridge_Shutdown:PROC
EXTERN PyreStopFlag_IsStopped:PROC

;============================================================================
; Data section
;============================================================================
.data
    align 64
    
    ; Bridge instance pointer (cached)
    g_bridgeInstance    DQ 0
    
    ; Token accumulation buffer (for multi-byte UTF-8)
    g_tokenBuffer       DB 256 DUP(0)
    g_tokenLength       DD 0
    
    ; Statistics
    g_tokensSubmitted   DQ 0
    g_tokensDropped     DQ 0
    g_stopChecks        DQ 0

;============================================================================
; Code section
;============================================================================
.code

;----------------------------------------------------------------------------
; PyreGhost_GetBridgeInstance
; Returns: RAX = GhostText_PyreBridge* (cached)
; Clobbers: RAX, RCX, RDX, R8-R11
;----------------------------------------------------------------------------
PyreGhost_GetBridgeInstance PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    ; Check if cached
    mov rax, g_bridgeInstance
    test rax, rax
    jnz @@done
    
    ; Call C++ singleton
    sub rsp, 32
    call GhostText_PyreBridge_Instance
    add rsp, 32
    
    ; Cache result
    mov g_bridgeInstance, rax
    
@@done:
    pop rbx
    ret
PyreGhost_GetBridgeInstance ENDP

;----------------------------------------------------------------------------
; PyreGhost_Init
; Initialize the Ghost Text bridge
; RCX = HWND hEditor
; Returns: RAX = bool success
;----------------------------------------------------------------------------
PyreGhost_Init PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    .endprolog
    
    mov rbx, rcx                    ; Save HWND
    
    ; Get bridge instance
    call PyreGhost_GetBridgeInstance
    mov rdi, rax                    ; RDI = bridge instance
    
    ; Call Initialize
    mov rcx, rbx                    ; HWND
    sub rsp, 32
    call GhostText_PyreBridge_Initialize
    add rsp, 32
    
    ; Reset stats
    mov g_tokensSubmitted, 0
    mov g_tokensDropped, 0
    mov g_stopChecks, 0
    mov g_tokenLength, 0
    
    pop rdi
    pop rbx
    ret
PyreGhost_Init ENDP

;----------------------------------------------------------------------------
; PyreGhost_SubmitToken
; Submit a token to the Ghost Text ring buffer
; RCX = const char* token (UTF-8 text)
; RDX = uint32_t length
; R8  = uint32_t tokenId (optional)
; R9  = float confidence (optional, in XMM0)
; Returns: RAX = bool success
; 
; Performance: ~50ns (lock-free ring buffer)
;----------------------------------------------------------------------------
PyreGhost_SubmitToken PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    .endprolog
    
    mov rbx, rcx                    ; RBX = token pointer
    mov esi, edx                    ; ESI = length
    mov r12d, r8d                   ; R12D = tokenId
    
    ; Get bridge instance
    call PyreGhost_GetBridgeInstance
    mov rdi, rax                    ; RDI = bridge instance
    test rdi, rdi
    jz @@fail
    
    ; Clamp length to max token size
    cmp esi, 63
    jbe @@length_ok
    mov esi, 63
@@length_ok:
    
    ; Call SubmitToken
    ; bool SubmitToken(const char* token, uint32_t length, 
    ;                  uint32_t tokenId, float confidence)
    mov rcx, rbx                    ; token
    mov edx, esi                    ; length
    mov r8d, r12d                   ; tokenId
    ; confidence already in XMM0
    
    sub rsp, 40                     ; Shadow space + alignment
    call GhostText_PyreBridge_SubmitToken
    add rsp, 40
    
    ; Update stats
    test al, al
    jz @@dropped
    
    inc qword ptr [g_tokensSubmitted]
    jmp @@done
    
@@dropped:
    inc qword ptr [g_tokensDropped]
    
@@done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
@@fail:
    xor eax, eax
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
PyreGhost_SubmitToken ENDP

;----------------------------------------------------------------------------
; PyreGhost_SubmitChar
; Submit a single character/token (simplified API)
; RCX = char c (or AL = char)
; Returns: RAX = bool success
;----------------------------------------------------------------------------
PyreGhost_SubmitChar PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    ; Store char in temp buffer
    mov byte ptr [g_tokenBuffer], al
    mov byte ptr [g_tokenBuffer+1], 0
    
    ; Call SubmitToken
    lea rcx, [g_tokenBuffer]
    mov edx, 1                      ; length = 1
    xor r8d, r8d                    ; tokenId = 0
    xorps xmm0, xmm0
    movss xmm0, __real@3f800000     ; confidence = 1.0
    
    sub rsp, 40
    call GhostText_PyreBridge_SubmitToken
    add rsp, 40
    
    pop rbx
    ret
PyreGhost_SubmitChar ENDP

;----------------------------------------------------------------------------
; PyreGhost_CheckStop
; Check if generation should stop (hot path - called every token)
; Returns: RAX = bool (true = stop requested)
; 
; Performance: ~3ns (atomic relaxed load)
;----------------------------------------------------------------------------
PyreGhost_CheckStop PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    inc qword ptr [g_stopChecks]
    
    ; Call C++ stop flag check
    sub rsp, 32
    call PyreStopFlag_IsStopped
    add rsp, 32
    
    pop rbx
    ret
PyreGhost_CheckStop ENDP

;----------------------------------------------------------------------------
; PyreGhost_RequestStop
; Request Pyre generation to stop
;----------------------------------------------------------------------------
PyreGhost_RequestStop PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    sub rsp, 32
    call GhostText_PyreBridge_RequestStop
    add rsp, 32
    
    pop rbx
    ret
PyreGhost_RequestStop ENDP

;----------------------------------------------------------------------------
; PyreGhost_Shutdown
; Shutdown the Ghost Text bridge
;----------------------------------------------------------------------------
PyreGhost_Shutdown PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    ; Get bridge instance
    call PyreGhost_GetBridgeInstance
    test rax, rax
    jz @@done
    
    mov rcx, rax
    sub rsp, 32
    call GhostText_PyreBridge_Shutdown
    add rsp, 32
    
    mov g_bridgeInstance, 0
    
@@done:
    pop rbx
    ret
PyreGhost_Shutdown ENDP

;----------------------------------------------------------------------------
; PyreGhost_GetStats
; Get submission statistics
; RCX = uint64_t* out_tokensSubmitted
; RDX = uint64_t* out_tokensDropped
;----------------------------------------------------------------------------
PyreGhost_GetStats PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    mov rbx, rcx                    ; RBX = out_tokensSubmitted
    
    mov rax, g_tokensSubmitted
    mov [rbx], rax
    
    mov rax, g_tokensDropped
    mov [rdx], rax
    
    pop rbx
    ret
PyreGhost_GetStats ENDP

;----------------------------------------------------------------------------
; PyreGhost_ClearStats
; Reset statistics counters
;----------------------------------------------------------------------------
PyreGhost_ClearStats PROC FRAME
    mov g_tokensSubmitted, 0
    mov g_tokensDropped, 0
    mov g_stopChecks, 0
    ret
PyreGhost_ClearStats ENDP

;============================================================================
; Integration with Pyre_GenerateLoop
; These functions are called from the main generation loop
;============================================================================

;----------------------------------------------------------------------------
; PyreGhost_OnTokenGenerated
; Called by Pyre after each token is generated
; RCX = const char* tokenText
; RDX = uint32_t tokenLength
; R8  = uint32_t tokenId
; Returns: RAX = bool continueGeneration (false = stop)
;----------------------------------------------------------------------------
PyreGhost_OnTokenGenerated PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog
    
    mov rbx, rcx                    ; RBX = token text
    mov esi, edx                    ; ESI = length
    mov edi, r8d                    ; EDI = tokenId
    
    ; Check stop flag first (fast path)
    call PyreGhost_CheckStop
    test al, al
    jnz @@stop_requested
    
    ; Submit token to ring buffer
    mov rcx, rbx
    mov edx, esi
    mov r8d, edi
    xorps xmm0, xmm0
    movss xmm0, __real@3f800000     ; confidence = 1.0
    
    call PyreGhost_SubmitToken
    
    ; Return true to continue
    mov eax, 1
    jmp @@done
    
@@stop_requested:
    ; Return false to stop generation
    xor eax, eax
    
@@done:
    pop rdi
    pop rsi
    pop rbx
    ret
PyreGhost_OnTokenGenerated ENDP

;============================================================================
; End of module
;============================================================================
END
