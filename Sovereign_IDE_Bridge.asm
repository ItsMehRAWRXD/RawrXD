; ==============================================================================
; Sovereign_IDE_Bridge.asm - Ghost Engine ↔ IDE Integration Layer
; ==============================================================================
; Bridges the Ghost Engine predictive overlay into the RawrXD IDE paint loop.
; Hooks into EditorWindow_HandlePaint to render AI suggestions as ghost text.
;
; Integration Points:
;   - IDE_GHOST_INIT: Initialize Ghost Engine on IDE startup
;   - IDE_GHOST_RENDER: Called from WM_PAINT after text rendering
;   - IDE_GHOST_PUSH: Called from AI thread when prediction arrives
;   - IDE_GHOST_HEARTBEAT: Called from IDE timer (60FPS)
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN INIT_GHOST_BUFFER : PROC
EXTERN PUSH_GHOST_PREDICTION : PROC
EXTERN RENDER_GHOST_PREDICTIVE : PROC
EXTERN GET_GHOST_STATS : PROC
EXTERN GET_GHOST_LATENCY : PROC
EXTERN GHOST_HEARTBEAT : PROC
EXTERN FLUSH_GHOST_BUFFER : PROC

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; Bridge state
IDE_GhostInitialized    dq 0
IDE_LastPrediction      db 256 dup(0)
IDE_LastPredictionLen   dq 0

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; IDE_GHOST_INIT: Initialize Ghost Engine for IDE
; ==============================================================================
IDE_GHOST_INIT PROC
    push rbx
    
    ; Check if already initialized
    mov rax, [IDE_GhostInitialized]
    test rax, rax
    jnz init_done
    
    ; Initialize Ghost Engine
    call INIT_GHOST_BUFFER
    test eax, eax
    jz init_fail
    
    ; Mark as initialized
    mov qword ptr [IDE_GhostInitialized], 1
    
init_done:
    mov eax, 1
    jmp init_exit
    
init_fail:
    xor eax, eax
    
init_exit:
    pop rbx
    ret
IDE_GHOST_INIT ENDP

; ==============================================================================
; IDE_GHOST_RENDER: Render ghost text in IDE window
; RCX = HWND (editor window)
; ==============================================================================
IDE_GHOST_RENDER PROC
    push rbx
    
    ; Check if initialized
    mov rax, [IDE_GhostInitialized]
    test rax, rax
    jz render_skip
    
    ; Render ghost prediction
    mov rbx, rcx            ; Save HWND
    call RENDER_GHOST_PREDICTIVE
    
render_skip:
    pop rbx
    ret
IDE_GHOST_RENDER ENDP

; ==============================================================================
; IDE_GHOST_PUSH: Push AI prediction to Ghost Engine
; RCX = Text pointer
; RDX = Text length
; R8  = Confidence (float bits)
; ==============================================================================
IDE_GHOST_PUSH PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Check if initialized
    mov rax, [IDE_GhostInitialized]
    test rax, rax
    jz push_skip
    
    ; Save parameters
    mov r12, rcx            ; Text pointer
    mov r13, rdx            ; Text length
    
    ; Clamp length to 255
    cmp r13, 255
    jbe push_len_ok
    mov r13, 255
    
push_len_ok:
    ; Copy text to local buffer
    mov rsi, r12            ; Source
    mov rdi, OFFSET IDE_LastPrediction  ; Dest
    mov rcx, r13            ; Count
    rep movsb
    mov byte ptr [rdi], 0   ; Null terminate
    mov [IDE_LastPredictionLen], r13
    
    ; Push to Ghost Engine
    mov rcx, r12            ; Original text pointer
    mov rdx, r13            ; Length
    ; R8 already has confidence from caller
    call PUSH_GHOST_PREDICTION
    
push_skip:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
IDE_GHOST_PUSH ENDP

; ==============================================================================
; IDE_GHOST_HEARTBEAT: Periodic maintenance from IDE timer
; RCX = HWND (editor window)
; ==============================================================================
IDE_GHOST_HEARTBEAT PROC
    push rbx
    
    ; Check if initialized
    mov rax, [IDE_GhostInitialized]
    test rax, rax
    jz hb_skip
    
    ; Call Ghost Engine heartbeat
    mov rbx, rcx
    call GHOST_HEARTBEAT
    
hb_skip:
    pop rbx
    ret
IDE_GHOST_HEARTBEAT ENDP

; ==============================================================================
; IDE_GHOST_FLUSH: Clear all pending predictions
; ==============================================================================
IDE_GHOST_FLUSH PROC
    push rbx
    
    ; Check if initialized
    mov rax, [IDE_GhostInitialized]
    test rax, rax
    jz flush_skip
    
    ; Flush Ghost Buffer
    call FLUSH_GHOST_BUFFER
    
    ; Clear local prediction
    mov qword ptr [IDE_LastPredictionLen], 0
    
flush_skip:
    pop rbx
    ret
IDE_GHOST_FLUSH ENDP

; ==============================================================================
; IDE_GHOST_GET_LATENCY: Get last render latency for IDE status bar
; Returns: RAX = Latency in cycles
; ==============================================================================
IDE_GHOST_GET_LATENCY PROC
    call GET_GHOST_LATENCY
    ret
IDE_GHOST_GET_LATENCY ENDP

; ==============================================================================
; End
; ==============================================================================
end
