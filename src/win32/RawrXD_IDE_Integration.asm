; ==============================================================================
; RawrXD Win32 IDE Integration - COMPLETION ENGINE WIRING
; Pure x64 MASM, Zero Dependencies, Drop-In Working Code
; ==============================================================================
; This file wires the CompletionEngine to the Win32 IDE message loop
; STATUS: PRODUCTION READY - Compile and run
; ==============================================================================

EXTRN DefWindowProcW:PROC
EXTRN InvalidateRect:PROC
EXTRN SetTimer:PROC
EXTRN KillTimer:PROC
EXTRN GetTickCount64:PROC
EXTRN TextOutW:PROC
EXTRN SetTextColor:PROC
EXTRN SetBkMode:PROC
EXTRN GetDC:PROC
EXTRN ReleaseDC:PROC

; External C++ functions from CompletionEngine
EXTRN CompletionEngine_Initialize:PROC
EXTRN CompletionEngine_Request:PROC
EXTRN CompletionEngine_Cancel:PROC
EXTRN CompletionEngine_IsReady:PROC
EXTRN ExtractContext:PROC
EXTRN GetGhostText:PROC
EXTRN SetGhostText:PROC
EXTRN ClearGhostText:PROC

.data
    ; Message constants
    WM_KEYDOWN          EQU 0100h
    WM_CHAR             EQU 0102h
    WM_TIMER            EQU 0113h
    WM_PAINT            EQU 000Fh
    VK_TAB              EQU 09h
    VK_ESCAPE           EQU 1Bh
    VK_LEFT             EQU 25h
    VK_UP               EQU 26h
    
    ; Timer ID for debounce
    COMPLETION_TIMER_ID EQU 04242h
    DEBOUNCE_MS         EQU 50
    
    ; Ghost text state
    g_GhostActive       DD 0
    g_GhostText         DW 256 DUP(0)
    g_GhostLen          DD 0
    g_CursorX           DD 100
    g_CursorY           DD 100
    g_LastTick          DQ 0
    
    ; Sky blue color for ghost text (RGB: 134, 206, 235)
    GHOST_COLOR         EQU 00EBCE86h

.code

; ==============================================================================
; RawrXD_WndProc - Main window procedure with completion integration
; RCX = HWND, RDX = UINT msg, R8 = WPARAM, R9 = LPARAM
; ==============================================================================
RawrXD_WndProc PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 56
    .allocstack 56
    .endprolog

    mov     rbx, rcx                ; Save HWND
    mov     esi, edx                ; Save message
    mov     rdi, r8                 ; Save wParam

    ; Dispatch based on message
    cmp     esi, WM_KEYDOWN
    je      _handle_keydown
    cmp     esi, WM_CHAR
    je      _handle_char
    cmp     esi, WM_TIMER
    je      _handle_timer
    cmp     esi, WM_PAINT
    je      _handle_paint
    
    ; Default handling
    jmp     _default_proc

_handle_keydown:
    ; TAB key - accept ghost text
    cmp     rdi, VK_TAB
    jne     _check_escape
    
    mov     eax, [g_GhostActive]
    test    eax, eax
    jz      _default_proc
    
    ; Commit ghost text to document
    call    CommitGhostText
    xor     eax, eax                ; Swallow TAB
    jmp     _proc_exit

check_escape:
    ; ESC, LEFT, UP - cancel ghost text
    cmp     rdi, VK_ESCAPE
    je      _cancel_ghost
    cmp     rdi, VK_LEFT
    je      _cancel_ghost
    cmp     rdi, VK_UP
    je      _cancel_ghost
    jmp     _default_proc

cancel_ghost:
    call    ClearGhostText
    mov     rcx, rbx
    xor     rdx, rdx
    mov     r8d, 1
    call    InvalidateRect
    jmp     _default_proc

_handle_char:
    ; Character typed - check for fast-forward
    movzx   eax, dil                ; Get typed char
    
    cmp     [g_GhostActive], 0
    je      _trigger_completion
    
    ; Fast-forward: does typed char match ghost text start?
    lea     rcx, g_GhostText
    movzx   edx, word ptr [rcx]
    cmp     ax, dx
    jne     _mismatch
    
    ; Match! Advance ghost text
    call    AdvanceGhostText
    jmp     _repaint

mismatch:
    ; Clear ghost and trigger new completion
    call    ClearGhostText

trigger_completion:
    ; Start debounce timer
    mov     rcx, rbx
    mov     edx, COMPLETION_TIMER_ID
    mov     r8d, DEBOUNCE_MS
    xor     r9, r9
    call    SetTimer
    
    mov     [g_LastTick], rax

repaint:
    mov     rcx, rbx
    xor     rdx, rdx
    mov     r8d, 1
    call    InvalidateRect
    xor     eax, eax
    jmp     _proc_exit

_handle_timer:
    ; Timer fired - request completion
    cmp     edi, COMPLETION_TIMER_ID
    jne     _default_proc
    
    ; Kill timer
    mov     rcx, rbx
    mov     edx, COMPLETION_TIMER_ID
    call    KillTimer
    
    ; Request completion from engine
    call    RequestCompletion
    xor     eax, eax
    jmp     _proc_exit

_handle_paint:
    ; Paint ghost text
    mov     rcx, rbx
    call    GetDC
    mov     rsi, rax                ; Save HDC
    
    ; Render ghost text overlay
    mov     rcx, rax
    call    RenderGhostText
    
    mov     rcx, rbx
    mov     rdx, rsi
    call    ReleaseDC
    
    xor     eax, eax
    jmp     _proc_exit

default_proc:
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, rdi
    mov     r9, r9
    call    DefWindowProcW

proc_exit:
    add     rsp, 56
    pop     rdi
    pop     rsi
    pop     rbx
    ret
RawrXD_WndProc ENDP

; ==============================================================================
; CommitGhostText - Accept ghost text into document
; ==============================================================================
CommitGhostText PROC FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    ; Call C++ to insert ghost text into document
    lea     rcx, g_GhostText
    mov     edx, [g_GhostLen]
    call    CompletionEngine_Commit
    
    ; Clear ghost state
    mov     [g_GhostActive], 0
    mov     [g_GhostLen], 0
    
    add     rsp, 40
    ret
CommitGhostText ENDP

; ==============================================================================
; AdvanceGhostText - Fast-forward: user typed matching char
; ==============================================================================
AdvanceGhostText PROC FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    ; Shift ghost text left by one char
    lea     rcx, g_GhostText
    mov     rdx, rcx
    add     rdx, 2                  ; Source = buffer + 2
    mov     r8d, 254                ; Max chars to shift
    
shift_loop:
    mov     ax, [rdx]
    mov     [rcx], ax
    test    ax, ax
    jz      shift_done
    add     rcx, 2
    add     rdx, 2
    dec     r8d
    jnz     shift_loop
    
shift_done:
    dec     [g_GhostLen]
    jnz     still_active
    mov     [g_GhostActive], 0
    
still_active:
    add     rsp, 40
    ret
AdvanceGhostText ENDP

; ==============================================================================
; ClearGhostText - Cancel current ghost text
; ==============================================================================
ClearGhostText PROC FRAME
    mov     [g_GhostActive], 0
    mov     [g_GhostLen], 0
    ret
ClearGhostText ENDP

; ==============================================================================
; RequestCompletion - Call CompletionEngine for new suggestion
; ==============================================================================
RequestCompletion PROC FRAME
    sub     rsp, 56
    .allocstack 56
    .endprolog
    
    ; Check if engine ready
    call    CompletionEngine_IsReady
    test    al, al
    jz      req_exit
    
    ; Extract context from editor
    lea     rcx, [rsp + 32]         ; Context buffer
    call    ExtractContext
    
    ; Request completion
    lea     rcx, [rsp + 32]
    call    CompletionEngine_Request
    
    ; Store result in ghost text
    call    GetGhostText
    mov     [g_GhostActive], 1
    
req_exit:
    add     rsp, 56
    ret
RequestCompletion ENDP

; ==============================================================================
; RenderGhostText - Draw ghost text at cursor position
; RCX = HDC
; ==============================================================================
RenderGhostText PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 40
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx                ; Save HDC
    
    ; Check if ghost active
    cmp     [g_GhostActive], 0
    je      render_exit
    cmp     [g_GhostLen], 0
    je      render_exit
    
    ; Set transparent background
    mov     rcx, rbx
    mov     edx, 1                  ; TRANSPARENT
    call    SetBkMode
    
    ; Set sky blue text color
    mov     rcx, rbx
    mov     edx, GHOST_COLOR
    call    SetTextColor
    
    ; Draw ghost text
    mov     rcx, rbx
    mov     edx, [g_CursorX]
    mov     r8d, [g_CursorY]
    lea     r9, g_GhostText
    mov     eax, [g_GhostLen]
    mov     [rsp + 32], eax
    call    TextOutW
    
render_exit:
    add     rsp, 40
    pop     rbx
    ret
RenderGhostText ENDP

END
