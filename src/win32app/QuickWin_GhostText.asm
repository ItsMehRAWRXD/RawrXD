; ==============================================================================
; RawrXD Quick Win: Ghost Text Integration
; Minimal working implementation - no stubs, no scaffolding
; ==============================================================================

EXTRN DefWindowProcW:PROC
EXTRN InvalidateRect:PROC
EXTRN TextOutW:PROC
EXTRN SetTextColor:PROC
EXTRN SetBkMode:PROC

.data
    ; Ghost text state
    g_GhostActive       dd  0           ; 0 = off, 1 = on
    g_GhostBuffer       dw  256 dup(0) ; UTF-16 ghost text
    g_GhostLen          dd  0
    g_CursorX           dd  100         ; Screen X
    g_CursorY           dd  100         ; Screen Y
    
    ; Colors
    COLOR_SKYBLUE       equ 00D7BDE6h    ; Ethereal sky-blue

.code

; ------------------------------------------------------------------------------
; QuickWin_WndProc - Drop-in replacement for your existing WndProc
; Handles: TAB (accept), ESC/LEFT/UP (cancel), CHAR (fast-forward)
; ------------------------------------------------------------------------------
QuickWin_WndProc PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rbx, rcx            ; hwnd
    mov     esi, edx            ; msg
    mov     r10, r8             ; wParam

    ; WM_KEYDOWN = 0x100
    cmp     esi, 100h
    je      _keydown
    
    ; WM_CHAR = 0x102
    cmp     esi, 102h
    je      _char
    
    ; WM_PAINT = 0xF
    cmp     esi, 0Fh
    je      _paint

_default:
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r10
    call    DefWindowProcW
    jmp     _exit

_keydown:
    ; TAB = 0x09 - Accept ghost text
    cmp     r10, 9
    jne     _check_cancel
    
    mov     eax, [g_GhostActive]
    test    eax, eax
    jz      _default
    
    ; ACCEPT: Insert ghost text into document here
    call    InsertGhostIntoDocument
    mov     [g_GhostActive], 0
    xor     rax, rax            ; Swallow TAB
    jmp     _exit

_check_cancel:
    ; ESC=0x1B, LEFT=0x25, UP=0x26 - Cancel ghost text
    cmp     r10, 1Bh
    je      _cancel
    cmp     r10, 25h
    je      _cancel
    cmp     r10, 26h
    je      _cancel
    jmp     _default

_cancel:
    mov     [g_GhostActive], 0
    mov     rcx, rbx
    xor     rdx, rdx
    mov     r8d, 1
    call    InvalidateRect
    jmp     _default

_char:
    ; Fast-forward: if typed char matches ghost[0], advance ghost
    mov     eax, [g_GhostActive]
    test    eax, eax
    jz      _trigger_completion
    
    ; Compare typed char (r10b) with ghost[0]
    movzx   eax, word ptr [g_GhostBuffer]
    cmp     ax, r10w
    jne     _trigger_completion
    
    ; MATCH: Shift ghost buffer left
    call    ShiftGhostLeft
    jmp     _redraw

_trigger_completion:
    ; User typed something new - trigger completion after debounce
    mov     [g_GhostActive], 0
    ; TODO: Call CompletionEngine here after 50ms debounce

_redraw:
    mov     rcx, rbx
    xor     rdx, rdx
    mov     r8d, 1
    call    InvalidateRect
    xor     rax, rax
    jmp     _exit

_paint:
    ; Render ghost text overlay
    mov     rcx, r10            ; HDC from wParam or GetDC
    call    RenderGhostText
    xor     rax, rax

_exit:
    add     rsp, 40
    pop     rsi
    pop     rbx
    ret
QuickWin_WndProc ENDP

; ------------------------------------------------------------------------------
; RenderGhostText - Draw ethereal sky-blue ghost text at cursor
; ------------------------------------------------------------------------------
RenderGhostText PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rbx, rcx            ; HDC

    mov     eax, [g_GhostActive]
    test    eax, eax
    jz      _done
    mov     eax, [g_GhostLen]
    test    eax, eax
    jz      _done

    ; Set transparent background
    mov     rcx, rbx
    mov     edx, 1              ; TRANSPARENT
    call    SetBkMode

    ; Set sky-blue color
    mov     rcx, rbx
    mov     edx, COLOR_SKYBLUE
    call    SetTextColor

    ; Draw ghost text
    mov     rcx, rbx
    mov     edx, [g_CursorX]
    mov     r8d, [g_CursorY]
    lea     r9, [g_GhostBuffer]
    mov     eax, [g_GhostLen]
    mov     dword ptr [rsp+32], eax
    call    TextOutW

_done:
    add     rsp, 40
    pop     rbx
    ret
RenderGhostText ENDP

; ------------------------------------------------------------------------------
; ShiftGhostLeft - Remove first char from ghost buffer (fast-forward)
; ------------------------------------------------------------------------------
ShiftGhostLeft PROC FRAME
    mov     eax, [g_GhostLen]
    dec     eax
    mov     [g_GhostLen], eax
    jz      _empty
    
    ; Shift UTF-16 buffer left by 1 char
    lea     rcx, [g_GhostBuffer]
    mov     rdx, rcx
    add     rdx, 2
    mov     r8, 127
_shift:
    mov     ax, [rdx]
    mov     [rcx], ax
    add     rcx, 2
    add     rdx, 2
    dec     r8
    jnz     _shift
_empty:
    ret
ShiftGhostLeft ENDP

; ------------------------------------------------------------------------------
; InsertGhostIntoDocument - Commit ghost text to main buffer
; ------------------------------------------------------------------------------
InsertGhostIntoDocument PROC FRAME
    ; TODO: Insert g_GhostBuffer (length g_GhostLen) at cursor position
    ; This is your piece table / gap buffer insertion
    ret
InsertGhostIntoDocument ENDP

; ------------------------------------------------------------------------------
; SetGhostText - Called by CompletionEngine when suggestion arrives
; RCX = UTF-16 string pointer, RDX = length
; ------------------------------------------------------------------------------
SetGhostText PROC FRAME
    mov     r8, rcx
    mov     r9d, edx
    
    lea     rax, [g_GhostBuffer]
_copy:
    mov     cx, [r8]
    mov     [rax], cx
    add     r8, 2
    add     rax, 2
    dec     r9d
    jnz     _copy
    
    mov     [g_GhostLen], edx
    mov     [g_GhostActive], 1
    ret
SetGhostText ENDP

END
