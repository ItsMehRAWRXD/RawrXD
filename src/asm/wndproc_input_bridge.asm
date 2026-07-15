; ============================================================================
; wndproc_input_bridge.asm - x64 MASM Window Procedure Input Bridge
; ============================================================================
; Architecture: x64 MASM, Windows x64 calling convention
; Purpose: Bridges Win32 WM_CHAR/WM_KEYDOWN messages to input_handler.asm
;          Integrates with existing win32ide_main.asm message pump.
;
; Integration Points:
;   - Call from WndProc when WM_CHAR/WM_KEYDOWN received
;   - Call Input_ProcessEvents from editor idle loop
;   - Direct buffer access via Input_GetBufferState
;
; Build: ml64 /c /Zi wndproc_input_bridge.asm
; Link: Link with input_handler.asm and editor.asm
; ============================================================================

option casemap:none

; ============================================================================
;                         CONSTANTS
; ============================================================================

; Window messages
WM_CHAR               EQU     0102h
WM_KEYDOWN            EQU     0100h
WM_KEYUP              EQU     0101h
WM_DESTROY            EQU     0002h
WM_CREATE             EQU     0001h
WM_SIZE               EQU     0005h
WM_PAINT              EQU     000Fh
WM_SETFOCUS           EQU     0007h
WM_KILLFOCUS          EQU     0008h

; Virtual key codes (duplicated from input_handler.asm for convenience)
VK_BACK               EQU     08h
VK_TAB                EQU     09h
VK_RETURN             EQU     0Dh
VK_SHIFT              EQU     10h
VK_CONTROL            EQU     11h
VK_MENU               EQU     12h
VK_ESCAPE             EQU     1Bh
VK_LEFT               EQU     25h
VK_UP                 EQU     26h
VK_RIGHT              EQU     27h
VK_DOWN               EQU     28h
VK_DELETE             EQU     2Eh

; ============================================================================
;                         EXTERNAL API
; ============================================================================

EXTERN DefWindowProcA:PROC
EXTERN CallWindowProcA:PROC
EXTERN PostQuitMessage:PROC
EXTERN InvalidateRect:PROC
EXTERN GetTickCount64:PROC

; External input handler functions
EXTERN Input_Init:PROC
EXTERN Input_OnChar:PROC
EXTERN Input_OnKeyDown:PROC
EXTERN Input_ProcessEvents:PROC
EXTERN Input_GetBufferState:PROC

; External editor functions
EXTERN Editor_Render:PROC
EXTERN Editor_Initialize:PROC

; ============================================================================
;                         DATA
; ============================================================================

.data

; Original window procedure (for subclassing)
g_OriginalWndProc    DQ 0

; Editor window handle
g_hEditorWnd         DQ 0

; Focus state
g_hasFocus           DB 0

; Last render time (for throttling)
g_lastRenderTime     DQ 0
RENDER_THROTTLE_MS   EQU 16    ; ~60 FPS

; Debug strings
szWndProcEnter       DB "[WNDPROC] Enter", 13, 10, 0
szCharReceived       DB "[WNDPROC] WM_CHAR: %c (0x%02X)", 13, 10, 0
szKeyDownReceived    DB "[WNDPROC] WM_KEYDOWN: VK=%d", 13, 10, 0

; ============================================================================
;                         CODE
; ============================================================================

.code

; ============================================================================
; WndProcInputBridge_Initialize
; ============================================================================
; Initializes the input bridge and connects to editor.
; Call this during WM_CREATE or application startup.
;
; Parameters:
;   RCX = hWnd (editor window handle)
; Returns: RAX = 1 on success, 0 on failure
; ============================================================================

ALIGN 16
WndProcInputBridge_Initialize PROC
    
    push    rbx
    sub     rsp, 28h
    
    mov     rbx, rcx            ; Save hWnd
    
    ; Initialize input handler
    call    Input_Init
    test    rax, rax
    jz      L_fail
    
    ; Initialize editor
    call    Editor_Initialize
    test    rax, rax
    jz      L_fail
    
    ; Store editor window handle
    mov     [g_hEditorWnd], rbx
    
    ; Set focus state
    mov     byte ptr [g_hasFocus], 1
    
    ; Initialize last render time
    call    GetTickCount64
    mov     [g_lastRenderTime], rax
    
    mov     rax, 1
    jmp     L_done
    
L_fail:
    xor     rax, rax
    
L_done:
    add     rsp, 28h
    pop     rbx
    ret

WndProcInputBridge_Initialize ENDP

; ============================================================================
; WndProcInputBridge_WndProc
; ============================================================================
; Window procedure that handles input messages and forwards to input_handler.
; Use this as the main WndProc or subclass an existing window.
;
; Parameters:
;   RCX = hWnd
;   RDX = uMsg
;   R8  = wParam
;   R9  = lParam
; Returns: LRESULT
; ============================================================================

ALIGN 16
WndProcInputBridge_WndProc PROC
    
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 28h
    
    mov     rbx, rcx            ; hWnd
    mov     esi, edx            ; uMsg
    mov     r12, r8             ; wParam
    mov     r13, r9             ; lParam
    
    ; Dispatch based on message
    cmp     esi, WM_CHAR
    je      L_wm_char
    cmp     esi, WM_KEYDOWN
    je      L_wm_keydown
    cmp     esi, WM_KEYUP
    je      L_wm_keyup
    cmp     esi, WM_SETFOCUS
    je      L_wm_setfocus
    cmp     esi, WM_KILLFOCUS
    je      L_wm_killfocus
    cmp     esi, WM_PAINT
    je      L_wm_paint
    cmp     esi, WM_DESTROY
    je      L_wm_destroy
    cmp     esi, WM_SIZE
    je      L_wm_size
    
    ; Default handling
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r12
    mov     r9, r13
    call    DefWindowProcA
    jmp     L_done
    
L_wm_char:
    ; Character input - forward to input handler
    mov     rcx, r12            ; wParam = character code
    mov     rdx, r13            ; lParam = key data
    call    Input_OnChar
    
    ; Invalidate for rendering
    xor     rdx, rdx            ; NULL rect = entire window
    xor     r8, r8              ; FALSE = don't erase background
    call    InvalidateRect
    
    mov     rax, 0              ; Return 0 (handled)
    jmp     L_done
    
L_wm_keydown:
    ; Key down - forward to input handler
    mov     rcx, r12            ; wParam = virtual key code
    mov     rdx, r13            ; lParam = key data
    call    Input_OnKeyDown
    
    ; Check if handled
    test    rax, rax
    jz      L_default_key
    
    ; Invalidate for rendering
    xor     rdx, rdx
    xor     r8, r8
    call    InvalidateRect
    
    mov     rax, 0
    jmp     L_done
    
L_default_key:
    ; Not handled - pass to DefWindowProc
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r12
    mov     r9, r13
    call    DefWindowProcA
    jmp     L_done
    
L_wm_keyup:
    ; Key up - currently not used, pass through
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r12
    mov     r9, r13
    call    DefWindowProcA
    jmp     L_done
    
L_wm_setfocus:
    ; Window gained focus
    mov     byte ptr [g_hasFocus], 1
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r12
    mov     r9, r13
    call    DefWindowProcA
    jmp     L_done
    
L_wm_killfocus:
    ; Window lost focus
    mov     byte ptr [g_hasFocus], 0
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r12
    mov     r9, r13
    call    DefWindowProcA
    jmp     L_done
    
L_wm_paint:
    ; Paint - render editor content
    ; Throttle rendering to ~60 FPS
    call    GetTickCount64
    mov     r14, rax
    
    mov     rax, [g_lastRenderTime]
    sub     r14, rax
    cmp     r14, RENDER_THROTTLE_MS
    jb      L_skip_render
    
    ; Update last render time
    mov     [g_lastRenderTime], r14
    
    ; Call editor render
    mov     rcx, rbx            ; hWnd
    call    Editor_Render
    
L_skip_render:
    ; Default paint handling
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r12
    mov     r9, r13
    call    DefWindowProcA
    jmp     L_done
    
L_wm_size:
    ; Window resized - notify editor
    mov     rcx, rbx
    mov     edx, esi
    mov     r8, r12
    mov     r9, r13
    call    DefWindowProcA
    jmp     L_done
    
L_wm_destroy:
    ; Window destroyed - cleanup
    call    PostQuitMessage
    xor     rax, rax
    jmp     L_done
    
L_done:
    add     rsp, 28h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

WndProcInputBridge_WndProc ENDP

; ============================================================================
; WndProcInputBridge_ProcessIdle
; ============================================================================
; Called from application idle loop to process pending input events.
; This is the consumer side of the input queue.
;
; Parameters: None
; Returns: RAX = number of events processed
; ============================================================================

ALIGN 16
WndProcInputBridge_ProcessIdle PROC
    
    ; Process all pending input events
    call    Input_ProcessEvents
    
    ; Return count (already in RAX)
    ret

WndProcInputBridge_ProcessIdle ENDP

; ============================================================================
; WndProcInputBridge_GetEditorBuffer
; ============================================================================
; Returns pointer to the editor text buffer for direct access.
; Use this for reading/writing buffer content directly.
;
; Parameters: None
; Returns: RAX = pointer to TEXT_BUFFER structure
; ============================================================================

ALIGN 16
WndProcInputBridge_GetEditorBuffer PROC
    
    call    Input_GetBufferState
    ret

WndProcInputBridge_GetEditorBuffer ENDP

; ============================================================================
; WndProcInputBridge_SubclassWindow
; ============================================================================
; Subclasses an existing window to intercept input messages.
; Stores original WndProc and replaces with input bridge.
;
; Parameters:
;   RCX = hWnd (window to subclass)
; Returns: RAX = 1 on success, 0 on failure
; ============================================================================

ALIGN 16
WndProcInputBridge_SubclassWindow PROC
    
    push    rbx
    sub     rsp, 28h
    
    mov     rbx, rcx            ; Save hWnd
    
    ; Initialize the bridge
    mov     rcx, rbx
    call    WndProcInputBridge_Initialize
    test    rax, rax
    jz      L_fail
    
    ; Store original WndProc
    ; Note: SetWindowLongPtr with GWLP_WNDPROC would go here
    ; For now, we just store the handle
    mov     [g_hEditorWnd], rbx
    
    mov     rax, 1
    jmp     L_done
    
L_fail:
    xor     rax, rax
    
L_done:
    add     rsp, 28h
    pop     rbx
    ret

WndProcInputBridge_SubclassWindow ENDP

; ============================================================================
; Exported symbols
; ============================================================================

PUBLIC WndProcInputBridge_Initialize
PUBLIC WndProcInputBridge_WndProc
PUBLIC WndProcInputBridge_ProcessIdle
PUBLIC WndProcInputBridge_GetEditorBuffer
PUBLIC WndProcInputBridge_SubclassWindow

END
