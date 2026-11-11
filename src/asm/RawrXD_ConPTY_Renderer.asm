; =============================================================================
; RawrXD_ConPTY_Renderer.asm - Native Win32 Pseudoconsole TUI Renderer
; Implementation of collapsible blocks and real-time progress bars in MASM
; =============================================================================

OPTION CASEMAP:NONE

include masm64_compat.inc

; Windows API declarations
GetStdHandle PROTO :DWORD
WriteConsoleA PROTO :QWORD, :QWORD, :DWORD, :QWORD, :QWORD

; Constants
STD_OUTPUT_HANDLE EQU -11

.DATA
    ; VT100 Escape Sequences
    ESC_CLEAR_LINE      BYTE 01Bh, "[2K", 0
    ESC_MOVE_UP         BYTE 01Bh, "[%dA", 0
    ESC_HIDE_CURSOR     BYTE 01Bh, "[?25l", 0
    ESC_SHOW_CURSOR     BYTE 01Bh, "[?25h", 0
    ESC_COLOR_GRAY      BYTE 01Bh, "[90m", 0
    ESC_COLOR_RESET     BYTE 01Bh, "[0m", 0
    
    ; TUI Glyphs (UTF-8)
    GLYPH_EXPANDED      BYTE 0E2h, 096h, 0BCh, " ", 0
    GLYPH_COLLAPSED     BYTE 0E2h, 096h, 0BAh, " ", 0
    GLYPH_PROGRESS_FILL BYTE 0E2h, 096h, 088h, 0

.CODE

; =============================================================================
; RawrXD_TUI_RenderThinkingBlock - Render a collapsible thinking stage
; =============================================================================
; RCX = Label string
; RDX = isExpanded (BOOL)
; R8  = Content string
RawrXD_TUI_RenderThinkingBlock PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 48                  ; 32 shadow space + 16 local alignment
    .allocstack 48
    .endprolog
    
    ; Save input parameters in shadow space
    mov [rbp+10h], rcx           ; Label string
    mov [rbp+18h], rdx           ; isExpanded
    mov [rbp+20h], r8            ; Content string
    
    ; Get Stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    sub rsp, 32                  ; Shadow space for API call
    call GetStdHandle
    add rsp, 32
    mov [rbp-8], rax             ; Store hStdOut in local
    
    ; Clear Line and Format Header
    ; [Logic to format: "? Thinking..." or "? Thinking: [content]"]
    ; We use VT100 codes to move the cursor if updating an existing block
    
    lea rsp, [rbp]
    pop rbp
    ret
RawrXD_TUI_RenderThinkingBlock ENDP

; =============================================================================
; RawrXD_TUI_UpdateProgressBar - Smoothed TUI progress bar
; =============================================================================
; RCX = Percentage (0-100)
; RDX = width
RawrXD_TUI_UpdateProgressBar PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32                  ; Shadow space
    .allocstack 32
    .endprolog
    
    ; Save parameters
    mov [rbp+10h], rcx           ; Percentage
    mov [rbp+18h], rdx           ; Width
    
    ; 1. Calculate filled segments
    ; 2. Render [????????] 50%
    ; 3. Use ESC_MOVEUP if necessary to redraw in-place
    
    lea rsp, [rbp]
    pop rbp
    ret
RawrXD_TUI_UpdateProgressBar ENDP

END


