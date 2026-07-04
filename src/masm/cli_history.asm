; ==============================================================================
; RawrXD Engine — Low-Level Console Interactive History Engine
; ==============================================================================

; External Win32 API declarations
EXTERN GetStdHandle:PROC
EXTERN ReadConsoleInputW:PROC
EXTERN WriteConsoleA:PROC
EXTERN WriteConsoleW:PROC
EXTERN SetConsoleCursorPosition:PROC
EXTERN GetConsoleScreenBufferInfo:PROC
EXTERN ExitProcess:PROC

.DATA
    ALIGN 8
    g_HistoryIndex      QWORD 0       ; Current pointer location in historical tracking
    g_HistoryCount      QWORD 0       ; Total valid history strings committed
    g_MaxHistoryCount   QWORD 32      ; Bound matrix limit
    
    ; Setup a 32-slot ring allocation boundary (Each command gets 256 bytes)
    g_HistoryRingBuffer BYTE  8192 dup(0) 
    g_CurrentInputLine  BYTE  256 dup(0)
    
    ; Console handle cache
    g_hConsoleInput     QWORD 0
    g_hConsoleOutput    QWORD 0
    
    ; UTF-8 BOM marker for reference
    UTF8_BOM            BYTE  0EFh, 0BBh, 0BFh

.CODE

;-------------------------------------------------------------------------------
; RawrXD_InitConsoleHandles
; Initializes cached console handles for REPL operations
;-------------------------------------------------------------------------------
RawrXD_InitConsoleHandles PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 32
    .endprolog
    
    ; Get stdin handle
    mov rcx, -10        ; STD_INPUT_HANDLE
    call GetStdHandle
    mov g_hConsoleInput, rax
    
    ; Get stdout handle
    mov rcx, -11        ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov g_hConsoleOutput, rax
    
    ; Get stderr handle for diagnostics
    mov rcx, -12        ; STD_ERROR_HANDLE
    call GetStdHandle
    
    add rsp, 32
    pop rbx
    pop rbp
    ret
RawrXD_InitConsoleHandles ENDP

;-------------------------------------------------------------------------------
; RawrXD_ReadConsoleInputEvent
; RCX = HANDLE hConsoleInput (optional, 0 = use cached)
; RDX = Pointer to standard input text array buffer
; R8  = Buffer capacity
; Returns RAX = Length of finalized string on VK_RETURN, or 0 on pass
;-------------------------------------------------------------------------------
RawrXD_ReadConsoleInputEvent PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ; 32-byte shadow space + 16-byte structure alignment + INPUT_RECORD space
    sub rsp, 80
    .endprolog

    ; Use cached handle if rcx is 0
    test rcx, rcx
    jnz @@handle_provided
    mov rcx, g_hConsoleInput
@@handle_provided:
    mov rbx, rcx        ; rbx = Native Console Input Handle
    mov rsi, rdx        ; rsi = Active Output Buffer Working String Pointer
    mov r15, r8         ; r15 = Buffer capacity
    
    ; Initialize buffer to empty
    mov byte ptr [rsi], 0
    xor r14, r14        ; r14 = Current buffer length

@@read_loop:
    ; Reserve local stack real-estate for ReadConsoleInputW parameters
    ; [rsp + 32] = INPUT_RECORD structure instance allocation
    ; [rsp + 52] = DWORD bytesRead container
    
    lea rdx, [rsp + 32] ; lpBuffer pointer mapping
    mov r8d, 1          ; Read exactly one record element block
    lea r9, [rsp + 52]  ; lpNumberOfEventsRead pointer
    
    call ReadConsoleInputW
    test rax, rax
    jz @@failed_execution

    ; Extract structural event components
    mov ax, word ptr [rsp + 32] ; INPUT_RECORD.EventType
    cmp ax, 0001h               ; KEY_EVENT definition matching
    jne @@read_loop             ; Skip non-key events

    ; Introspect internal KEY_EVENT structure mechanics
    ; Offset 4: bKeyDown (BOOL)
    mov edx, dword ptr [rsp + 36]
    test edx, edx
    jz @@read_loop              ; Ignore key release execution events

    ; Offset 8: wRepeatCount (WORD)
    ; Offset 10: wVirtualKeyCode (WORD)
    movzx r12d, word ptr [rsp + 42] ; Virtual Key Code
    
    ; Offset 12: wVirtualScanCode (WORD)
    ; Offset 14: UnicodeChar (WCHAR)
    movzx r13d, word ptr [rsp + 46] ; Unicode character
    
    ; Offset 16: dwControlKeyState (DWORD)

    ; Check for special keys first
    cmp r12d, 0Dh               ; VK_RETURN
    je @@handle_return
    cmp r12d, 26h               ; VK_UP
    je @@handle_history_up
    cmp r12d, 28h               ; VK_DOWN
    je @@handle_history_down
    cmp r12d, 08h               ; VK_BACK (Backspace)
    je @@handle_backspace
    cmp r12d, 1Bh               ; VK_ESCAPE
    je @@handle_escape
    
    ; Regular character input
    cmp r13d, 20h               ; Filter control characters (< space)
    jb @@read_loop
    
    ; Add character to buffer if space available
    cmp r14, r15
    jae @@read_loop             ; Buffer full, ignore
    
    ; Convert WCHAR to UTF-8 (simplified: assume ASCII for now)
    cmp r13d, 80h
    jae @@unicode_input         ; Multi-byte UTF-8 needed
    
    ; Single byte ASCII
    mov byte ptr [rsi + r14], r13b
    inc r14
    mov byte ptr [rsi + r14], 0
    
    ; Echo character to console
    mov rcx, g_hConsoleOutput
    lea rdx, [rsi + r14 - 1]
    mov r8d, 1
    xor r9d, r9d
    push 0
    sub rsp, 32
    call WriteConsoleA
    add rsp, 40
    
    jmp @@read_loop

@@unicode_input:
    ; TODO: Full UTF-8 encoding for characters >= 0x80
    jmp @@read_loop

@@handle_backspace:
    ; Remove last character if buffer not empty
    test r14, r14
    jz @@read_loop
    
    dec r14
    mov byte ptr [rsi + r14], 0
    
    ; Send backspace sequence to console
    mov rcx, g_hConsoleOutput
    lea rdx, [rsp + 60]         ; Temp space for backspace sequence
    mov byte ptr [rdx], 08h     ; Backspace
    mov byte ptr [rdx + 1], 20h ; Space (erase)
    mov byte ptr [rdx + 2], 08h ; Backspace again
    mov r8d, 3
    xor r9d, r9d
    push 0
    sub rsp, 32
    call WriteConsoleA
    add rsp, 40
    
    jmp @@read_loop

@@handle_escape:
    ; Clear current line
    mov rcx, g_hConsoleOutput
    lea rdx, [rsp + 60]
    mov r8d, 0
@@clear_esc_loop:
    cmp r8d, r14d
    jae @@clear_esc_done
    mov byte ptr [rdx + r8], 08h  ; Backspace
    inc r8d
    jmp @@clear_esc_loop
@@clear_esc_done:
    mov byte ptr [rdx + r8], 0
    
    test r8d, r8d
    jz @@clear_esc_skip_write
    
    xor r9d, r9d
    push 0
    sub rsp, 32
    call WriteConsoleA
    add rsp, 40
    
@@clear_esc_skip_write:
    xor r14, r14
    mov byte ptr [rsi], 0
    jmp @@read_loop

@@handle_history_up:
    ; Introspect if historical commands exist
    mov rax, g_HistoryCount
    test rax, rax
    jz @@read_loop

    ; Safely decrement tracking index with wrapping boundaries
    mov rax, g_HistoryIndex
    test rax, rax
    jz @@lock_upper_bound
    dec rax
    mov g_HistoryIndex, rax
@@lock_upper_bound:
    call RawrXD_SwapConsoleLineDisplay
    jmp @@read_loop

@@handle_history_down:
    mov rax, g_HistoryIndex
    inc rax
    cmp rax, g_HistoryCount
    jae @@clear_active_line
    
    mov g_HistoryIndex, rax
    call RawrXD_SwapConsoleLineDisplay
    jmp @@read_loop

@@clear_active_line:
    mov g_HistoryIndex, rax ; Match index to head pointer bounds
    ; Blank out current line displays natively
    jmp @@read_loop

@@handle_return:
    ; Finalize text line mapping, execute ring update, and return string density
    test r14, r14
    jz @@empty_return
    
    ; Add to history ring buffer
    call RawrXD_AddToHistory
    
@@empty_return:
    ; Output newline
    mov rcx, g_hConsoleOutput
    lea rdx, [rsp + 60]
    mov byte ptr [rdx], 0Dh     ; CR
    mov byte ptr [rdx + 1], 0Ah ; LF
    mov r8d, 2
    xor r9d, r9d
    push 0
    sub rsp, 32
    call WriteConsoleA
    add rsp, 40
    
    mov rax, r14                ; Return length in RAX
    jmp @@exit_sequence

@@failed_execution:
    xor rax, rax

@@exit_sequence:
    add rsp, 80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_ReadConsoleInputEvent ENDP

;-------------------------------------------------------------------------------
; RawrXD_SwapConsoleLineDisplay
; Swaps current console line with history entry at g_HistoryIndex
;-------------------------------------------------------------------------------
RawrXD_SwapConsoleLineDisplay PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 32
    .endprolog
    
    ; Calculate history entry pointer
    mov rax, g_HistoryIndex
    mov rcx, 256                ; Entry size
    mul rcx
    lea rsi, g_HistoryRingBuffer
    add rsi, rax                ; rsi = source history entry
    
    ; Get current input line
    lea rdi, g_CurrentInputLine
    
    ; Clear current console line (send backspaces)
    mov rcx, g_hConsoleOutput
    mov r12, rdi
    xor r8d, r8d
@@count_current:
    cmp byte ptr [r12 + r8], 0
    je @@count_done
    inc r8d
    jmp @@count_current
@@count_done:
    
    ; Send backspaces
    test r8d, r8d
    jz @@no_backspace_needed
    mov r12d, r8d
@@backspace_loop:
    mov byte ptr [rsp + 48], 08h
    lea rdx, [rsp + 48]
    mov r8d, 1
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    dec r12d
    jnz @@backspace_loop
@@no_backspace_needed:
    
    ; Copy history to current line
    mov rcx, 256
    rep movsb
    
    ; Write new line to console
    mov rcx, g_hConsoleOutput
    lea rdx, g_CurrentInputLine
    mov r8d, 256
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    
    add rsp, 32
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_SwapConsoleLineDisplay ENDP

;-------------------------------------------------------------------------------
; RawrXD_AddToHistory
; Adds current input line to history ring buffer
;-------------------------------------------------------------------------------
RawrXD_AddToHistory PROC FRAME
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    sub rsp, 32
    .endprolog
    
    ; Calculate insertion point (at g_HistoryCount % g_MaxHistoryCount)
    mov rax, g_HistoryCount
    xor rdx, rdx
    mov rcx, g_MaxHistoryCount
    div rcx
    mov rax, rdx                ; rax = insertion index
    
    ; Calculate destination pointer
    mov rcx, 256
    mul rcx
    lea rdi, g_HistoryRingBuffer
    add rdi, rax
    
    ; Copy current line to history
    lea rsi, g_CurrentInputLine
    mov rcx, 256
    rep movsb
    
    ; Increment history count (capped at max)
    mov rax, g_HistoryCount
    inc rax
    cmp rax, g_MaxHistoryCount
    cmova rax, g_MaxHistoryCount
    mov g_HistoryCount, rax
    
    ; Reset history index to end
    mov g_HistoryIndex, rax
    
    add rsp, 32
    pop rdi
    pop rsi
    pop rbp
    ret
RawrXD_AddToHistory ENDP

;-------------------------------------------------------------------------------
; RawrXD_REPL_MainLoop
; Main REPL entry point - handles interactive console mode
;-------------------------------------------------------------------------------
RawrXD_REPL_MainLoop PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    .endprolog
    
    ; Initialize console handles
    call RawrXD_InitConsoleHandles
    
    ; Print REPL banner to stderr (diagnostic)
    mov rcx, g_hConsoleOutput
    lea rdx, banner_text
    mov r8d, banner_len
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    
@@repl_loop:
    ; Print prompt
    mov rcx, g_hConsoleOutput
    lea rdx, prompt_text
    mov r8d, prompt_len
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    
    ; Read input
    xor rcx, rcx                ; Use cached handle
    lea rdx, g_CurrentInputLine
    mov r8d, 256                ; Buffer capacity
    call RawrXD_ReadConsoleInputEvent
    
    ; Check for exit command
    lea rcx, g_CurrentInputLine
    lea rdx, exit_cmd
    call RawrXD_StrCompare
    test rax, rax
    jz @@repl_exit
    
    ; TODO: Process command through transformer
    
    jmp @@repl_loop
    
@@repl_exit:
    add rsp, 32
    pop rbp
    ret
RawrXD_REPL_MainLoop ENDP

;-------------------------------------------------------------------------------
; RawrXD_StrCompare
; Simple string comparison (case-sensitive)
; RCX = string 1, RDX = string 2
; Returns RAX = 0 if equal, non-zero otherwise
;-------------------------------------------------------------------------------
RawrXD_StrCompare PROC FRAME
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    .endprolog
    
    mov rsi, rcx
    mov rdi, rdx
    
@@compare_loop:
    mov al, byte ptr [rsi]
    mov ah, byte ptr [rdi]
    cmp al, ah
    jne @@not_equal
    test al, al
    jz @@equal
    inc rsi
    inc rdi
    jmp @@compare_loop
    
@@not_equal:
    mov rax, 1
    jmp @@done
    
@@equal:
    xor rax, rax
    
@@done:
    pop rdi
    pop rsi
    pop rbp
    ret
RawrXD_StrCompare ENDP

.DATA
    banner_text BYTE "RawrXD v1.0.0-Stable REPL", 0Dh, 0Ah
                BYTE "Type 'exit' to quit.", 0Dh, 0Ah, 0Dh, 0Ah, 0
    banner_len  EQU $ - banner_text
    
    prompt_text BYTE "rawrxd> ", 0
    prompt_len  EQU $ - prompt_text
    
    exit_cmd    BYTE "exit", 0

END
