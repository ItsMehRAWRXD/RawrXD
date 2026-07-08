; ==============================================================================
; RawrXD Engine — Fixed REPL with Line-Based Input
; ==============================================================================

; External Win32 API declarations
EXTERN GetStdHandle:PROC
EXTERN ReadConsoleA:PROC          ; LINE-BASED input (fixed!)
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

.DATA
    ALIGN 8
    g_HistoryIndex      QWORD 0
    g_HistoryCount      QWORD 0
    g_MaxHistoryCount   QWORD 32
    
    ; 32-slot ring buffer (256 bytes each)
    g_HistoryRingBuffer BYTE  8192 dup(0) 
    g_CurrentInputLine  BYTE  256 dup(0)
    
    ; Console handle cache
    g_hConsoleInput     QWORD 0
    g_hConsoleOutput    QWORD 0

.CODE

;-------------------------------------------------------------------------------
; RawrXD_InitConsoleHandles
;-------------------------------------------------------------------------------
RawrXD_InitConsoleHandles PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    .endprolog
    
    mov rcx, -10        ; STD_INPUT_HANDLE
    call GetStdHandle
    mov g_hConsoleInput, rax
    
    mov rcx, -11        ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov g_hConsoleOutput, rax
    
    add rsp, 32
    pop rbp
    ret
RawrXD_InitConsoleHandles ENDP

;-------------------------------------------------------------------------------
; RawrXD_ReadLine
; FIXED: Uses ReadConsoleA for LINE-BASED input
; RCX = Buffer pointer
; RDX = Buffer capacity
; Returns RAX = Length of line read (0 if empty, -1 if EOF/pipe ended)
;-------------------------------------------------------------------------------
RawrXD_ReadLine PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 56
    .endprolog

    mov rsi, rcx        ; rsi = buffer
    mov rdi, rdx        ; rdi = capacity
    mov r12, 0          ; r12 = total bytes read
    
    ; Clear buffer
    mov byte ptr [rsi], 0
    
@@read_loop:
    ; Read one character at a time to handle both console and pipe input
    mov rcx, g_hConsoleInput
    mov rdx, rsi
    add rdx, r12        ; Position in buffer
    mov r8d, 1          ; Read 1 byte
    lea r9, [rsp+32]    ; Bytes read
    mov qword ptr [rsp+40], 0
    call ReadConsoleA
    
    test rax, rax
    jz @@check_error
    
    mov ebx, dword ptr [rsp+32]
    test ebx, ebx
    jz @@eof            ; EOF - no more data
    
    ; Check for newline
    mov al, byte ptr [rsi + r12]
    cmp al, 0Ah         ; LF
    je @@found_newline
    cmp al, 0Dh         ; CR
    je @@found_newline
    
    ; Regular character
    inc r12
    cmp r12, rdi
    jae @@buffer_full
    jmp @@read_loop
    
@@found_newline:
    ; Replace newline with null terminator
    mov byte ptr [rsi + r12], 0
    mov rax, r12
    jmp @@done
    
@@buffer_full:
    mov byte ptr [rsi + r12], 0
    mov rax, r12
    jmp @@done
    
@@eof:
    ; End of file/pipe
    test r12, r12
    jz @@empty_eof
    mov byte ptr [rsi + r12], 0
    mov rax, r12
    jmp @@done
    
@@empty_eof:
    mov rax, -1         ; Signal EOF
    jmp @@done
    
@@check_error:
    ; Check if it's a broken pipe (EOF)
    mov rax, -1
    
@@done:
    add rsp, 56
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_ReadLine ENDP

;-------------------------------------------------------------------------------
; RawrXD_REPL_MainLoop
; FIXED: Line-based REPL that doesn't echo prompts between characters
;-------------------------------------------------------------------------------
RawrXD_REPL_MainLoop PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    .endprolog
    
    ; Initialize console handles
    call RawrXD_InitConsoleHandles
    
    ; Print banner
    mov rcx, g_hConsoleOutput
    lea rdx, banner_text
    mov r8d, banner_len
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    
@@repl_loop:
    ; Print prompt ONCE per line
    mov rcx, g_hConsoleOutput
    lea rdx, prompt_text
    mov r8d, prompt_len
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    
    ; Read entire line
    lea rcx, g_CurrentInputLine
    mov rdx, 256
    call RawrXD_ReadLine
    
    ; Check for EOF (-1) or empty input (0)
    cmp rax, -1
    je @@repl_exit        ; EOF - exit gracefully
    test rax, rax
    jz @@repl_loop        ; Empty line - just show prompt again
    
    ; Check for exit command
    lea rcx, g_CurrentInputLine
    lea rdx, exit_cmd
    call RawrXD_StrCompare
    test rax, rax
    jz @@repl_exit
    
    ; Echo back what was typed
    mov rcx, g_hConsoleOutput
    lea rdx, g_CurrentInputLine
    mov r8d, eax        ; Length from ReadLine
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    
    ; Print newline
    mov rcx, g_hConsoleOutput
    lea rdx, newline
    mov r8d, 2
    xor r9d, r9d
    push 0
    call WriteConsoleA
    add rsp, 8
    
    jmp @@repl_loop
    
@@repl_exit:
    add rsp, 32
    pop rbp
    ret
RawrXD_REPL_MainLoop ENDP

;-------------------------------------------------------------------------------
; RawrXD_StrCompare
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
    
    newline     BYTE 0Dh, 0Ah, 0
    
    exit_cmd    BYTE "exit", 0

END
