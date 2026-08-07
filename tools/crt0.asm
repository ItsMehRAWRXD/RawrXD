; ============================================================================
; crt0.asm - Custom C Runtime Startup for RawrXD Sovereign Build
; Zero MSVC CRT dependency
; Replaces: msvcrt.dll, vcruntime.dll, ucrt.dll
; ============================================================================

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; External imports from kernel32
EXTERN GetModuleHandleA:PROC
EXTERN GetCommandLineA:PROC
EXTERN ExitProcess:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN HeapCreate:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC

; Public exports
PUBLIC _start
PUBLIC mainCRTStartup
PUBLIC WinMainCRTStartup
PUBLIC __chkstk
PUBLIC memset
PUBLIC memcpy
PUBLIC strlen

; Constants
STD_OUTPUT_HANDLE EQU -11
HEAP_NO_SERIALIZE EQU 1

; ============================================================================
; .DATA section - initialized data
; ============================================================================
.DATA

; Command line storage
cmdline_buffer DB 32768 DUP(0)  ; 32KB command line buffer
argc DD 0
argv DQ 64 DUP(0)               ; Up to 64 arguments

; Heap handle
hHeap DQ 0

; Standard handles
hStdOut DQ 0
hStdIn DQ 0
hStdErr DQ 0

; Error message
sz_crt_init db "[CRT] Sovereign runtime initialized", 13, 10, 0
sz_crt_init_len EQU $ - sz_crt_init

; ============================================================================
; .CODE section
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; _start - Entry point (replaces CRT startup)
; ----------------------------------------------------------------------------
_start PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 48
    
    ; Initialize heap
    xor ecx, ecx                    ; flOptions = 0
    mov rdx, 100000h                ; dwInitialSize = 1MB
    mov r8, 0                       ; dwMaximumSize = 0 (growable)
    call HeapCreate
    mov [hHeap], rax
    
    ; Get standard handles
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [hStdOut], rax
    
    mov ecx, -10                    ; STD_INPUT_HANDLE
    call GetStdHandle
    mov [hStdIn], rax
    
    mov ecx, -12                    ; STD_ERROR_HANDLE
    call GetStdHandle
    mov [hStdErr], rax
    
    ; Parse command line
    call parse_command_line
    
    ; Call C++ main
    mov ecx, [argc]
    lea rdx, [argv]
    call main
    
    ; Exit with return code
    mov ecx, eax
    call ExitProcess
    
_start ENDP

; Alias entry points
mainCRTStartup PROC
    jmp _start
mainCRTStartup ENDP

WinMainCRTStartup PROC
    jmp _start
WinMainCRTStartup ENDP

; ----------------------------------------------------------------------------
; parse_command_line - Parse GetCommandLineA output into argc/argv
; ----------------------------------------------------------------------------
parse_command_line PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    ; Get command line
    call GetCommandLineA
    mov rsi, rax
    
    ; Copy to buffer
    lea rdi, [cmdline_buffer]
    mov rcx, 32768
    rep movsb
    
    ; Reset to start
    lea rsi, [cmdline_buffer]
    lea rdi, [argv]
    xor r12, r12                    ; argc counter
    xor r13, r13                    ; in_quotes flag
    
parse_loop:
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz parse_done
    
    ; Skip leading whitespace
    cmp al, ' '
    je skip_whitespace
    cmp al, 9                       ; Tab
    je skip_whitespace
    
    ; Check for quote
    cmp al, '"'
    je handle_quote
    
    ; Start of argument
    mov [rdi + r12*8], rsi
    inc r12
    
    ; Find end of argument
arg_loop:
    movzx eax, BYTE PTR [rsi]
    test al, al
    jz parse_done
    cmp al, ' '
    je arg_end
    cmp al, 9
    je arg_end
    cmp al, '"'
    je arg_end
    inc rsi
    jmp arg_loop
    
arg_end:
    mov BYTE PTR [rsi], 0           ; Null terminate
    inc rsi
    jmp parse_loop
    
skip_whitespace:
    inc rsi
    jmp parse_loop
    
handle_quote:
    xor r13, 1                      ; Toggle quote state
    inc rsi
    jmp parse_loop
    
parse_done:
    mov [argc], r12d
    
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
    
parse_command_line ENDP

; ----------------------------------------------------------------------------
; main - Placeholder, will be overridden by actual main
; ----------------------------------------------------------------------------
main PROC
    ; Default main - should be overridden
    xor eax, eax
    ret
main ENDP

; ----------------------------------------------------------------------------
; __chkstk - Stack probe for large allocations
; ----------------------------------------------------------------------------
__chkstk PROC
    ; Minimal implementation - just return
    ret
__chkstk ENDP

; ----------------------------------------------------------------------------
; memset - Fill memory with byte
; RCX = dest, RDX = value, R8 = count
; ----------------------------------------------------------------------------
memset PROC
    mov rax, rdx                    ; Value
    mov r9, rcx                     ; Save dest
    mov rcx, r8                     ; Count
    rep stosb
    mov rax, r9                     ; Return dest
    ret
memset ENDP

; ----------------------------------------------------------------------------
; memcpy - Copy memory
; RCX = dest, RDX = src, R8 = count
; ----------------------------------------------------------------------------
memcpy PROC
    mov r9, rcx                     ; Save dest
    mov rcx, r8                     ; Count
    mov rsi, rdx                    ; Src
    mov rdi, r9                     ; Dest
    rep movsb
    mov rax, r9                     ; Return dest
    ret
memcpy ENDP

; ----------------------------------------------------------------------------
; strlen - String length
; RCX = string
; ----------------------------------------------------------------------------
strlen PROC
    mov rax, rcx                    ; Save start
strlen_loop:
    cmp BYTE PTR [rcx], 0
    je strlen_done
    inc rcx
    jmp strlen_loop
strlen_done:
    sub rcx, rax                    ; Length
    mov rax, rcx
    ret
strlen ENDP

; ----------------------------------------------------------------------------
; malloc - Heap allocate
; RCX = size
; ----------------------------------------------------------------------------
malloc PROC
    mov r8, rcx                     ; dwBytes
    mov rcx, [hHeap]                ; hHeap
    xor edx, edx                    ; dwFlags
    call HeapAlloc
    ret
malloc ENDP

; ----------------------------------------------------------------------------
; free - Heap free
; RCX = pointer
; ----------------------------------------------------------------------------
free PROC
    test rcx, rcx
    jz free_done
    mov rdx, rcx                    ; lpMem
    mov rcx, [hHeap]                ; hHeap
    xor r8d, r8d                    ; dwFlags
    call HeapFree
free_done:
    ret
free ENDP

; ----------------------------------------------------------------------------
; __C_specific_handler - SEH handler (minimal)
; ----------------------------------------------------------------------------
__C_specific_handler PROC
    xor eax, eax
    ret
__C_specific_handler ENDP

END
