; RawrXD Minimal Runtime Library
; Provides basic functions for self-hosted C compiler
; Assemble: ml64 /c /Fo rawrxd_runtime.obj rawrxd_runtime.asm

; External Windows API imports
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN ExitProcess:PROC
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC

; Constants
STD_OUTPUT_HANDLE equ -11
HEAP_ZERO_MEMORY equ 00000008h

; Public exports for C compiler
PUBLIC _print_string
PUBLIC _print_int
PUBLIC _print_newline
PUBLIC _allocate
PUBLIC _free
PUBLIC _exit

; Data section
.DATA

; Buffer for integer to string conversion
int_buffer DB 32 DUP(0)

; Code section
.CODE

;==============================================================================
; _print_string - Print null-terminated string to stdout
; RCX = pointer to string
;==============================================================================
_print_string PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 48
    
    mov rsi, rcx                    ; RSI = string pointer
    
    ; Calculate string length
    mov rdi, rsi
    xor rcx, rcx
    dec rcx
    xor al, al
    repne scasb
    not rcx
    dec rcx                         ; RCX = length
    mov rbx, rcx                    ; Save length in RBX
    
    ; Get stdout handle
    mov rcx, 0FFFFFFF5h             ; STD_OUTPUT_HANDLE = -11
    call GetStdHandle
    
    ; WriteFile(stdout, buffer, length, &written, NULL)
    mov r8, rbx                     ; Length
    mov rcx, rax                    ; Handle
    mov rdx, rsi                    ; Buffer
    lea r9, [rsp+32]                ; &written
    mov QWORD PTR [rsp+32], 0       ; Overlapped = NULL
    sub rsp, 32
    call WriteFile
    add rsp, 32
    
    add rsp, 48
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
_print_string ENDP

;==============================================================================
; _print_int - Print integer to stdout
; RCX = integer value
;==============================================================================
_print_int PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    sub rsp, 32
    
    mov rax, rcx                    ; RAX = integer
    lea rsi, int_buffer + 31      ; RSI = end of buffer
    mov BYTE PTR [rsi], 0           ; Null terminate
    
    ; Handle zero
    test rax, rax
    jnz convert_loop
    mov BYTE PTR [rsi-1], '0'
    dec rsi
    jmp print_it
    
convert_loop:
    xor rdx, rdx
    mov rbx, 10
    div rbx                         ; RAX = quotient, RDX = remainder
    add dl, '0'
    dec rsi
    mov [rsi], dl
    test rax, rax
    jnz convert_loop
    
print_it:
    mov rcx, rsi
    call _print_string
    
    add rsp, 32
    pop rsi
    pop rbx
    pop rbp
    ret
_print_int ENDP

;==============================================================================
; _print_newline - Print newline
;==============================================================================
_print_newline PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Print CRLF
    lea rcx, newline_str
    call _print_string
    
    add rsp, 32
    pop rbp
    ret
_print_newline ENDP

newline_str DB 13, 10, 0

;==============================================================================
; _allocate - Allocate memory from heap
; RCX = size in bytes
; Returns: RAX = pointer to allocated memory
;==============================================================================
_allocate PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Get process heap
    call GetProcessHeap
    
    ; HeapAlloc(heap, HEAP_ZERO_MEMORY, size)
    mov r8, rcx                     ; Size
    mov rdx, HEAP_ZERO_MEMORY       ; Flags
    mov rcx, rax                    ; Heap handle
    sub rsp, 32
    call HeapAlloc
    add rsp, 32
    
    add rsp, 32
    pop rbp
    ret
_allocate ENDP

;==============================================================================
; _free - Free memory
; RCX = pointer to memory
;==============================================================================
_free PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Get process heap
    call GetProcessHeap
    
    ; HeapFree(heap, 0, ptr)
    mov r8, rcx                     ; Pointer
    xor rdx, rdx                    ; Flags = 0
    mov rcx, rax                    ; Heap handle
    sub rsp, 32
    call HeapFree
    add rsp, 32
    
    add rsp, 32
    pop rbp
    ret
_free ENDP

;==============================================================================
; _exit - Exit process
; RCX = exit code
;==============================================================================
_exit PROC
    call ExitProcess
_exit ENDP

END
