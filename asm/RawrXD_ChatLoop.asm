; ============================================================================
; RawrXD_ChatLoop.asm
; Pure x64 MASM interactive chat loop — stdin/stdout, no CRT
; Zero dependencies, links only against kernel32.lib
; ============================================================================

option casemap:none

; ============================================================================
; Windows API imports
; ============================================================================

includelib kernel32.lib

GetStdHandle              proto :dword
ReadFile                  proto :qword, :qword, :dword, :qword, :qword
WriteFile                 proto :qword, :qword, :dword, :qword, :qword
WriteConsoleA             proto :qword, :qword, :dword, :qword, :qword
ExitProcess               proto :dword
GetTickCount64            proto
Sleep                     proto :dword
GetLastError              proto

; ============================================================================
; Constants
; ============================================================================

STD_INPUT_HANDLE          equ -10
STD_OUTPUT_HANDLE         equ -11
MAX_INPUT_LEN             equ 2048
MAX_OUTPUT_LEN            equ 32768
PROMPT_PREFIX_LEN         equ 5

; ============================================================================
; .data section
; ============================================================================

.data

banner db "=================================================================",13,10
       db "  Sovereign Engine - Interactive Chat Mode",13,10
       db "  Type your message and press Enter. Type 'exit' to quit.",13,10
       db "=================================================================",13,10,0

you_prompt    db 13,10,"You: ",0
ai_prompt     db 13,10,"AI: ",0
exit_cmd      db "exit",0
quit_cmd      db "quit",0
newline       db 13,10,0

; ============================================================================
; .bss section
; ============================================================================

.data?

input_buffer  db MAX_INPUT_LEN dup(?)
output_buffer db MAX_OUTPUT_LEN dup(?)
h_stdin       dq ?
h_stdout      dq ?

; ============================================================================
; .code section
; ============================================================================

.code

; ============================================================================
; ChatLoop_Run PROC
;   RCX = inference_callback (function pointer: token_id* -> count -> outbuf -> capacity -> written)
;   RDX = context_pointer (opaque, passed to callback)
;   Returns: never (calls ExitProcess), or RAX=0 on error
; ============================================================================

ChatLoop_Run PROC frame
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov r12, rcx                          ; inference_callback
    mov r13, rdx                          ; context_pointer

    ; Get stdin/stdout handles
    mov ecx, STD_INPUT_HANDLE
    call GetStdHandle
    mov h_stdin, rax
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov h_stdout, rax

    ; Print banner
    lea rcx, banner
    call ChatLoop_PrintString

main_loop:
    ; Print "You: "
    lea rcx, you_prompt
    call ChatLoop_PrintString

    ; Read input line
    call ChatLoop_ReadLine
    test rax, rax
    jz main_loop_done

    ; Check for exit/quit
    lea rcx, input_buffer
    lea rdx, exit_cmd
    mov r8, 4
    call ChatLoop_StrNCmp
    test rax, rax
    jz do_exit

    lea rcx, input_buffer
    lea rdx, quit_cmd
    mov r8, 4
    call ChatLoop_StrNCmp
    test rax, rax
    jz do_exit

    ; Print "AI: "
    lea rcx, ai_prompt
    call ChatLoop_PrintString

    ; Call inference callback
    ; Signature: callback(context, input_ptr, input_len, output_ptr, output_capacity)
    ; Returns: RAX = output bytes written
    mov rcx, r13
    lea rdx, input_buffer
    mov r8, rax                          ; input length from ReadLine
    lea r9, output_buffer
    mov qword ptr [rsp+32], MAX_OUTPUT_LEN
    sub rsp, 8
    call r12
    add rsp, 8

    ; Print response
    lea rcx, output_buffer
    mov edx, eax
    call ChatLoop_PrintBytes

    ; Print newline
    lea rcx, newline
    call ChatLoop_PrintString

    jmp main_loop

do_exit:
    lea rcx, newline
    call ChatLoop_PrintString

main_loop_done:
    xor ecx, ecx
    call ExitProcess

    ; Should never reach here
    xor rax, rax
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ChatLoop_Run ENDP

; ============================================================================
; ChatLoop_ReadLine PROC
;   Reads line from stdin into input_buffer
;   Returns: RAX = number of bytes read (excluding CR/LF), 0 if empty/error
; ============================================================================

ChatLoop_ReadLine PROC frame
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    lea rdi, input_buffer
    xor ebx, ebx                          ; bytes read

read_char:
    cmp ebx, MAX_INPUT_LEN - 1
    jae read_done

    mov rcx, h_stdin
    mov rdx, rdi
    mov r8d, 1
    lea r9, qword ptr [rsp+32]             ; bytes_read
    mov qword ptr [rsp+40], 0
    call ReadFile

    mov rax, qword ptr [rsp+32]
    test rax, rax
    jz read_done_eof

    mov al, byte ptr [rdi]

    ; Check for CR/LF
    cmp al, 13
    je read_done
    cmp al, 10
    je read_done

    inc rdi
    inc ebx
    jmp read_char

read_done_eof:
    mov byte ptr [rdi], 0
    mov rax, rbx
    jmp read_exit

read_done:
    mov byte ptr [rdi], 0
    mov rax, rbx
    jmp read_exit

read_exit:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
ChatLoop_ReadLine ENDP

; ============================================================================
; ChatLoop_PrintString PROC
;   RCX = null-terminated string
; ============================================================================

ChatLoop_PrintString PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rbx, rcx
    xor eax, eax
    mov rcx, -1

str_len_loop:
    cmp byte ptr [rbx + rax], 0
    je str_len_done
    inc rax
    jmp str_len_loop

str_len_done:
    mov rcx, h_stdout
    mov rdx, rbx
    mov r8d, eax
    lea r9, qword ptr [rsp+32]
    mov qword ptr [rsp+40], 0
    call WriteFile

    add rsp, 32
    pop rbx
    ret
ChatLoop_PrintString ENDP

; ============================================================================
; ChatLoop_PrintBytes PROC
;   RCX = buffer, RDX = length
; ============================================================================

ChatLoop_PrintBytes PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rbx, rcx
    mov rcx, h_stdout
    mov r8d, edx
    mov rdx, rbx
    lea r9, qword ptr [rsp+32]
    mov qword ptr [rsp+40], 0
    call WriteFile

    add rsp, 32
    pop rbx
    ret
ChatLoop_PrintBytes ENDP

; ============================================================================
; ChatLoop_StrNCmp PROC
;   RCX = str1, RDX = str2, R8 = n
;   Returns: RAX = 0 if equal, non-zero otherwise
; ============================================================================

ChatLoop_StrNCmp PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 8
    .allocstack 8
    .endprolog

    mov rax, rcx
    mov rbx, rdx

cmp_loop:
    test r8, r8
    jz cmp_equal
    dec r8

    mov cl, byte ptr [rax]
    mov dl, byte ptr [rbx]
    cmp cl, dl
    jne cmp_neq

    test cl, cl
    jz cmp_equal

    inc rax
    inc rbx
    jmp cmp_loop

cmp_equal:
    xor rax, rax
    add rsp, 8
    pop rbx
    ret

cmp_neq:
    mov rax, 1
    add rsp, 8
    pop rbx
    ret
ChatLoop_StrNCmp ENDP

; ============================================================================
; Exports
; ============================================================================

PUBLIC ChatLoop_Run
PUBLIC ChatLoop_ReadLine
PUBLIC ChatLoop_PrintString
PUBLIC ChatLoop_PrintBytes
PUBLIC ChatLoop_StrNCmp

END