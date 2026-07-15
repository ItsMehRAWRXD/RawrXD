; ============================================================================
; RawrXD_ChatLoop_v2.asm
; Fixed pure x64 MASM interactive chat loop
; Zero dependencies, kernel32.lib only
; Callback ABI: int Infer(void* ctx, const char* input, int input_len, char* out, int out_cap)
; ============================================================================

option casemap:none

includelib kernel32.lib

GetStdHandle      proto :dword
ReadFile          proto :qword, :qword, :dword, :qword, :qword
WriteFile         proto :qword, :qword, :dword, :qword, :qword
ExitProcess       proto :dword
Sleep             proto :dword

STD_INPUT_HANDLE  equ -10
STD_OUTPUT_HANDLE equ -11

MAX_INPUT_LEN     equ 4096
MAX_OUTPUT_LEN    equ 65536

.data
banner            db "=================================================================",13,10
                  db "  Sovereign Engine - Interactive Chat Mode",13,10
                  db "  Type 'exit' or 'quit' to stop.",13,10
                  db "=================================================================",13,10,13,10,0
you_prompt        db "You: ",0
ai_prompt         db 13,10,"AI: ",0
exit_cmd          db "exit",0
quit_cmd          db "quit",0
newline           db 13,10,0

.data?
input_buffer      db MAX_INPUT_LEN dup(?)
output_buffer     db MAX_OUTPUT_LEN dup(?)
h_stdin           dq ?
h_stdout          dq ?

.code

; ============================================================================
; ChatLoop_Run
;   RCX = inference_callback
;   RDX = context_pointer
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
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov r12, rcx                       ; callback
    mov r13, rdx                       ; context

    mov ecx, STD_INPUT_HANDLE
    call GetStdHandle
    mov h_stdin, rax
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov h_stdout, rax

    lea rcx, banner
    call ChatLoop_PrintString

main_loop:
    lea rcx, you_prompt
    call ChatLoop_PrintString

    call ChatLoop_ReadLine
    mov r14d, eax                      ; input length

    test r14d, r14d
    jz main_loop

    lea rcx, input_buffer
    lea rdx, exit_cmd
    mov r8d, 4
    call ChatLoop_StrNCaseCmp
    test eax, eax
    jz do_exit

    lea rcx, input_buffer
    lea rdx, quit_cmd
    mov r8d, 4
    call ChatLoop_StrNCaseCmp
    test eax, eax
    jz do_exit

    lea rcx, ai_prompt
    call ChatLoop_PrintString

    ; Callback(ctx, input, input_len, output, output_capacity)
    ; RCX, RDX, R8, R9, stack
    mov rcx, r13
    lea rdx, input_buffer
    mov r8d, r14d
    lea r9, output_buffer
    mov qword ptr [rsp+32], MAX_OUTPUT_LEN
    call r12
    mov ebx, eax                       ; response length

    lea rcx, output_buffer
    mov edx, ebx
    call ChatLoop_PrintBytes

    lea rcx, newline
    call ChatLoop_PrintString

    jmp main_loop

do_exit:
    lea rcx, newline
    call ChatLoop_PrintString
    xor ecx, ecx
    call ExitProcess

    ; never reached
    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ChatLoop_Run ENDP

; ============================================================================
; ChatLoop_ReadLine
; Returns RAX = bytes read excluding CR/LF, input_buffer null-terminated
; ============================================================================
ChatLoop_ReadLine PROC frame
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog

    lea rdi, input_buffer
    xor ebx, ebx

read_char:
    cmp ebx, MAX_INPUT_LEN - 2
    jae read_done

    mov rcx, h_stdin
    mov rdx, rdi
    mov r8d, 1
    lea r9, qword ptr [rsp+32]
    mov qword ptr [rsp+40], 0
    call ReadFile

    mov rax, qword ptr [rsp+32]
    test rax, rax
    jz read_done_eof

    mov al, byte ptr [rdi]
    cmp al, 13
    je read_done
    cmp al, 10
    je read_done

    inc rdi
    inc ebx
    jmp read_char

read_done_eof:
read_done:
    mov byte ptr [rdi], 0
    mov eax, ebx

    add rsp, 40
    pop rdi
    pop rbx
    ret
ChatLoop_ReadLine ENDP

; ============================================================================
; ChatLoop_PrintString
; RCX = null-terminated string
; ============================================================================
ChatLoop_PrintString PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rbx, rcx
    xor eax, eax
len_loop:
    cmp byte ptr [rbx + rax], 0
    je len_done
    inc eax
    jmp len_loop
len_done:

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
; ChatLoop_PrintBytes
; RCX = buffer, RDX = length
; ============================================================================
ChatLoop_PrintBytes PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rbx, rcx
    mov rcx, h_stdout
    mov rdx, rbx
    mov r8d, edx
    lea r9, qword ptr [rsp+32]
    mov qword ptr [rsp+40], 0
    call WriteFile

    add rsp, 32
    pop rbx
    ret
ChatLoop_PrintBytes ENDP

; ============================================================================
; ChatLoop_StrNCaseCmp
; RCX = s1, RDX = s2, R8D = n
; Returns RAX = 0 if equal (case-insensitive), 1 otherwise
; ============================================================================
ChatLoop_StrNCaseCmp PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 8
    .allocstack 8
    .endprolog

    mov rax, rcx
    mov rbx, rdx

cmp_loop:
    test r8d, r8d
    jz cmp_equal
    dec r8d

    movzx ecx, byte ptr [rax]
    movzx edx, byte ptr [rbx]

    ; to lower
    cmp cl, 'A'
    jb cmp_not_upper1
    cmp cl, 'Z'
    ja cmp_not_upper1
    add cl, 32
cmp_not_upper1:
    cmp dl, 'A'
    jb cmp_not_upper2
    cmp dl, 'Z'
    ja cmp_not_upper2
    add dl, 32
cmp_not_upper2:

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
ChatLoop_StrNCaseCmp ENDP

PUBLIC ChatLoop_Run
PUBLIC ChatLoop_ReadLine
PUBLIC ChatLoop_PrintString
PUBLIC ChatLoop_PrintBytes
PUBLIC ChatLoop_StrNCaseCmp

END