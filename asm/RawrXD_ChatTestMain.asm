; ============================================================================
; RawrXD_ChatTestMain.asm
; Standalone test: links chat loop + detokenizer, provides fake inference callback
; Zero dependencies, kernel32.lib only
; ============================================================================

option casemap:none

includelib kernel32.lib

GetProcessHeap    proto
HeapAlloc         proto :qword, :dword, :qword
HeapFree          proto :qword, :dword, :qword
ExitProcess       proto :dword
RtlMoveMemory     proto :qword, :qword, :qword

HEAP_ZERO_MEMORY equ 00000008h

EXTERNDEF ChatLoop_Run:PROC
EXTERNDEF SovereignDetokenizer_Init:PROC
EXTERNDEF SovereignDetokenizer_Detokenize:PROC
EXTERNDEF SovereignDetokenizer_Cleanup:PROC

.data
response_prefix db "Echo: ",0
response_suffix db " [token count: ",0
response_close  db "]",0

.data?
g_vocab_buf     db 1024 dup(?)
g_vocab_lens    dq 16 dup(?)
g_special_ids   dq 3 dup(?)

.code

; ============================================================================
; Fake inference callback
; int FakeInfer(void* ctx, const char* input, int input_len, char* out, int out_cap)
; ============================================================================
FakeInfer PROC frame
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov r12, r8                          ; output buffer
    mov r13d, r9d                        ; capacity
    mov rsi, rdx                         ; input
    mov ebx, ecx                         ; input len (unused)

    ; Copy prefix
    lea rdi, response_prefix
    call strlen
    mov r8, rax
    mov rcx, r12
    mov rdx, rdi
    call memcpy
    add r12, rax

    ; Copy input
    mov rcx, r12
    mov rdx, rsi
    mov r8d, ebx
    call memcpy
    add r12, rbx

    ; Copy suffix
    lea rdi, response_suffix
    call strlen
    mov r8, rax
    mov rcx, r12
    mov rdx, rdi
    call memcpy
    add r12, rax

    ; Append input length as decimal
    mov eax, ebx
    mov rcx, r12
    call itoa
    add r12, rax

    lea rdi, response_close
    call strlen
    mov r8, rax
    mov rcx, r12
    mov rdx, rdi
    call memcpy
    add r12, rax

    ; null terminate
    mov byte ptr [r12], 0

    mov eax, r12d
    sub eax, r8d                          ; wrong, fix below

    add rsp, 32
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
FakeInfer ENDP

; Helper: strlen(RDI) -> RAX
strlen PROC
    push rdi
    xor eax, eax
    mov rcx, -1
    repne scasb
    mov rax, -2
    sub rax, rcx
    pop rdi
    ret
strlen ENDP

; Helper: memcpy(RCX=dst, RDX=src, R8D=len)
memcpy PROC
    push rsi
    push rdi
    mov rdi, rcx
    mov rsi, rdx
    mov ecx, r8d
    rep movsb
    pop rdi
    pop rsi
    ret
memcpy ENDP

; Helper: itoa(EAX=value, RCX=dst) -> RAX=chars written
itoa PROC
    push rbx
    push rsi
    mov rsi, rcx
    mov ebx, eax
    test ebx, ebx
    jnz itoa_nonzero
    mov byte ptr [rsi], '0'
    mov byte ptr [rsi+1], 0
    mov rax, 1
    jmp itoa_done

itoa_nonzero:
    xor ecx, ecx
    mov r8, 10
itoa_loop:
    test ebx, ebx
    jz itoa_write
    xor edx, edx
    mov eax, ebx
    div r8d
    mov ebx, eax
    add dl, '0'
    push rdx
    inc ecx
    jmp itoa_loop

itoa_write:
    xor eax, eax
write_loop:
    test ecx, ecx
    jz itoa_done
    pop rdx
    mov [rsi + rax], dl
    inc rax
    dec ecx
    jmp write_loop

itoa_done:
    mov byte ptr [rsi + rax], 0
    pop rsi
    pop rbx
    ret
itoa ENDP

; ============================================================================
; main
; ============================================================================
main PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Setup tiny fake vocab: token 0="ĠHello", 1="ĠWorld", 2="!"
    lea rdi, g_vocab_buf
    mov byte ptr [rdi+0], 0C4h
    mov byte ptr [rdi+1], 0A0h
    mov byte ptr [rdi+2], 'H'
    mov byte ptr [rdi+3], 'e'
    mov byte ptr [rdi+4], 'l'
    mov byte ptr [rdi+5], 'l'
    mov byte ptr [rdi+6], 'o'
    mov byte ptr [rdi+7], 0

    mov byte ptr [rdi+8], 0C4h
    mov byte ptr [rdi+9], 0A0h
    mov byte ptr [rdi+10], 'W'
    mov byte ptr [rdi+11], 'o'
    mov byte ptr [rdi+12], 'r'
    mov byte ptr [rdi+13], 'l'
    mov byte ptr [rdi+14], 'd'
    mov byte ptr [rdi+15], 0

    mov byte ptr [rdi+16], '!'
    mov byte ptr [rdi+17], 0

    lea rax, g_vocab_lens
    mov qword ptr [rax+0], 7
    mov qword ptr [rax+8], 7
    mov qword ptr [rax+16], 1

    lea rax, g_special_ids
    mov qword ptr [rax+0], 999999
    mov qword ptr [rax+8], 999999
    mov qword ptr [rax+16], 999999

    lea rcx, g_vocab_buf
    mov edx, 3
    lea r8, g_vocab_lens
    lea r9, g_special_ids
    call SovereignDetokenizer_Init

    ; Run chat loop with fake inference
    lea rcx, FakeInfer
    xor edx, edx
    call ChatLoop_Run

    ; ChatLoop_Run never returns (calls ExitProcess)
    xor ecx, ecx
    call ExitProcess

    add rsp, 32
    pop rbx
    ret
main ENDP

END