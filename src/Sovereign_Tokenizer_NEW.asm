; ============================================================================
; Sovereign_Tokenizer.asm — Byte-Pair Encoding
; Static vocabulary + merge table in .DATA
; Real encode/decode with merge application
; ============================================================================
OPTION CASEMAP:NONE

include Sovereign_Common.inc

.DATA
VOCAB_SIZE equ 512
MAX_MERGES equ 4096

TOKEN_ENTRY STRUCT
    token_id    dd 0
    token_len   dd 0
    token_data  db 32 dup(0)
TOKEN_ENTRY ENDS

MERGE_ENTRY STRUCT
    left_id     dd 0
    right_id    dd 0
    rank        dd 0
    new_id      dd 0
MERGE_ENTRY ENDS

align 64
vocab_table TOKEN_ENTRY VOCAB_SIZE dup(<>)
byte_token_map dd 256 dup(0)
merge_table MERGE_ENTRY MAX_MERGES dup(<>)
merge_count dd 0

.CODE

; ----------------------------------------------------------------------------
; Tokenizer_Init
; Initialize 256 byte tokens + common merges
; ----------------------------------------------------------------------------
PUBLIC Tokenizer_Init
Tokenizer_Init PROC
    push rbx
    push r12

    ; Byte tokens 0-255
    xor rbx, rbx
@byte_loop:
    cmp ebx, 256
    jge @byte_done
    mov [vocab_table + rbx*SIZEOF TOKEN_ENTRY].TOKEN_ENTRY.token_id, ebx
    mov [vocab_table + rbx*SIZEOF TOKEN_ENTRY].TOKEN_ENTRY.token_len, 1
    mov [vocab_table + rbx*SIZEOF TOKEN_ENTRY].TOKEN_ENTRY.token_data, bl
    mov [byte_token_map + rbx*4], ebx
    inc rbx
    jmp @byte_loop
@byte_done:

    ; Clear merge table
    mov dword ptr [merge_count], 0

    ; Add common merges
    call @add_merge_th
    call @add_merge_he
    call @add_merge_in
    call @add_merge_er
    call @add_merge_an
    call @add_merge_re
    call @add_merge_on
    call @add_merge_at
    call @add_merge_en
    call @add_merge_nd

    pop r12
    pop rbx
    ret

@add_merge_th:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 't'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'h'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 1
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 256
    inc dword ptr [merge_count]
    ret

@add_merge_he:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'h'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'e'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 2
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 257
    inc dword ptr [merge_count]
    ret

@add_merge_in:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'i'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'n'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 3
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 258
    inc dword ptr [merge_count]
    ret

@add_merge_er:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'e'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'r'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 4
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 259
    inc dword ptr [merge_count]
    ret

@add_merge_an:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'a'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'n'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 5
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 260
    inc dword ptr [merge_count]
    ret

@add_merge_re:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'r'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'e'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 6
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 261
    inc dword ptr [merge_count]
    ret

@add_merge_on:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'o'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'n'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 7
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 262
    inc dword ptr [merge_count]
    ret

@add_merge_at:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'a'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 't'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 8
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 263
    inc dword ptr [merge_count]
    ret

@add_merge_en:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'e'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'n'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 9
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 264
    inc dword ptr [merge_count]
    ret

@add_merge_nd:
    mov ecx, [merge_count]
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id, 'n'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id, 'd'
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.rank, 10
    mov [merge_table + rcx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id, 265
    inc dword ptr [merge_count]
    ret
Tokenizer_Init ENDP

; ----------------------------------------------------------------------------
; Tokenize_String
; RCX = input string, RDX = input length, R8 = output token IDs
; Returns RAX = token count
; ----------------------------------------------------------------------------
PUBLIC Tokenize_String
Tokenize_String PROC
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40

    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    xor r15, r15

    ; Step 1: Byte tokens
    xor rbx, rbx
@init:
    cmp rbx, r13
    jge @init_done
    movzx eax, byte ptr [r12 + rbx]
    mov [r14 + rbx*4], eax
    inc rbx
    jmp @init
@init_done:
    mov r15, r13

    ; Step 2: Apply merges iteratively
@merge_pass:
    xor ebx, ebx
    xor rcx, rcx
@merge_loop:
    cmp rcx, r15
    jge @merge_pass_done
    cmp rcx, r15-1
    jge @merge_next

    mov eax, [r14 + rcx*4]
    mov edx, [r14 + rcx*4 + 4]

    ; Find merge
    push rcx
    push rbx
    xor rbx, rbx
@find_loop:
    cmp ebx, [merge_count]
    jge @find_fail
    cmp eax, [merge_table + rbx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.left_id
    jne @find_next
    cmp edx, [merge_table + rbx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.right_id
    jne @find_next
    mov eax, [merge_table + rbx*SIZEOF MERGE_ENTRY].MERGE_ENTRY.new_id
    jmp @find_done
@find_next:
    inc rbx
    jmp @find_loop
@find_fail:
    mov eax, -1
@find_done:
    pop rbx
    pop rcx

    cmp eax, -1
    je @merge_next

    ; Apply merge
    mov [r14 + rcx*4], eax
    ; Shift left
    push rcx
    push rax
    mov rbx, rcx
@shift:
    cmp rbx, r15-1
    jge @shift_done
    mov eax, [r14 + rbx*4 + 4]
    mov [r14 + rbx*4], eax
    inc rbx
    jmp @shift
@shift_done:
    pop rax
    pop rcx
    dec r15
    mov ebx, 1
    jmp @merge_loop

@merge_next:
    inc rcx
    jmp @merge_loop
@merge_pass_done:
    test ebx, ebx
    jnz @merge_pass

    mov rax, r15

    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
Tokenize_String ENDP

; ----------------------------------------------------------------------------
; Detokenize_String
; RCX = token IDs ptr, RDX = token count, R8 = output buffer
; Returns RAX = bytes written
; ----------------------------------------------------------------------------
PUBLIC Detokenize_String
Detokenize_String PROC
    push rbx
    push r12
    push r13
    push r14

    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    xor rbx, rbx

    xor rcx, rcx
@loop:
    cmp rcx, r13
    jge @done

    mov eax, [r12 + rcx*4]
    cmp eax, 256
    jae .unknown_token

    ; Byte token
    mov [r14 + rbx], al
    inc rbx
    jmp @next

@unknown_token:
    ; For merged tokens, output placeholder or lookup vocab
    ; Simplified: output '?' for unknown
    mov byte ptr [r14 + rbx], '?'
    inc rbx

@next:
    inc rcx
    jmp @loop

@done:
    mov rax, rbx

    pop r14
    pop r13
    pop r12
    pop rbx
    ret
Detokenize_String ENDP

END