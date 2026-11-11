; ============================================================================
; RawrXD_Detokenizer_v2.asm
; Fixed pure x64 MASM detokenizer — token IDs to UTF-8 text
; Zero dependencies, links only against kernel32.lib
; ============================================================================

option casemap:none

includelib kernel32.lib

; Windows API
VirtualAlloc      proto :qword, :qword, :dword, :dword
VirtualFree       proto :qword, :qword, :dword
GetProcessHeap    proto
HeapAlloc         proto :qword, :dword, :qword
HeapFree          proto :qword, :dword, :qword
RtlMoveMemory     proto :qword, :qword, :qword

; Constants
MEM_COMMIT       equ 00001000h
MEM_RESERVE      equ 00002000h
MEM_RELEASE      equ 00008000h
PAGE_READWRITE   equ 00000004h
HEAP_ZERO_MEMORY equ 00000008h

VOCAB_MAX        equ 100000
MAX_TOKEN_LEN    equ 256

; UTF-8 bytes for "Ġ" (SentencePiece space prefix)
SP_SPACE_1       equ 0C4h
SP_SPACE_2       equ 0A0h

; Data
.data
g_initialized    dq 0

.data?
g_vocab_data     dq ?
g_vocab_offsets  dq ?
g_vocab_lens     dq ?
g_vocab_size     dq ?
g_bos_id         dq ?
g_eos_id         dq ?
g_unk_id         dq ?

.code

; ============================================================================
; SovereignDetokenizer_Init
;   RCX = vocab_data_ptr (packed UTF-8 strings)
;   RDX = vocab_size
;   R8  = vocab_lengths_ptr (qword array)
;   R9  = special_ids_ptr (3 qwords: bos, eos, unk)
;   Returns: RAX = 1 success, 0 failure
; ============================================================================
SovereignDetokenizer_Init PROC frame
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

    mov rsi, rcx
    mov r12, rdx
    mov r13, r8
    mov r14, r9

    cmp r12, VOCAB_MAX
    ja init_fail
    test r12, r12
    jz init_fail

    mov g_vocab_data, rsi
    mov g_vocab_lens, r13
    mov g_vocab_size, r12

    mov rax, [r14]
    mov g_bos_id, rax
    mov rax, [r14+8]
    mov g_eos_id, rax
    mov rax, [r14+16]
    mov g_unk_id, rax

    xor ecx, ecx
    call GetProcessHeap
    test rax, rax
    jz init_fail
    mov rbx, rax

    ; Allocate offset table: vocab_size * 8 bytes
    mov rcx, rbx
    mov edx, HEAP_ZERO_MEMORY
    mov r8, r12
    shl r8, 3
    call HeapAlloc
    test rax, rax
    jz init_fail
    mov g_vocab_offsets, rax

    ; Build prefix-sum offset table
    xor rax, rax
    xor rcx, rcx
    mov rdi, g_vocab_offsets
    mov rsi, g_vocab_lens

build_offsets:
    cmp rcx, r12
    jae offsets_done
    mov [rdi + rcx*8], rax
    mov rdx, [rsi + rcx*8]
    add rax, rdx
    inc rcx
    jmp build_offsets

offsets_done:
    mov g_initialized, 1
    mov rax, 1
    jmp init_done

init_fail:
    xor rax, rax

init_done:
    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SovereignDetokenizer_Init ENDP

; ============================================================================
; SovereignDetokenizer_Detokenize
;   RCX = token_ids_ptr (dword array)
;   RDX = token_count
;   R8  = output_buffer
;   R9  = output_capacity
;   [RSP+40] = strip_special (byte)
;   [RSP+48] = convert_spaces (byte)  ; 1 = convert Ġ prefix to space
;   Returns: RAX = bytes written (not including null)
; ============================================================================
SovereignDetokenizer_Detokenize PROC frame
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

    mov rsi, rcx
    mov r12, rdx
    mov rdi, r8
    mov r13, r9
    movzx r14d, byte ptr [rsp+80]      ; strip_special
    movzx r15d, byte ptr [rsp+88]      ; convert_spaces

    xor ebx, ebx                        ; output bytes
    xor ecx, ecx                        ; token index

token_loop:
    cmp rcx, r12
    jae det_done

    mov eax, dword ptr [rsi + rcx*4]   ; token_id
    mov r8d, eax

    test r14b, r14b
    jz do_token
    cmp r8, g_bos_id
    je skip_token
    cmp r8, g_eos_id
    je det_done
    cmp r8, g_unk_id
    je skip_token

do_token:
    cmp r8, g_vocab_size
    jae skip_token

    mov rax, g_vocab_offsets
    mov rdx, [rax + r8*8]              ; token offset
    mov rax, g_vocab_lens
    mov r9, [rax + r8*8]               ; token length
    test r9, r9
    jz skip_token

    mov rax, g_vocab_data
    add rax, rdx                        ; token string pointer

    ; Handle Ġ -> space conversion
    cmp r15b, 1
    jne copy_token
    cmp r9, 2
    jb copy_token
    cmp byte ptr [rax], SP_SPACE_1
    jne copy_token
    cmp byte ptr [rax+1], SP_SPACE_2
    jne copy_token

    ; Output space, then copy remaining bytes
    cmp rbx, r13
    jae det_done_overflow
    mov byte ptr [rdi + rbx], ' '
    inc rbx
    add rax, 2
    sub r9, 2
    jz skip_token

copy_token:
    mov r10, rbx
    add r10, r9
    cmp r10, r13
    jae det_done_overflow
    mov r11, rsi
    mov r10, rcx
    mov rsi, rax
    mov rcx, r9
    rep movsb
    mov rsi, r11
    mov rcx, r10
    add rbx, r9

skip_token:
    inc rcx
    jmp token_loop

det_done_overflow:
    ; fall through to terminate
det_done:
    mov byte ptr [rdi + rbx], 0
    mov rax, rbx

    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SovereignDetokenizer_Detokenize ENDP

; ============================================================================
; SovereignDetokenizer_Cleanup
; ============================================================================
SovereignDetokenizer_Cleanup PROC frame
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    cmp g_initialized, 0
    je cleanup_done

    xor ecx, ecx
    call GetProcessHeap
    test rax, rax
    jz cleanup_done
    mov rbx, rax

    mov rcx, rbx
    xor edx, edx
    mov r8, g_vocab_offsets
    call HeapFree

    mov g_initialized, 0

cleanup_done:
    add rsp, 32
    pop rbx
    ret
SovereignDetokenizer_Cleanup ENDP

PUBLIC SovereignDetokenizer_Init
PUBLIC SovereignDetokenizer_Detokenize
PUBLIC SovereignDetokenizer_Cleanup

END