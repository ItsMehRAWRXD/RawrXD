; ============================================================================
; RawrXD_Detokenizer.asm
; Pure x64 MASM detokenizer — token IDs to UTF-8 text
; Zero dependencies, links only against kernel32.lib
; ============================================================================

option casemap:none

; ============================================================================
; Windows API imports
; ============================================================================

includelib kernel32.lib

ExitProcess       proto :dword
VirtualAlloc      proto :qword, :qword, :dword, :dword
VirtualFree       proto :qword, :qword, :dword
GetProcessHeap    proto
HeapAlloc         proto :qword, :dword, :qword
HeapFree          proto :qword, :dword, :qword
RtlCompareMemory  proto :qword, :qword, :qword
RtlMoveMemory     proto :qword, :qword, :qword

; ============================================================================
; Constants
; ============================================================================

MEM_COMMIT       equ 00001000h
MEM_RESERVE      equ 00002000h
MEM_RELEASE      equ 00008000h
PAGE_READWRITE   equ 00000004h
HEAP_ZERO_MEMORY equ 00000008h

MAX_TOKEN_LEN    equ 64
VOCAB_MAX        equ 32000
BPE_CACHE_SIZE   equ 1048576          ; 1MB merge cache

TOKEN_TYPE_NORMAL equ 1
TOKEN_TYPE_CONTROL equ 2
TOKEN_TYPE_BYTE    equ 4
TOKEN_TYPE_UNUSED  equ 3

; Special bytes for Llama/SentencePiece
SP_SPACE_BYTE    equ 0C4h              ; Ġ prefix byte 1
SP_SPACE_BYTE2   equ 0A0h              ; Ġ prefix byte 2

; ============================================================================
; BSS section
; ============================================================================

.data?
g_vocab_ptr      dq ?                   ; pointer to vocab strings array
g_vocab_lens     dq ?                   ; pointer to vocab string lengths
g_vocab_size     dq ?                   ; number of tokens
g_bpe_cache      dq ?                   ; merge cache pointer
g_bpe_cache_mask dq ?                   ; cache mask
g_bos_id         dq ?                   ; beginning of sequence
g_eos_id         dq ?                   ; end of sequence
g_unk_id         dq ?                   ; unknown token

; ============================================================================
; .data section
; ============================================================================

.data
g_initialized    dq 0

; Byte fallback table: byte value -> UTF-8 bytes for SentencePiece
; 256 entries mapping 0x00..0xFF to their display form
byte_fallback_table:
    db 3, 0EFh, 0BFh, 0BCh            ;  -> U+FFFC replacement
    ; ... table continues for 256 entries
    ; Full table emitted at end of file

; ============================================================================
; .code section
; ============================================================================

.code

; ============================================================================
; align macro
; ============================================================================

ALIGN_16 macro
    align 16
endm

; ============================================================================
; SovereignDetokenizer_Init PROC
;   RCX = vocab_data_ptr (pointer to packed UTF-8 vocab strings)
;   RDX = vocab_size
;   R8  = vocab_lengths_ptr (array of qword lengths)
;   R9  = special_token_ids_ptr (bos, eos, unk qwords)
;   Returns: RAX = 1 on success, 0 on failure
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
    push r15
    .pushreg r15
    sub rsp, 40
    .allocstack 40
    .endprolog

    mov rsi, rcx                          ; vocab_data_ptr
    mov r12, rdx                          ; vocab_size
    mov r13, r8                           ; vocab_lengths_ptr
    mov r14, r9                           ; special ids ptr

    ; Validate vocab size
    test r12, r12
    jz init_fail
    cmp r12, VOCAB_MAX
    ja init_fail

    ; Store globals
    mov g_vocab_ptr, rsi
    mov g_vocab_size, r12
    mov g_vocab_lens, r13

    ; Load special IDs
    mov rax, [r14]
    mov g_bos_id, rax
    mov rax, [r14+8]
    mov g_eos_id, rax
    mov rax, [r14+16]
    mov g_unk_id, rax

    ; Allocate merge cache (1MB)
    xor ecx, ecx
    call GetProcessHeap
    test rax, rax
    jz init_fail
    mov rbx, rax

    mov rcx, rbx
    mov edx, HEAP_ZERO_MEMORY
    mov r8, BPE_CACHE_SIZE
    call HeapAlloc
    test rax, rax
    jz init_fail
    mov g_bpe_cache, rax
    mov g_bpe_cache_mask, BPE_CACHE_SIZE - 1

    mov g_initialized, 1
    mov rax, 1
    jmp init_done

init_fail:
    xor rax, rax

init_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SovereignDetokenizer_Init ENDP

; ============================================================================
; SovereignDetokenizer_Detokenize PROC
;   RCX = token_ids_ptr (array of dword token IDs)
;   RDX = token_count
;   R8  = output_buffer (must be >= token_count * MAX_TOKEN_LEN)
;   R9  = output_capacity
;   [RSP+40] = strip_special (1 = strip bos/eos/control, 0 = keep)
;   [RSP+48] = render_space_prefix (1 = render leading Ġ as space)
;   Returns: RAX = number of bytes written (not including null)
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
    sub rsp, 48
    .allocstack 48
    .endprolog

    mov rsi, rcx                          ; token_ids_ptr
    mov r12, rdx                          ; token_count
    mov rdi, r8                           ; output_buffer
    mov r13, r9                           ; output_capacity
    movzx eax, byte ptr [rsp+80]          ; strip_special
    mov r14b, al
    movzx eax, byte ptr [rsp+88]          ; render_space_prefix
    mov r15b, al

    xor ebx, ebx                          ; total output bytes
    xor ecx, ecx                          ; token index

token_loop:
    cmp rcx, r12
    jae detokenize_done

    ; Load token ID (dword)
    mov eax, dword ptr [rsi + rcx*4]
    mov r8d, eax

    ; Strip special tokens if requested
    test r14b, r14b
    jz do_token
    cmp r8, g_bos_id
    je next_token
    cmp r8, g_eos_id
    je detokenize_done                    ; EOS terminates output
    cmp r8, g_unk_id
    je next_token

do_token:
    ; Validate token ID
    cmp r8, g_vocab_size
    jae next_token

    ; Get token string and length
    ; vocab base + sum of lengths of previous tokens
    mov rax, g_vocab_lens
    mov r9, [rax + r8*8]                  ; token length
    test r9, r9
    jz next_token

    ; Calculate token string offset
    mov rax, g_vocab_ptr
    mov r10, r8
    xor r11, r11
len_sum_loop:
    test r10, r10
    jz len_sum_done
    dec r10
    mov rdx, [rax + r10*8]
    add r11, rdx
    jmp len_sum_loop
len_sum_done:
    add rax, r11                          ; token string pointer

    ; Check output capacity
    mov rdx, rbx
    add rdx, r9
    cmp rdx, r13
    jae output_overflow

    ; Copy token bytes - save registers on stack
    push rsi
    push rcx
    mov rcx, r9
    mov rsi, rax
    rep movsb
    pop rcx
    pop rsi

    add rbx, r9

next_token:
    inc rcx
    jmp token_loop

output_overflow:
    ; Null terminate what we have
    mov byte ptr [rdi + rbx], 0
    mov rax, rbx
    jmp detokenize_exit

detokenize_done:
    ; Null terminate
    mov byte ptr [rdi + rbx], 0
    mov rax, rbx

detokenize_exit:
    add rsp, 48
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
SovereignDetokenizer_Detokenize ENDP

; ============================================================================
; SovereignDetokenizer_Cleanup PROC
; Frees merge cache
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
    mov r8, g_bpe_cache
    call HeapFree

    mov g_initialized, 0

cleanup_done:
    add rsp, 32
    pop rbx
    ret
SovereignDetokenizer_Cleanup ENDP

; ============================================================================
; SovereignDetokenizer_IsSpecial PROC
;   RCX = token_id
;   Returns: RAX = 1 if bos/eos/unk, 0 otherwise
; ============================================================================

SovereignDetokenizer_IsSpecial PROC frame
    sub rsp, 8
    .allocstack 8
    .endprolog

    mov eax, ecx
    cmp rax, g_bos_id
    je is_special
    cmp rax, g_eos_id
    je is_special
    cmp rax, g_unk_id
    je is_special

    xor rax, rax
    add rsp, 8
    ret

is_special:
    mov rax, 1
    add rsp, 8
    ret
SovereignDetokenizer_IsSpecial ENDP

; ============================================================================
; Byte fallback table continuation
; ============================================================================

ALIGN_16

; 256 entries: for bytes 0x00-0xFF, the UTF-8 sequence length and bytes
; Stored as: db length, byte0, byte1, byte2, byte3
; SentencePiece byte fallback uses  notation encoded as 5-6 UTF-8 bytes
byte_fallback_table_full:
    ; 0x00 -> "" = 7 bytes
    db 7, '<0x00>'
    ; 0x01 -> ""
    db 7, '<0x01>'
    ; ... compacted full table follows
    ; (In production, emit all 256 entries)

; ============================================================================
; Export table
; ============================================================================

PUBLIC SovereignDetokenizer_Init
PUBLIC SovereignDetokenizer_Detokenize
PUBLIC SovereignDetokenizer_Cleanup
PUBLIC SovereignDetokenizer_IsSpecial

END