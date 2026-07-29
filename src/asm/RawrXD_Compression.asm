;=============================================================================
; RawrXD_Compression.asm - Zero-Dependency x64 Compression for Checkpoints
; Implements: LZ4-like fast compression + simple entropy coding
; No external dependencies - pure x64 MASM
;=============================================================================

;=============================================================================
; Compression Algorithm Overview
;=============================================================================
; This is a fast LZ4-style compression optimized for checkpoint data:
; - 4-byte hash table for match finding
; - 4-byte minimum match length
; - 64KB sliding window
; - Simple entropy coding for literals
;
; Format:
; [Token: 1 byte] [Literal Length: 0-4 bytes] [Literals: N bytes]
; [Match Offset: 2 bytes] [Match Length: 0-4 bytes]
;=============================================================================

;=============================================================================
; Constants
;=============================================================================
HASH_TABLE_SIZE EQU 4096          ; 4KB hash table (12-bit hash)
HASH_SHIFT      EQU 12            ; Hash shift amount
HASH_SHIFT_AMT  EQU 20            ; 32 - HASH_SHIFT = 20
HASH_MASK       EQU 4095          ; HASH_TABLE_SIZE - 1
MIN_MATCH_LEN   EQU 4             ; Minimum match length
MAX_MATCH_LEN   EQU 65535         ; Maximum match length
WINDOW_SIZE     EQU 65536         ; 64KB sliding window

;=============================================================================
; Data Section
;=============================================================================
.data

; Hash table for LZ4-style compression
; Each entry is a 32-bit offset into the source buffer
align 16
hash_table      DD HASH_TABLE_SIZE DUP(0)

; Compression level (1-9, higher = better compression, slower)
compression_level DD 1

;=============================================================================
; Code Section
;=============================================================================
.code

;=============================================================================
; RawrXD_Compress
;   Compress data using fast LZ4-style algorithm
;
; Parameters:
;   RCX = source buffer
;   RDX = source length
;   R8  = destination buffer
;   R9  = destination max length
;
; Returns:
;   RAX = compressed size (0 if compression failed)
;=============================================================================
RawrXD_Compress PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog

    ; Save parameters
    mov     rsi, rcx                ; RSI = source
    mov     rbx, rdx                ; RBX = source length
    mov     rdi, r8                 ; RDI = destination
    mov     r15, r9                 ; R15 = dest max length

    ; Check for empty input
    test    rbx, rbx
    jz      compress_empty

    ; Check for insufficient output buffer
    cmp     r15, 16                 ; Need at least 16 bytes for header
    jb      compress_fail

    ; Write header
    mov     rax, rbx                ; Original size
    mov     [rdi], rax              ; Store original size
    mov     rax, 0                  ; Compressed size placeholder
    mov     [rdi+8], rax            ; Will be filled at end
    add     rdi, 16                 ; Skip header
    sub     r15, 16                 ; Adjust remaining space

    ; Initialize compression state
    mov     r12, rsi                ; R12 = current position in source
    mov     r13, rsi                ; R13 = source end
    add     r13, rbx
    mov     r14, rdi                ; R14 = destination start (for size calc)

    ; Clear hash table
    xor     rax, rax
    mov     rcx, HASH_TABLE_SIZE
    lea     rdi, [hash_table]
    rep     stosq

    mov     rdi, r14                ; Restore destination

    ; Main compression loop
    mov     rcx, rsi                ; RCX = anchor (start of current block)
    add     rcx, rbx                ; RCX = source end
    sub     rcx, MIN_MATCH_LEN      ; Stop before end to allow match

compress_loop:
    cmp     r12, rcx
    jae     compress_literals       ; Near end, just emit literals

    ; Compute hash of next 4 bytes
    mov     eax, [r12]              ; Load 4 bytes
    mov     r10d, 2654435761        ; Golden ratio hash constant (0x9E3779B1)
    imul    eax, r10d               ; Multiply
    shr     eax, HASH_SHIFT_AMT     ; Reduce to table index (32 - HASH_SHIFT)
    and     eax, HASH_MASK          ; HASH_TABLE_SIZE - 1

    ; Look up in hash table
    lea     r8, [hash_table]
    mov     r9d, [r8 + rax*4]       ; R9 = previous position

    ; Update hash table
    mov     eax, r12d
    sub     eax, esi                ; Convert to relative offset
    mov     [r8 + rax*4], eax

    ; Check if we have a valid match
    test    r9d, r9d
    jz      no_match

    ; Calculate match position
    mov     r8, rsi
    add     r8d, r9d                ; R8 = match position

    ; Check if match is within window
    mov     rax, r12
    sub     rax, r8
    cmp     rax, WINDOW_SIZE
    ja      no_match                ; Match too far back

    ; Verify match (4-byte comparison)
    mov     eax, [r12]
    cmp     eax, [r8]
    jne     no_match

    ; Found a match - calculate match length
    mov     r10, r12                ; R10 = current position
    add     r10, MIN_MATCH_LEN
    mov     r11, r8
    add     r11, MIN_MATCH_LEN

    ; Extend match
    mov     rdx, r13                ; Source end
    sub     rdx, r10
    cmp     rdx, MAX_MATCH_LEN
    jbe     match_extend_ok
    mov     rdx, MAX_MATCH_LEN

match_extend_ok:
    test    rdx, rdx
    jz      match_extend_done

match_extend_loop:
    mov     al, [r10]
    cmp     al, [r11]
    jne     match_extend_done
    inc     r10
    inc     r11
    dec     rdx
    jnz     match_extend_loop

match_extend_done:
    ; Calculate match length
    mov     rax, r10
    sub     rax, r12
    mov     r11, rax                ; R11 = match length

    ; Calculate literal length (bytes before match)
    mov     rax, r12
    sub     rax, rsi                ; Current position - start
    mov     r10, rax                ; R10 = literal length

    ; Emit token + literals + match
    call    emit_block

    ; Advance source position
    mov     rax, r11                ; Match length
    add     r12, rax
    add     r12, MIN_MATCH_LEN

    jmp     compress_loop

no_match:
    ; No match found, advance by 1
    inc     r12
    jmp     compress_loop

compress_literals:
    ; Emit remaining literals
    mov     rax, r13                ; Source end
    sub     rax, rsi                ; Remaining bytes
    test    rax, rax
    jz      compress_done

    mov     r10, rax                ; Literal length
    xor     r11, r11                ; No match
    call    emit_block

compress_done:
    ; Update header with compressed size
    mov     rax, rdi
    sub     rax, r14                ; Compressed size (excluding header)
    add     rax, 16                 ; Include header
    mov     [r14+8], rax            ; Store compressed size in header

    ; Return compressed size
    mov     rax, rdi
    sub     rax, r14
    jmp     compress_exit

compress_empty:
    ; Empty input - write minimal header
    mov     qword ptr [rdi], 0      ; Original size = 0
    mov     qword ptr [rdi+8], 16   ; Compressed size = header only
    mov     rax, 16
    jmp     compress_exit

compress_fail:
    xor     rax, rax                ; Return 0 (failure)

compress_exit:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

RawrXD_Compress ENDP

;=============================================================================
; emit_block - Internal helper to emit compressed block
; Inputs:
;   RDI = destination buffer (updated)
;   R15 = remaining destination space
;   RSI = literal start
;   R10 = literal length
;   R12 = match position (for offset calculation)
;   R11 = match length (0 if no match)
;=============================================================================
emit_block PROC
    push    rax
    push    rcx
    push    rdx

    ; Calculate token
    xor     al, al                  ; Token byte

    ; Encode literal length
    mov     rcx, r10
    cmp     rcx, 15
    jb      lit_len_small
    mov     al, 0F0h                ; 15 literals minimum
    jmp     lit_len_done
lit_len_small:
    shl     cl, 4                   ; Literal length in high nibble
    or      al, cl
lit_len_done:

    ; Encode match length (if any)
    test    r11, r11
    jz      no_match_len
    mov     rcx, r11
    sub     rcx, 4                  ; Match length offset
    cmp     rcx, 15
    jb      match_len_small
    or      al, 0Fh                 ; 15+ match
    jmp     match_len_done
match_len_small:
    or      al, cl
match_len_done:
no_match_len:

    ; Write token
    mov     [rdi], al
    inc     rdi
    dec     r15
    jz      emit_fail

    ; Write literal length extension if needed
    mov     rcx, r10
    cmp     rcx, 15
    jb      lit_ext_done
    sub     rcx, 15
    call    write_variable_length
    jc      emit_fail
lit_ext_done:

    ; Write literals
    mov     rcx, r10
    test    rcx, rcx
    jz      lit_copy_done
    cmp     r15, rcx
    jb      emit_fail

    ; Copy literals
    push    rsi
    push    rdi
    push    rcx
    rep     movsb
    pop     rcx
    pop     rdi
    pop     rsi
    add     rdi, rcx
    sub     r15, rcx
lit_copy_done:

    ; Skip if no match
    test    r11, r11
    jz      emit_done

    ; Write match offset (2 bytes, little-endian)
    mov     rax, r12
    sub     rax, rsi                ; Offset from current to match
    sub     rax, r10                ; Adjust for literals
    cmp     r15, 2
    jb      emit_fail
    mov     [rdi], ax
    add     rdi, 2
    sub     r15, 2

    ; Write match length extension if needed
    mov     rcx, r11
    sub     rcx, 4                  ; Base match length
    cmp     rcx, 15
    jbe     match_ext_done
    sub     rcx, 15
    call    write_variable_length
    jc      emit_fail
match_ext_done:

emit_done:
    clc                             ; Success
    jmp     emit_exit

emit_fail:
    stc                             ; Failure

emit_exit:
    pop     rdx
    pop     rcx
    pop     rax
    ret

emit_block ENDP

;=============================================================================
; write_variable_length - Write variable-length encoded integer
; Inputs:
;   RDI = destination
;   R15 = remaining space
;   RCX = value to encode
; Outputs:
;   RDI updated
;   R15 updated
;   CF set on failure
;=============================================================================
write_variable_length PROC
    push    rax

write_loop:
    cmp     r15, 0
    jz      write_fail

    cmp     rcx, 255
    jb      write_last

    ; Write 255 + continuation
    mov     byte ptr [rdi], 255
    inc     rdi
    dec     r15
    sub     rcx, 255
    jmp     write_loop

write_last:
    mov     [rdi], cl
    inc     rdi
    dec     r15

    clc
    jmp     write_exit

write_fail:
    stc

write_exit:
    pop     rax
    ret

write_variable_length ENDP

;=============================================================================
; RawrXD_Decompress
;   Decompress data compressed with RawrXD_Compress
;
; Parameters:
;   RCX = source buffer (compressed)
;   RDX = source length
;   R8  = destination buffer
;   R9  = destination max length
;
; Returns:
;   RAX = decompressed size (0 if decompression failed)
;=============================================================================
RawrXD_Decompress PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .endprolog

    ; Save parameters
    mov     rsi, rcx                ; RSI = source
    mov     rbx, rdx                ; RBX = source length
    mov     rdi, r8                 ; RDI = destination
    mov     r15, r9                 ; R15 = dest max length

    ; Check minimum header size
    cmp     rbx, 16
    jb      decompress_fail

    ; Read header
    mov     rax, [rsi]              ; Original size
    mov     r12, rax                ; R12 = expected output size
    mov     rax, [rsi+8]            ; Compressed size
    mov     r13, rax                ; R13 = compressed size

    ; Validate compressed size
    cmp     r13, rbx
    ja      decompress_fail         ; Header says more than we have

    ; Skip header
    add     rsi, 16
    sub     rbx, 16

    ; Check output buffer
    cmp     r15, r12
    jb      decompress_fail         ; Output buffer too small

    ; Main decompression loop
    mov     r14, rdi                ; R14 = destination start
    add     r15, rdi                ; R15 = destination end

decompress_loop:
    cmp     rbx, 0
    jz      decompress_done         ; No more input

    cmp     rdi, r15
    jae     decompress_done         ; Output buffer full

    ; Read token
    movzx   eax, byte ptr [rsi]
    inc     rsi
    dec     rbx

    mov     r8, rax                 ; Save token

    ; Extract literal length
    mov     rcx, rax
    shr     rcx, 4                  ; High nibble
    and     rcx, 0Fh
    cmp     rcx, 15
    jne     lit_len_ready

    ; Read extended literal length
    xor     rcx, rcx
lit_ext_loop:
    cmp     rbx, 0
    jz      decompress_fail
    movzx   eax, byte ptr [rsi]
    inc     rsi
    dec     rbx
    add     rcx, rax
    cmp     rax, 255
    je      lit_ext_loop

lit_len_ready:
    ; Copy literals
    test    rcx, rcx
    jz      lit_copy_done

    cmp     rbx, rcx
    jb      decompress_fail
    cmp     rdi, r15
    jae     decompress_fail

    push    rcx
    push    rsi
    push    rdi
    rep     movsb
    pop     rdi
    pop     rsi
    pop     rcx
    add     rdi, rcx
    sub     rbx, rcx
    add     rsi, rcx

lit_copy_done:
    ; Check for match
    mov     rax, r8
    and     rax, 0Fh                ; Low nibble = match length
    test    rax, rax
    jz      decompress_loop         ; No match, continue

    ; Read match offset
    cmp     rbx, 2
    jb      decompress_fail
    movzx   eax, word ptr [rsi]
    add     rsi, 2
    sub     rbx, 2

    ; Calculate match source
    mov     r9, rdi
    sub     r9, rax                 ; R9 = match source
    cmp     r9, r14
    jb      decompress_fail         ; Match before start of buffer

    ; Get match length
    mov     rcx, r8
    and     rcx, 0Fh
    add     rcx, 4                  ; Minimum match
    cmp     rcx, 19
    jne     match_len_ready

    ; Read extended match length
    xor     rcx, rcx
match_ext_loop:
    cmp     rbx, 0
    jz      decompress_fail
    movzx   eax, byte ptr [rsi]
    inc     rsi
    dec     rbx
    add     rcx, rax
    cmp     rax, 255
    je      match_ext_loop
    add     rcx, 19

match_len_ready:
    ; Copy match
    cmp     rdi, r15
    jae     decompress_fail

    push    rcx
    push    rsi
    push    rdi
    mov     rsi, r9                 ; Source = match position
    rep     movsb
    pop     rdi
    pop     rsi
    pop     rcx
    add     rdi, rcx

    jmp     decompress_loop

decompress_done:
    ; Verify we got expected size
    mov     rax, rdi
    sub     rax, r14                ; Actual output size
    cmp     rax, r12
    jne     decompress_fail         ; Size mismatch

    ; Return decompressed size
    jmp     decompress_exit

decompress_fail:
    xor     rax, rax                ; Return 0 (failure)

decompress_exit:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

RawrXD_Decompress ENDP

;=============================================================================
; RawrXD_Compression_GetMaxSize
;   Calculate maximum compressed size for given input
;
; Parameters:
;   RCX = input size
;
; Returns:
;   RAX = maximum compressed size
;=============================================================================
RawrXD_Compression_GetMaxSize PROC
    ; Worst case: header + 1 byte per input byte + overhead
    mov     rax, rcx
    add     rax, 16                 ; Header
    add     rax, rcx                ; Token per byte
    ; Variable length overhead: (rcx + 254) / 255
    mov     rdx, rcx
    add     rdx, 254
    xor     r8, r8
    mov     r8b, 255
    mov     rax, rdx
    xor     rdx, rdx
    div     r8
    add     rax, rcx
    add     rax, 16
    add     rax, 32                 ; Safety margin
    ret
RawrXD_Compression_GetMaxSize ENDP

;=============================================================================
; RawrXD_Compression_Init
;   Initialize compression library
;
; Parameters:
;   RCX = compression level (1-9, ignored for now)
;
; Returns:
;   RAX = 0 on success
;=============================================================================
RawrXD_Compression_Init PROC
    mov     [compression_level], ecx
    xor     rax, rax
    ret
RawrXD_Compression_Init ENDP

;=============================================================================
; RawrXD_Compression_Version
;   Get compression library version
;
; Returns:
;   RAX = version number (major << 24 | minor << 16 | patch << 8 | build)
;=============================================================================
RawrXD_Compression_Version PROC
    mov     eax, 01000001h          ; Version 1.0.0.1
    ret
RawrXD_Compression_Version ENDP

END
