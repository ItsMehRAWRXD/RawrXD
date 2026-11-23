; deflate_brutal_masm.asm
; ml64 /c /Fo deflate_brutal_masm.obj deflate_brutal_masm.asm
OPTION casemap:none
PUBLIC deflate_brutal_masm
EXTERN malloc:PROC
EXTERN memcpy:PROC
EXTERN rawrxd_gzip_crc32:PROC

.code
deflate_brutal_masm PROC
    ; Prologue
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 64         ; Reserve 64 bytes (aligned to 16 bytes)

    ; Save non-volatile registers
    mov     rsi, rcx        ; src (advanced while copying)
    mov     r13, rcx        ; original src for CRC32
    mov     rbx, rdx        ; len
    mov     r14, r8         ; out_len*

    ; out_len is mandatory; initialize it before any failure path.
    test    r14, r14
    jz      _fail
    mov     qword ptr [r14], 0
    ; A null source is valid only for the empty stream.
    test    rbx, rbx
    jz      _source_ok
    test    rsi, rsi
    jz      _fail
_source_ok:

    ; Calculate block count and allocation size
    mov     rax, rbx
    add     rax, 65534
    jc      _fail           ; reject size_t overflow
    mov     rcx, 65535
    xor     rdx, rdx
    div     rcx             ; rax = block_count
    test    rax, rax
    jnz     _have_blocks
    mov     eax, 1          ; empty input still needs a final empty block
_have_blocks:
    mov     rcx, rax
    imul    rcx, 5          ; 5 bytes overhead per block
    jo      _fail
    add     rcx, rbx
    jc      _fail
    add     rcx, 18         ; gzip header + footer
    jc      _fail

    ; Allocate memory
    sub     rsp, 32         ; Shadow space for malloc call
    mov     rcx, rcx
    call    malloc
    add     rsp, 32
    test    rax, rax
    jz      _fail

    mov     r15, rax        ; out base
    mov     rdi, rax        ; p

    ; Gzip header (10 bytes)
    mov     word ptr [rdi], 08B1Fh
    mov     byte ptr [rdi+2], 08h
    mov     dword ptr [rdi+4], 0
    mov     byte ptr [rdi+8], 0
    mov     byte ptr [rdi+9], 3
    add     rdi, 10

    ; Stored blocks. RFC 1951 requires one final empty stored block for
    ; an empty payload; do not emit a gzip header immediately followed by
    ; the trailer.
    mov     r12, rbx        ; remaining bytes
    test    r12, r12
    jnz     _block_loop
    mov     byte ptr [rdi], 1
    inc     rdi
    mov     word ptr [rdi], 0
    mov     word ptr [rdi+2], 0FFFFh
    add     rdi, 4
    jmp     _after_blocks
_block_loop:
    test    r12, r12
    jz      _after_blocks

    mov     rax, r12
    cmp     rax, 65535
    jbe     _chunk_ok
    mov     rax, 65535
_chunk_ok:
    ; Header byte: BFINAL if remaining == chunk
    mov     rcx, r12
    sub     rcx, rax
    cmp     rcx, 0
    jne     _not_final
    mov     byte ptr [rdi], 1
    jmp     _hdr_done
_not_final:
    mov     byte ptr [rdi], 0
_hdr_done:
    inc     rdi
    mov     cx, ax
    mov     word ptr [rdi], cx
    not     cx
    mov     word ptr [rdi+2], cx
    add     rdi, 4

    ; Copy data using rep movsb (fast on modern CPUs)
    mov     rcx, rax        ; count
    rep     movsb           ; rsi+=count, rdi+=count, rcx=0
    
    sub     r12, rax
    jmp     _block_loop

_after_blocks:
    ; Footer: IEEE CRC32 of the original input and ISIZE modulo 2^32.
    ; The helper uses the gzip/IEEE polynomial, not the CRC32C instruction.
    mov     rcx, r13
    mov     rdx, rbx
    sub     rsp, 32
    call    rawrxd_gzip_crc32
    add     rsp, 32
    mov     dword ptr [rdi], eax
    add     rdi, 4
    mov     eax, ebx
    mov     dword ptr [rdi], eax
    add     rdi, 4

    ; Set out_len
    mov     rax, rdi
    sub     rax, r15
    mov     qword ptr [r14], rax

    mov     rax, r15        ; return buffer
    jmp     _exit

_fail:
    xor     rax, rax

_exit:
    add     rsp, 64         ; Restore stack alignment
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
deflate_brutal_masm ENDP
END
