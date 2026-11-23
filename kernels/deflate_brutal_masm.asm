; Valid gzip writer using DEFLATE stored blocks.
; ABI: RCX=source, RDX=source length, R8=output-length pointer.
; Caller owns the returned malloc() buffer and releases it with free().
OPTION casemap:none
PUBLIC deflate_brutal_masm
EXTERN malloc:PROC

.code
deflate_brutal_masm PROC
    ; Seven nonvolatile pushes leave RSP 16-byte aligned. Reserve 32 bytes
    ; of Win64 shadow space plus a 256-entry CRC32 table (1024 bytes).
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 1088

    mov     r13, rcx                ; preserve original source for CRC
    mov     rbx, rdx                ; input length
    mov     r14, r8                 ; output-length pointer
    test    r14, r14
    jz      _fail
    mov     qword ptr [r14], 0
    test    rbx, rbx
    jz      _source_ok              ; empty input permits a null source
    test    r13, r13
    jz      _fail

_source_ok:
    ; block_count=max(1, ceil(len/65535)); reject size arithmetic overflow.
    mov     rax, rbx
    add     rax, 65534
    jc      _fail
    mov     rcx, 65535
    xor     rdx, rdx
    div     rcx
    test    rax, rax
    jnz     _have_blocks
    mov     eax, 1                  ; empty stream still needs a final block
_have_blocks:
    imul    rax, 5
    jo      _fail
    add     rax, rbx
    jc      _fail
    add     rax, 18                 ; gzip header + footer
    jc      _fail

    ; RSP already supplies Win64 shadow space for malloc.
    mov     rcx, rax
    call    malloc
    test    rax, rax
    jz      _fail
    mov     r15, rax                ; allocation base
    mov     rdi, rax                ; output cursor

    ; RFC 1952 gzip header, OS=unknown.
    mov     word ptr [rdi], 08B1Fh
    mov     byte ptr [rdi+2], 08h
    mov     byte ptr [rdi+3], 0
    mov     dword ptr [rdi+4], 0
    mov     word ptr [rdi+8], 0FF00h
    add     rdi, 10

    ; Emit one or more RFC 1951 stored blocks, each <= 65535 bytes.
    mov     rsi, r13
    mov     r12, rbx
    cld
    test    r12, r12
    jnz     _block_loop

    ; Empty input: BFINAL=1, LEN=0, NLEN=0xffff.
    mov     byte ptr [rdi], 1
    mov     word ptr [rdi+1], 0
    mov     word ptr [rdi+3], 0FFFFh
    add     rdi, 5
    jmp     _blocks_done

_block_loop:
    mov     rax, r12
    cmp     rax, 65535
    jbe     _chunk_ready
    mov     eax, 65535
_chunk_ready:
    mov     rcx, r12
    sub     rcx, rax
    mov     byte ptr [rdi], 0
    test    rcx, rcx
    jnz     _header_ready
    mov     byte ptr [rdi], 1      ; BFINAL on last block
_header_ready:
    inc     rdi
    mov     cx, ax
    mov     word ptr [rdi], cx    ; LEN
    not     cx
    mov     word ptr [rdi+2], cx  ; NLEN
    add     rdi, 4
    mov     rcx, rax
    rep     movsb
    sub     r12, rax
    jnz     _block_loop

_blocks_done:
    ; Build the standard IEEE CRC-32 table (polynomial 0xedb88320).
    lea     r11, [rsp+32]
    xor     ecx, ecx
_crc_table_outer:
    mov     eax, ecx
    mov     r10d, 8
_crc_table_bit:
    shr     eax, 1
    jnc     _crc_table_next
    xor     eax, 0EDB88320h
_crc_table_next:
    dec     r10d
    jnz     _crc_table_bit
    mov     dword ptr [r11+rcx*4], eax
    inc     ecx
    cmp     ecx, 256
    jb      _crc_table_outer

    ; CRC32 = ~fold(0xffffffff, source bytes).
    mov     eax, 0FFFFFFFFh
    mov     rsi, r13
    mov     rcx, rbx
_crc_data_loop:
    test    rcx, rcx
    jz      _crc_data_done
    movzx   edx, byte ptr [rsi]
    xor     eax, edx
    mov     edx, eax
    and     edx, 0FFh
    shr     eax, 8
    xor     eax, dword ptr [r11+rdx*4]
    inc     rsi
    dec     rcx
    jmp     _crc_data_loop
_crc_data_done:
    not     eax
    mov     dword ptr [rdi], eax    ; gzip CRC32 (little-endian)
    add     rdi, 4
    mov     eax, ebx
    mov     dword ptr [rdi], eax    ; ISIZE modulo 2^32
    add     rdi, 4

    mov     rax, rdi
    sub     rax, r15
    mov     qword ptr [r14], rax
    mov     rax, r15
    jmp     _exit

_fail:
    xor     rax, rax
_exit:
    add     rsp, 1088
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
