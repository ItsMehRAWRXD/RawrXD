; ============================================================================
; RawrXD_IntegrityValidator.asm — CRC32C stream validator (SSE4.2)
; ============================================================================
; Exports:
;   RawrXD_ValidateBufferCRC32_Asm(buffer_ptr, size_bytes, seed) -> crc32
; ============================================================================

OPTION CASEMAP:NONE

.code

RawrXD_ValidateBufferCRC32_Asm PROC PUBLIC
    ; RCX = buffer ptr
    ; RDX = size bytes
    ; R8  = initial seed
    ; RAX = final crc32 (zero-extended)

    mov eax, r8d
    test rdx, rdx
    jz crc_done

crc_qword_loop:
    cmp rdx, 8
    jb crc_byte_loop
    mov r9, qword ptr [rcx]
    crc32 rax, r9
    add rcx, 8
    sub rdx, 8
    jmp crc_qword_loop

crc_byte_loop:
    test rdx, rdx
    jz crc_done
    mov r9b, byte ptr [rcx]
    crc32 eax, r9b
    inc rcx
    dec rdx
    jmp crc_byte_loop

crc_done:
    ret
RawrXD_ValidateBufferCRC32_Asm ENDP

END
