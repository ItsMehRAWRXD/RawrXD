OPTION CASEMAP:NONE
PUBLIC RemoteCrc32
.code
RemoteCrc32 PROC
    ; rcx=data rdx=len -> eax IEEE CRC32 (tableless)
    mov eax,0FFFFFFFFh
crc_byte:
    test rdx,rdx
    jz crc_done
    movzx r8d,BYTE PTR [rcx]
    xor eax,r8d
    mov r9d,8
crc_bit:
    mov r10d,eax
    and r10d,1
    neg r10d
    shr eax,1
    and r10d,0EDB88320h
    xor eax,r10d
    dec r9d
    jnz crc_bit
    inc rcx
    dec rdx
    jmp crc_byte
crc_done:
    not eax
    ret
RemoteCrc32 ENDP
END
