; Deep2OuterPrint.asm — six fail-closed status lines
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN OuterWriteZ:PROC
PUBLIC OuterPrintFlags

.data
s_path db "PATH_PRESENT=",0
s_dir  db "DIRECTORY_PRESENT=",0
s_comp db "SHARD_COUNT_COMPLETE=",0
s_dup  db "NO_DUPLICATE_INDEX=",0
s_miss db "NO_MISSING_INDEX=",0
s_hdr  db "EVERY_SHARD_GGUF_HEADER_VALID=",0
s_nl   db 13,10,0
s_one  db "1",0
s_zero db "0",0

.code
OuterBitLine PROC
    push rbx
    push rsi
    sub rsp, 28h
    mov ebx, ecx
    mov esi, edx
    mov rcx, r8
    call OuterWriteZ
    test ebx, esi
    lea rcx, s_zero
    jz BL_W
    lea rcx, s_one
BL_W:
    call OuterWriteZ
    lea rcx, s_nl
    call OuterWriteZ
    add rsp, 28h
    pop rsi
    pop rbx
    ret
OuterBitLine ENDP

OuterPrintFlags PROC PUBLIC
    push rbx
    sub rsp, 20h
    mov ebx, ecx
    mov ecx, ebx
    mov edx, OUT_F_PATH
    lea r8, s_path
    call OuterBitLine
    mov ecx, ebx
    mov edx, OUT_F_DIR
    lea r8, s_dir
    call OuterBitLine
    mov ecx, ebx
    mov edx, OUT_F_COMPLETE
    lea r8, s_comp
    call OuterBitLine
    mov ecx, ebx
    mov edx, OUT_F_NO_DUP
    lea r8, s_dup
    call OuterBitLine
    mov ecx, ebx
    mov edx, OUT_F_NO_MISS
    lea r8, s_miss
    call OuterBitLine
    mov ecx, ebx
    mov edx, OUT_F_HDR_OK
    lea r8, s_hdr
    call OuterBitLine
    add rsp, 20h
    pop rbx
    ret
OuterPrintFlags ENDP
END
