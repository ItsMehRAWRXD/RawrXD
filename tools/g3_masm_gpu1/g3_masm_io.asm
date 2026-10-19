; g3_masm_io.asm — stdout helpers (≤99)
OPTION CASEMAP:NONE
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
PUBLIC MasmWriteZ
PUBLIC MasmWriteU64
PUBLIC MasmWriteI32
PUBLIC MasmWriteNL

.data
align 8
io_written DWORD 0
io_tmp     BYTE 48 DUP(0)
nl_bytes   BYTE 13,10,0
minus_ch   BYTE '-',0

.code
MasmWriteZ PROC
    push rsi
    sub  rsp, 20h
    mov  rsi, rcx
    mov  ecx, -11
    call GetStdHandle
    test rsi, rsi
    jz   wz_d
    mov  rcx, rax
    xor  eax, eax
wz_l: cmp  BYTE PTR [rsi+rax], 0
    je   wz_g
    inc  eax
    jmp  wz_l
wz_g: mov  rdx, rsi
    mov  r8d, eax
    lea  r9, io_written
    mov  QWORD PTR [rsp+20h], 0
    call WriteFile
wz_d: add  rsp, 20h
    pop  rsi
    ret
MasmWriteZ ENDP

MasmWriteNL PROC
    lea  rcx, nl_bytes
    jmp  MasmWriteZ
MasmWriteNL ENDP

MasmWriteU64 PROC
    push rbx
    push rsi
    sub  rsp, 28h
    mov  rax, rcx
    lea  rsi, io_tmp+47
    mov  BYTE PTR [rsi], 0
    mov  rbx, 10
u64l: xor  rdx, rdx
    div  rbx
    add  dl, '0'
    dec  rsi
    mov  [rsi], dl
    test rax, rax
    jnz  u64l
    mov  rcx, rsi
    call MasmWriteZ
    add  rsp, 28h
    pop  rsi
    pop  rbx
    ret
MasmWriteU64 ENDP

MasmWriteI32 PROC
    push rbx
    sub  rsp, 20h
    movsxd rbx, ecx
    test rbx, rbx
    jns  i_ok
    lea  rcx, minus_ch
    call MasmWriteZ
    neg  rbx
i_ok: mov  rcx, rbx
    call MasmWriteU64
    add  rsp, 20h
    pop  rbx
    ret
MasmWriteI32 ENDP
END
