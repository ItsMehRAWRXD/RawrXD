; g3_masm_vk_dev.asm — heap + A0 vkCreateDevice (≤99)
OPTION CASEMAP:NONE
EXTERN vkGetPhysicalDeviceMemoryProperties:PROC
EXTERN vkCreateDevice:PROC
EXTERN vkDestroyDevice:PROC
EXTERN MasmWriteZ:PROC
EXTERN MasmWriteI32:PROC
EXTERN MasmWriteU64:PROC
EXTERN MasmWriteNL:PROC
EXTERN pdev:QWORD
EXTERN dev:QWORD
EXTERN memP:BYTE
EXTERN props:BYTE
EXTERN qci:BYTE
EXTERN devCI:BYTE
EXTERN prio:DWORD
EXTERN szName:BYTE
EXTERN szVram:BYTE
EXTERN szA0:BYTE
EXTERN szOk:BYTE
EXTERN szBad:BYTE
PUBLIC MasmVkSoloDev

.code
MasmVkSoloDev PROC
    push rbx
    push rsi
    push rdi
    sub  rsp, 20h
    lea  rcx, szName
    call MasmWriteZ
    lea  rcx, props+20
    call MasmWriteZ
    call MasmWriteNL
    mov  rcx, pdev
    lea  rdx, memP
    call vkGetPhysicalDeviceMemoryProperties
    mov  eax, DWORD PTR memP[260]
    xor  esi, esi
    xor  rdi, rdi
hl:  cmp  esi, eax
    jae  hv
    mov  r9d, esi
    shl  r9, 4
    lea  r10, memP[264]
    add  r10, r9
    test DWORD PTR [r10+8], 1
    jz   hn
    mov  r11, QWORD PTR [r10]
    cmp  r11, rdi
    jbe  hn
    mov  rdi, r11
hn:  inc  esi
    jmp  hl
hv:  lea  rcx, szVram
    call MasmWriteZ
    mov  rcx, rdi
    call MasmWriteU64
    call MasmWriteNL
    lea  rdi, qci
    xor  eax, eax
    mov  ecx, 40
    rep  stosb
    mov  DWORD PTR qci[0], 2
    mov  DWORD PTR qci[24], 1
    lea  rax, prio
    mov  QWORD PTR qci[32], rax
    lea  rdi, devCI
    xor  eax, eax
    mov  ecx, 72
    rep  stosb
    mov  DWORD PTR devCI[0], 3
    mov  DWORD PTR devCI[20], 1
    lea  rax, qci
    mov  QWORD PTR devCI[24], rax
    mov  rcx, pdev
    lea  rdx, devCI
    xor  r8, r8
    lea  r9, dev
    call vkCreateDevice
    mov  ebx, eax
    lea  rcx, szA0
    call MasmWriteZ
    mov  ecx, ebx
    call MasmWriteI32
    call MasmWriteNL
    test ebx, ebx
    jnz  bad
    lea  rcx, szOk
    call MasmWriteZ
    call MasmWriteNL
    mov  rcx, dev
    xor  rdx, rdx
    call vkDestroyDevice
    jmp  dev_exit
bad: lea  rcx, szBad
    call MasmWriteZ
    call MasmWriteNL
dev_exit:
    add  rsp, 20h
    pop  rdi
    pop  rsi
    pop  rbx
    ret
MasmVkSoloDev ENDP
END
