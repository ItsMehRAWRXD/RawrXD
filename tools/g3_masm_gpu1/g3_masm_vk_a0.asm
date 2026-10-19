; g3_masm_vk_a0.asm — CreateInstance + find 7800 (≤99)
OPTION CASEMAP:NONE
EXTERN vkCreateInstance:PROC
EXTERN vkDestroyInstance:PROC
EXTERN vkEnumeratePhysicalDevices:PROC
EXTERN vkGetPhysicalDeviceProperties:PROC
EXTERN MasmWriteZ:PROC
EXTERN MasmWriteI32:PROC
EXTERN MasmWriteNL:PROC
EXTERN MasmVkSoloDev:PROC
EXTERN gInst:QWORD
EXTERN pdev:QWORD
EXTERN pdN:DWORD
EXTERN pds:QWORD
EXTERN props:BYTE
EXTERN needle:BYTE
EXTERN szGate:BYTE
EXTERN szMode:BYTE
EXTERN szCI:BYTE
EXTERN szMiss:BYTE
PUBLIC MasmVkSoloA0

r$ = 32
inst$ = 40
app$ = 48
ci$ = 96

.code
MasmVkSoloA0 PROC
    push rbx
    push rsi
    push rdi
    sub  rsp, 160
    lea  rax, [rsp+app$]
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, 48
    rep  stosb
    mov  DWORD PTR [rsp+app$+44], 00402000h
    lea  rax, [rsp+ci$]
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, 64
    rep  stosb
    mov  DWORD PTR [rsp+ci$], 1
    lea  rax, [rsp+app$]
    mov  QWORD PTR [rsp+ci$+24], rax
    mov  QWORD PTR [rsp+inst$], 0
    lea  r8, [rsp+inst$]
    xor  edx, edx
    lea  rcx, [rsp+ci$]
    call vkCreateInstance
    mov  DWORD PTR [rsp+r$], eax
    lea  rcx, szGate
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szMode
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szCI
    call MasmWriteZ
    mov  ecx, DWORD PTR [rsp+r$]
    call MasmWriteI32
    call MasmWriteNL
    cmp  DWORD PTR [rsp+r$], 0
    jne  miss
    mov  rax, QWORD PTR [rsp+inst$]
    mov  gInst, rax
    mov  pdN, 16
    mov  rcx, rax
    lea  rdx, pdN
    lea  r8, pds
    call vkEnumeratePhysicalDevices
    xor  ebx, ebx
find:
    cmp  ebx, pdN
    jae  miss
    lea  rax, pds
    mov  rcx, QWORD PTR [rax+rbx*8]
    lea  rdx, props
    call vkGetPhysicalDeviceProperties
    lea  rsi, props+20
    lea  rdi, needle
    mov  r8, rsi
sc0: mov  al, [rdi]
    test al, al
    jz   hit
    mov  dl, [r8]
    test dl, dl
    jz   nxt
    cmp  al, dl
    jne  rst
    inc  r8
    inc  rdi
    jmp  sc0
rst: inc  rsi
    mov  r8, rsi
    lea  rdi, needle
    jmp  sc0
nxt: inc  ebx
    jmp  find
hit: lea  rax, pds
    mov  rax, QWORD PTR [rax+rbx*8]
    mov  pdev, rax
    call MasmVkSoloDev
    jmp  shut
miss:lea  rcx, szMiss
    call MasmWriteZ
    call MasmWriteNL
shut:mov  rcx, gInst
    test rcx, rcx
    jz   vk_exit
    xor  edx, edx
    call vkDestroyInstance
    mov  gInst, 0
vk_exit:
    add  rsp, 160
    pop  rdi
    pop  rsi
    pop  rbx
    ret
MasmVkSoloA0 ENDP
END
