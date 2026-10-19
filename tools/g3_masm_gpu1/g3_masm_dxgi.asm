; g3_masm_dxgi.asm — DXGI DedicatedVideoMemory (≤99)
OPTION CASEMAP:NONE
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN FreeLibrary:PROC
EXTERN MasmWriteZ:PROC
EXTERN MasmWriteU64:PROC
EXTERN MasmWriteNL:PROC
EXTERN MatchW:PROC
PUBLIC MasmDxgiEmit

.data
szDxgi    BYTE "dxgi.dll",0
szCreate  BYTE "CreateDXGIFactory1",0
align 16
iidFact   BYTE 78h,0AEh,0Ah,77h,6Fh,0F2h,0BAh,4Dh
          BYTE 0A8h,29h,25h,3Ch,83h,0D1h,0B3h,87h
sz7800    BYTE "RX7800XT_DXGI_DedicatedVideoMemory=",0
sz9700    BYTE "R9700_DXGI_DedicatedVideoMemory=",0
szFail    BYTE "DXGI_EMIT=FAIL",0
n7800     BYTE "7800",0
n9700     BYTE "R9700",0
align 8
hDxgi     QWORD 0
pfnCreate QWORD 0
pFactory  QWORD 0
pAdapter  QWORD 0
desc1     BYTE 320 DUP(0)

.code
MasmDxgiEmit PROC
    push rbx
    sub  rsp, 20h
    lea  rcx, szDxgi
    call LoadLibraryA
    test rax, rax
    jz   fail
    mov  hDxgi, rax
    mov  rcx, rax
    lea  rdx, szCreate
    call GetProcAddress
    test rax, rax
    jz   fail
    mov  pfnCreate, rax
    lea  rcx, iidFact
    lea  rdx, pFactory
    call pfnCreate
    test eax, eax
    js   fail
    xor  ebx, ebx
lp:  mov  rax, pFactory
    mov  rax, [rax]
    mov  rcx, pFactory
    mov  edx, ebx
    lea  r8, pAdapter
    call QWORD PTR [rax+60h]
    test eax, eax
    js   done
    mov  rax, pAdapter
    mov  rax, [rax]
    mov  rcx, pAdapter
    lea  rdx, desc1
    call QWORD PTR [rax+50h]
    lea  rcx, desc1
    lea  rdx, n7800
    call MatchW
    test eax, eax
    jz   t97
    lea  rcx, sz7800
    call MasmWriteZ
    mov  rcx, QWORD PTR desc1[110h]
    call MasmWriteU64
    call MasmWriteNL
    jmp  rel
t97: lea  rcx, desc1
    lea  rdx, n9700
    call MatchW
    test eax, eax
    jz   rel
    lea  rcx, sz9700
    call MasmWriteZ
    mov  rcx, QWORD PTR desc1[110h]
    call MasmWriteU64
    call MasmWriteNL
rel: mov  rax, pAdapter
    mov  rax, [rax]
    mov  rcx, pAdapter
    call QWORD PTR [rax+10h]
    inc  ebx
    cmp  ebx, 16
    jb   lp
done:mov  rax, pFactory
    test rax, rax
    jz   fr
    mov  rax, [rax]
    mov  rcx, pFactory
    call QWORD PTR [rax+10h]
fr:  mov  rcx, hDxgi
    test rcx, rcx
    jz   dx_exit
    call FreeLibrary
dx_exit:
    add  rsp, 20h
    pop  rbx
    ret
fail:lea  rcx, szFail
    call MasmWriteZ
    call MasmWriteNL
    jmp  dx_exit
MasmDxgiEmit ENDP
END
