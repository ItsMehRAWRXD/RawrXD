; g3_masm_vdrv_emit.asm — one-adapter D3D12CreateDevice emit (≤99)
OPTION CASEMAP:NONE
EXTERN MasmWriteZ:PROC
EXTERN MasmWriteI32:PROC
EXTERN MasmWriteU64:PROC
EXTERN MasmWriteNL:PROC
PUBLIC EmitOne
PUBLIC pfnCD
PUBLIC pAdapter
PUBLIC pDevice
PUBLIC desc1

D3D_FL_11_0 EQU 0B000h

.data
szDed BYTE "DXGI_DedicatedVideoMemory=",0
szHr  BYTE "D3D12CreateDevice_HRESULT=",0
szOk  BYTE "D3D12CreateDevice=PASS",0
szBad BYTE "D3D12CreateDevice=FAIL",0
align 16
iidDev BYTE 0F1h,19h,98h,18h,0B6h,1Dh,57h,4Bh
       BYTE 0BEh,54h,18h,21h,33h,9Bh,85h,0F7h
align 8
pfnCD    QWORD 0
pAdapter QWORD 0
pDevice  QWORD 0
desc1    BYTE 320 DUP(0)

.code
; RCX = tag prefix
EmitOne PROC
    push rbx
    push rsi
    sub  rsp, 28h
    mov  rsi, rcx
    mov  rcx, rsi
    call MasmWriteZ
    lea  rcx, szDed
    call MasmWriteZ
    mov  rcx, QWORD PTR desc1[110h]
    call MasmWriteU64
    call MasmWriteNL
    mov  pDevice, 0
    mov  rcx, pAdapter
    mov  edx, D3D_FL_11_0
    lea  r8, iidDev
    lea  r9, pDevice
    call QWORD PTR pfnCD
    mov  ebx, eax
    mov  rcx, rsi
    call MasmWriteZ
    lea  rcx, szHr
    call MasmWriteZ
    mov  ecx, ebx
    call MasmWriteI32
    call MasmWriteNL
    mov  rcx, rsi
    call MasmWriteZ
    test ebx, ebx
    jnz  ebad
    lea  rcx, szOk
    call MasmWriteZ
    call MasmWriteNL
    mov  rax, pDevice
    test rax, rax
    jz   edone
    mov  rax, [rax]
    mov  rcx, pDevice
    call QWORD PTR [rax+10h]
    jmp  edone
ebad:lea  rcx, szBad
    call MasmWriteZ
    call MasmWriteNL
edone:add  rsp, 28h
    pop  rsi
    pop  rbx
    ret
EmitOne ENDP
END
