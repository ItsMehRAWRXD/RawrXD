; g3_masm_main.asm — DXGI + solo A0
OPTION CASEMAP:NONE
EXTERN MasmDxgiEmit:PROC
EXTERN MasmVkSoloA0:PROC
EXTERN MasmWriteZ:PROC
EXTERN MasmWriteNL:PROC
PUBLIC main

.data
szHdr BYTE "IMPL=pure_x64_masm",0
szDep BYTE "STATIC_DEP=masm+ucrt+vulkan-1_iat DYNAMIC=dxgi",0
szNote BYTE "NOTE=LARGEADDRESSAWARE_REQUIRED_FOR_AMDVLK",0
szBe  BYTE "BEHAVIOR_PATCH=0",0
szPr  BYTE "PROMOTE=0",0
szPost BYTE "STAGE=complete",0

.code
main PROC
    sub  rsp, 28h
    lea  rcx, szHdr
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szDep
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szNote
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szBe
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szPr
    call MasmWriteZ
    call MasmWriteNL
    call MasmVkSoloA0
    call MasmDxgiEmit
    lea  rcx, szPost
    call MasmWriteZ
    call MasmWriteNL
    xor  eax, eax
    add  rsp, 28h
    ret
main ENDP
END
