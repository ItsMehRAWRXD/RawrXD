; g3_masm_vdrv_main.asm — no Vulkan; DXGI+D3D12+UMD load
OPTION CASEMAP:NONE
EXTERN MasmVdrvD3D12:PROC
EXTERN MasmVdrvUmd:PROC
EXTERN MasmWriteZ:PROC
EXTERN MasmWriteNL:PROC
PUBLIC main

.data
szHdr BYTE "IMPL=pure_x64_masm_vdriver",0
szDep BYTE "STATIC_DEP=masm+ucrt DYNAMIC=dxgi,d3d12 NO_VULKAN=1",0
szBe  BYTE "BEHAVIOR_PATCH=0",0
szPr  BYTE "PROMOTE=0",0
szEnd BYTE "STAGE=complete",0

.code
main PROC
    sub  rsp, 28h
    lea  rcx, szHdr
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szDep
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szBe
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szPr
    call MasmWriteZ
    call MasmWriteNL
    call MasmVdrvUmd
    call MasmVdrvD3D12
    lea  rcx, szEnd
    call MasmWriteZ
    call MasmWriteNL
    xor  eax, eax
    add  rsp, 28h
    ret
main ENDP
END
