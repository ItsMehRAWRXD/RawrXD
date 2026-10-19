; g3_masm_vdrv_umd.asm — LoadLibrary amdxc64 (display UMD), no Vulkan (≤99)
OPTION CASEMAP:NONE
EXTERN LoadLibraryA:PROC
EXTERN FreeLibrary:PROC
EXTERN GetModuleFileNameA:PROC
EXTERN MasmWriteZ:PROC
EXTERN MasmWriteNL:PROC
PUBLIC MasmVdrvUmd

.data
szTag  BYTE "UMD_AMDXC64_LOAD=",0
szPath BYTE "C:\Windows\System32\DriverStore\FileRepository\"
       BYTE "u0203304.inf_amd64_a6e5a337568ce3f0\B026373\amdxc64.dll",0
szOk   BYTE "PASS",0
szBad  BYTE "FAIL",0
szMod  BYTE "UMD_AMDXC64_MODULE=",0
szNote BYTE "UMD_ROLE=WDDM_display_vdriver_not_amdvlk_ICD",0
buf    BYTE 512 DUP(0)

.code
MasmVdrvUmd PROC
    push rbx
    sub  rsp, 20h
    lea  rcx, szNote
    call MasmWriteZ
    call MasmWriteNL
    lea  rcx, szPath
    call LoadLibraryA
    mov  rbx, rax
    lea  rcx, szTag
    call MasmWriteZ
    test rbx, rbx
    jz   bad
    lea  rcx, szOk
    call MasmWriteZ
    call MasmWriteNL
    mov  rcx, rbx
    lea  rdx, buf
    mov  r8d, 512
    call GetModuleFileNameA
    lea  rcx, szMod
    call MasmWriteZ
    lea  rcx, buf
    call MasmWriteZ
    call MasmWriteNL
    mov  rcx, rbx
    call FreeLibrary
    jmp  done
bad: lea  rcx, szBad
    call MasmWriteZ
    call MasmWriteNL
done:add  rsp, 20h
    pop  rbx
    ret
MasmVdrvUmd ENDP
END
