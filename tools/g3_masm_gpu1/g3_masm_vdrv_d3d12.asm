; g3_masm_vdrv_d3d12.asm — DXGI+D3D12 no Vulkan (≤99)
OPTION CASEMAP:NONE
INCLUDE g3_masm_vdrv_d3d12_ext.inc
PUBLIC MasmVdrvD3D12
.code
MasmVdrvD3D12 PROC
    push rbx
    sub rsp,20h
    lea rcx,szGate
    call MasmWriteZ
    call MasmWriteNL
    lea rcx,szDxgi
    call LoadLibraryA
    test rax,rax
    jz fail
    mov hDxgi,rax
    lea rcx,szD3d12
    call LoadLibraryA
    test rax,rax
    jz fail
    mov hD3d,rax
    mov rcx,hDxgi
    lea rdx,szCF1
    call GetProcAddress
    mov pfnCF1,rax
    mov rcx,hD3d
    lea rdx,szCD
    call GetProcAddress
    mov pfnCD,rax
    test rax,rax
    jz fail
    lea rcx,iidFact
    lea rdx,pFactory
    call QWORD PTR pfnCF1
    test eax,eax
    js fail
    xor ebx,ebx
lp: mov rax,pFactory
    mov rax,[rax]
    mov rcx,pFactory
    mov edx,ebx
    lea r8,pAdapter
    call QWORD PTR [rax+60h]
    test eax,eax
    js done
    mov rax,pAdapter
    mov rax,[rax]
    mov rcx,pAdapter
    lea rdx,desc1
    call QWORD PTR [rax+50h]
    lea rcx,desc1
    lea rdx,n7800
    call MatchW
    test eax,eax
    jz t97
    lea rcx,sz7800
    call EmitOne
    jmp rel
t97: lea rcx,desc1
    lea rdx,n9700
    call MatchW
    test eax,eax
    jz rel
    lea rcx,sz9700
    call EmitOne
rel: mov rax,pAdapter
    mov rax,[rax]
    mov rcx,pAdapter
    call QWORD PTR [rax+10h]
    inc ebx
    cmp ebx,16
    jb lp
done:mov rax,pFactory
    test rax,rax
    jz fr
    mov rax,[rax]
    mov rcx,pFactory
    call QWORD PTR [rax+10h]
fr: mov rcx,hD3d
    test rcx,rcx
    jz fr2
    call FreeLibrary
fr2:mov rcx,hDxgi
    test rcx,rcx
    jz vx
    call FreeLibrary
vx: add rsp,20h
    pop rbx
    ret
fail:lea rcx,szFail
    call MasmWriteZ
    call MasmWriteNL
    jmp fr
MasmVdrvD3D12 ENDP
END
