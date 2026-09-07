; Deep2R1_Smoke.asm — no-CRT decoder smoke (kernel32 ExitProcess only)
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
EXTERN Deep2R1_DecodeTensorName:PROC
EXTERN Deep2R1_ValidateTopology:PROC
EXTERN Deep2R1_LayerKind:PROC
EXTERN ExitProcess:PROC

.data
n1 db "blk.3.attn_kv_b.weight",0
n2 db "blk.4.ffn_gate_exps.weight",0
n3 db "blk.4.ffn_gate_inp.weight",0
ALIGN 16
decoded db R1D_SIZE dup(0)
ALIGN 16
topo LABEL BYTE
    dd 129280, 7168, 61, 128, 128
    dd 1536, 512, 128, 64, 128
    dd 256, 8, 1, 3, 1, 0

.code
mainCRTStartup PROC
    sub rsp, 28h
    lea rcx, n1
    lea rdx, decoded
    call Deep2R1_DecodeTensorName
    test eax, eax
    jz FAIL
    cmp dword ptr [decoded + R1D_ROLE], R1_ROLE_MLA_KV_B
    jne FAIL
    cmp dword ptr [decoded + R1D_LAYER], 3
    jne FAIL
    lea rcx, n2
    lea rdx, decoded
    call Deep2R1_DecodeTensorName
    test eax, eax
    jz FAIL
    cmp dword ptr [decoded + R1D_ROLE], R1_ROLE_MOE_GATE_EXPS
    jne FAIL
    lea rcx, n3
    lea rdx, decoded
    call Deep2R1_DecodeTensorName
    test eax, eax
    jz FAIL
    cmp dword ptr [decoded + R1D_ROLE], R1_ROLE_MOE_ROUTER
    jne FAIL
    lea rcx, topo
    call Deep2R1_ValidateTopology
    test eax, eax
    jz FAIL
    lea rcx, topo
    xor edx, edx
    call Deep2R1_LayerKind
    cmp eax, 0
    jne FAIL
    lea rcx, topo
    mov edx, 3
    call Deep2R1_LayerKind
    cmp eax, 1
    jne FAIL
    xor ecx, ecx
    call ExitProcess
FAIL:
    mov ecx, 1
    call ExitProcess
mainCRTStartup ENDP
END
