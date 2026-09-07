; Deep2R1_LayerKind.asm — dense vs MoE from first_moe + freq
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
PUBLIC Deep2R1_LayerKind

.code
; RCX=topo EDX=layer  EAX=0 dense, 1 MoE, FFFFFFFFh invalid
Deep2R1_LayerKind PROC PUBLIC
    test rcx, rcx
    jz short R1LK_Inv
    cmp edx, dword ptr [rcx + R1T_NUM_LAYERS]
    jae short R1LK_Inv
    cmp dword ptr [rcx + R1T_NUM_EXPERTS], 0
    je short R1LK_Dense
    mov eax, dword ptr [rcx + R1T_FIRST_MOE_LAYER]
    cmp edx, eax
    jb short R1LK_Dense
    sub edx, eax
    mov r8d, dword ptr [rcx + R1T_MOE_LAYER_FREQ]
    test r8d, r8d
    jz short R1LK_Inv
    cmp r8d, 1
    je short R1LK_Moe
    mov eax, edx
    xor edx, edx
    div r8d
    test edx, edx
    jz short R1LK_Moe
R1LK_Dense:
    xor eax, eax
    ret
R1LK_Moe:
    mov eax, 1
    ret
R1LK_Inv:
    mov eax, 0FFFFFFFFh
    ret
Deep2R1_LayerKind ENDP
END
