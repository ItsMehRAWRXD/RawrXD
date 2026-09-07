; Deep2R1_Validate.asm — structural MLA/MoE topology check
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
PUBLIC Deep2R1_ValidateTopology

.code
Deep2R1_ValidateTopology PROC PUBLIC
    test rcx, rcx
    jz short R1V_No
    cmp dword ptr [rcx + R1T_VOCAB_SIZE], 0
    je short R1V_No
    cmp dword ptr [rcx + R1T_HIDDEN_DIM], 0
    je short R1V_No
    cmp dword ptr [rcx + R1T_NUM_LAYERS], 0
    je short R1V_No
    cmp dword ptr [rcx + R1T_NUM_HEADS], 0
    je short R1V_No
    cmp dword ptr [rcx + R1T_KV_LORA_RANK], 0
    je short R1V_No
    cmp dword ptr [rcx + R1T_QK_NOPE_HEAD_DIM], 0
    je short R1V_No
    cmp dword ptr [rcx + R1T_QK_ROPE_HEAD_DIM], 0
    je short R1V_No
    cmp dword ptr [rcx + R1T_V_HEAD_DIM], 0
    je short R1V_No
    mov eax, dword ptr [rcx + R1T_NUM_EXPERTS]
    test eax, eax
    jz short R1V_No
    mov edx, dword ptr [rcx + R1T_EXPERTS_USED]
    test edx, edx
    jz short R1V_No
    cmp edx, eax
    ja short R1V_No
    mov eax, dword ptr [rcx + R1T_FIRST_MOE_LAYER]
    cmp eax, dword ptr [rcx + R1T_NUM_LAYERS]
    ja short R1V_No
    cmp dword ptr [rcx + R1T_MOE_LAYER_FREQ], 0
    je short R1V_No
    mov eax, 1
    ret
R1V_No:
    xor eax, eax
    ret
Deep2R1_ValidateTopology ENDP
END
