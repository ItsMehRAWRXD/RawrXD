; Deep2R1_GlobData.asm — global tensor name/role table
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
PUBLIC GlobalRoleTable

.data
s_token_embd    db "token_embd.weight",0
s_output_norm   db "output_norm.weight",0
s_output        db "output.weight",0
s_lm_head       db "lm_head.weight",0
s_norm          db "norm.weight",0

ALIGN 8
GlobalRoleTable LABEL BYTE
    dq OFFSET s_token_embd
    dd R1_ROLE_TOKEN_EMBD, R1_FLAG_GLOBAL
    dq OFFSET s_output_norm
    dd R1_ROLE_OUTPUT_NORM, R1_FLAG_GLOBAL or R1_FLAG_NORM
    dq OFFSET s_output
    dd R1_ROLE_OUTPUT, R1_FLAG_GLOBAL
    dq OFFSET s_lm_head
    dd R1_ROLE_OUTPUT, R1_FLAG_GLOBAL or R1_FLAG_R1_ALIAS
    dq OFFSET s_norm
    dd R1_ROLE_OUTPUT_NORM, R1_FLAG_GLOBAL or R1_FLAG_NORM or R1_FLAG_R1_ALIAS
    dq 0
    dd 0, 0
END
