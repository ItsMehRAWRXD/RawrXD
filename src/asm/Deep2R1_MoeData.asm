; Deep2R1_MoeData.asm — MoE packed/shared + dense FFN suffixes
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
PUBLIC MoeRoleTable

.data
s_ffn_gate_inp      db "ffn_gate_inp.weight",0
s_ffn_exp_probs_b   db "ffn_exp_probs_b.bias",0
s_ffn_gate_exps     db "ffn_gate_exps.weight",0
s_ffn_up_exps       db "ffn_up_exps.weight",0
s_ffn_down_exps     db "ffn_down_exps.weight",0
s_ffn_gate_shexp    db "ffn_gate_shexp.weight",0
s_ffn_up_shexp      db "ffn_up_shexp.weight",0
s_ffn_down_shexp    db "ffn_down_shexp.weight",0
s_ffn_gate_shared   db "ffn_gate_shared.weight",0
s_ffn_up_shared     db "ffn_up_shared.weight",0
s_ffn_down_shared   db "ffn_down_shared.weight",0
s_ffn_gate          db "ffn_gate.weight",0
s_ffn_up            db "ffn_up.weight",0
s_ffn_down          db "ffn_down.weight",0

ALIGN 8
MoeRoleTable LABEL BYTE
    dq OFFSET s_ffn_gate_inp
    dd R1_ROLE_MOE_ROUTER, R1_FLAG_MOE
    dq OFFSET s_ffn_exp_probs_b
    dd R1_ROLE_MOE_EXP_BIAS, R1_FLAG_MOE or R1_FLAG_R1_ALIAS
    dq OFFSET s_ffn_gate_exps
    dd R1_ROLE_MOE_GATE_EXPS, R1_FLAG_MOE or R1_FLAG_PACKED_EXPERTS
    dq OFFSET s_ffn_up_exps
    dd R1_ROLE_MOE_UP_EXPS, R1_FLAG_MOE or R1_FLAG_PACKED_EXPERTS
    dq OFFSET s_ffn_down_exps
    dd R1_ROLE_MOE_DOWN_EXPS, R1_FLAG_MOE or R1_FLAG_PACKED_EXPERTS
    dq OFFSET s_ffn_gate_shexp
    dd R1_ROLE_MOE_SHARED_GATE, R1_FLAG_MOE
    dq OFFSET s_ffn_up_shexp
    dd R1_ROLE_MOE_SHARED_UP, R1_FLAG_MOE
    dq OFFSET s_ffn_down_shexp
    dd R1_ROLE_MOE_SHARED_DOWN, R1_FLAG_MOE
    dq OFFSET s_ffn_gate_shared
    dd R1_ROLE_MOE_SHARED_GATE, R1_FLAG_MOE or R1_FLAG_R1_ALIAS
    dq OFFSET s_ffn_up_shared
    dd R1_ROLE_MOE_SHARED_UP, R1_FLAG_MOE or R1_FLAG_R1_ALIAS
    dq OFFSET s_ffn_down_shared
    dd R1_ROLE_MOE_SHARED_DOWN, R1_FLAG_MOE or R1_FLAG_R1_ALIAS
    dq OFFSET s_ffn_gate
    dd R1_ROLE_DENSE_GATE, R1_FLAG_DENSE
    dq OFFSET s_ffn_up
    dd R1_ROLE_DENSE_UP, R1_FLAG_DENSE
    dq OFFSET s_ffn_down
    dd R1_ROLE_DENSE_DOWN, R1_FLAG_DENSE
    dq 0
    dd 0, 0
END
