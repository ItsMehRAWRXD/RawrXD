; Deep2R1_MlaData.asm — attn / MLA block suffixes
OPTION CASEMAP:NONE
INCLUDE Deep2R1TensorDecode.inc
PUBLIC MlaRoleTable

.data
s_attn_norm         db "attn_norm.weight",0
s_ffn_norm          db "ffn_norm.weight",0
s_attn_q            db "attn_q.weight",0
s_attn_k            db "attn_k.weight",0
s_attn_v            db "attn_v.weight",0
s_attn_output       db "attn_output.weight",0
s_attn_o            db "attn_o.weight",0
s_attn_q_a_norm     db "attn_q_a_norm.weight",0
s_attn_q_a          db "attn_q_a.weight",0
s_attn_q_b          db "attn_q_b.weight",0
s_attn_kv_a_norm    db "attn_kv_a_norm.weight",0
s_attn_kv_a_mqa     db "attn_kv_a_mqa.weight",0
s_attn_kv_b         db "attn_kv_b.weight",0
s_attn_k_b          db "attn_k_b.weight",0
s_attn_v_b          db "attn_v_b.weight",0

ALIGN 8
MlaRoleTable LABEL BYTE
    dq OFFSET s_attn_norm
    dd R1_ROLE_ATTN_NORM, R1_FLAG_NORM
    dq OFFSET s_ffn_norm
    dd R1_ROLE_FFN_NORM, R1_FLAG_NORM
    dq OFFSET s_attn_q
    dd R1_ROLE_ATTN_Q, 0
    dq OFFSET s_attn_k
    dd R1_ROLE_ATTN_K, 0
    dq OFFSET s_attn_v
    dd R1_ROLE_ATTN_V, 0
    dq OFFSET s_attn_output
    dd R1_ROLE_ATTN_OUT, 0
    dq OFFSET s_attn_o
    dd R1_ROLE_ATTN_OUT, R1_FLAG_R1_ALIAS
    dq OFFSET s_attn_q_a_norm
    dd R1_ROLE_MLA_Q_A_NORM, R1_FLAG_MLA or R1_FLAG_NORM
    dq OFFSET s_attn_q_a
    dd R1_ROLE_MLA_Q_A, R1_FLAG_MLA
    dq OFFSET s_attn_q_b
    dd R1_ROLE_MLA_Q_B, R1_FLAG_MLA
    dq OFFSET s_attn_kv_a_norm
    dd R1_ROLE_MLA_KV_A_NORM, R1_FLAG_MLA or R1_FLAG_NORM
    dq OFFSET s_attn_kv_a_mqa
    dd R1_ROLE_MLA_KV_A_MQA, R1_FLAG_MLA
    dq OFFSET s_attn_kv_b
    dd R1_ROLE_MLA_KV_B, R1_FLAG_MLA or R1_FLAG_R1_ALIAS
    dq OFFSET s_attn_k_b
    dd R1_ROLE_MLA_K_B, R1_FLAG_MLA
    dq OFFSET s_attn_v_b
    dd R1_ROLE_MLA_V_B, R1_FLAG_MLA
    dq 0
    dd 0, 0
END
