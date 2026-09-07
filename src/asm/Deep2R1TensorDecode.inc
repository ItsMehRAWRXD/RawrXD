; Deep2R1TensorDecode.inc — DeepSeek-R1 / V3 GGUF topology decode (x64)
OPTION CASEMAP:NONE

R1_ROLE_UNKNOWN             EQU 0
R1_ROLE_TOKEN_EMBD          EQU 1
R1_ROLE_OUTPUT_NORM         EQU 2
R1_ROLE_OUTPUT              EQU 3
R1_ROLE_ATTN_NORM           EQU 10
R1_ROLE_FFN_NORM            EQU 11
R1_ROLE_ATTN_Q              EQU 12
R1_ROLE_ATTN_K              EQU 13
R1_ROLE_ATTN_V              EQU 14
R1_ROLE_ATTN_OUT            EQU 15
R1_ROLE_MLA_Q_A_NORM        EQU 20
R1_ROLE_MLA_Q_A             EQU 21
R1_ROLE_MLA_Q_B             EQU 22
R1_ROLE_MLA_KV_A_NORM       EQU 23
R1_ROLE_MLA_KV_A_MQA        EQU 24
R1_ROLE_MLA_KV_B            EQU 25
R1_ROLE_MLA_K_B             EQU 26
R1_ROLE_MLA_V_B             EQU 27
R1_ROLE_MOE_ROUTER          EQU 30
R1_ROLE_MOE_GATE_EXPS       EQU 31
R1_ROLE_MOE_UP_EXPS         EQU 32
R1_ROLE_MOE_DOWN_EXPS       EQU 33
R1_ROLE_MOE_SHARED_GATE     EQU 34
R1_ROLE_MOE_SHARED_UP       EQU 35
R1_ROLE_MOE_SHARED_DOWN     EQU 36
R1_ROLE_MOE_EXP_BIAS        EQU 37
R1_ROLE_DENSE_GATE          EQU 40
R1_ROLE_DENSE_UP            EQU 41
R1_ROLE_DENSE_DOWN          EQU 42

R1_FLAG_GLOBAL              EQU 00000001h
R1_FLAG_MLA                 EQU 00000002h
R1_FLAG_MOE                 EQU 00000004h
R1_FLAG_NORM                EQU 00000008h
R1_FLAG_PACKED_EXPERTS      EQU 00000010h
R1_FLAG_DENSE               EQU 00000020h
R1_FLAG_R1_ALIAS            EQU 00000040h

R1_LAYER_NONE               EQU 0FFFFFFFFh
R1_EXPERT_NONE              EQU 0FFFFFFFFh

R1D_ROLE                    EQU 0
R1D_LAYER                   EQU 4
R1D_EXPERT                  EQU 8
R1D_FLAGS                   EQU 12
R1D_SIZE                    EQU 16

R1T_VOCAB_SIZE              EQU 0
R1T_HIDDEN_DIM              EQU 4
R1T_NUM_LAYERS              EQU 8
R1T_NUM_HEADS               EQU 12
R1T_NUM_KV_HEADS            EQU 16
R1T_Q_LORA_RANK             EQU 20
R1T_KV_LORA_RANK            EQU 24
R1T_QK_NOPE_HEAD_DIM        EQU 28
R1T_QK_ROPE_HEAD_DIM        EQU 32
R1T_V_HEAD_DIM              EQU 36
R1T_NUM_EXPERTS             EQU 40
R1T_EXPERTS_USED            EQU 44
R1T_NUM_SHARED_EXPERTS      EQU 48
R1T_FIRST_MOE_LAYER         EQU 52
R1T_MOE_LAYER_FREQ          EQU 56
R1T_RESERVED                EQU 60
R1T_SIZE                    EQU 64

R1S_NUM_HEADS               EQU 0
R1S_K_DIM                   EQU 4
R1S_V_DIM                   EQU 8
R1S_RESERVED                EQU 12
R1S_SIZE                    EQU 16
