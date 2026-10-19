; deep2_auth_abi.inc — observation → AttemptGrant; no declaration mint
D2_AUTH_UNPROVEN          EQU 0
D2_AUTH_OBSERVED          EQU 1
D2_AUTH_VALIDATED         EQU 2
D2_AUTH_GRANTED           EQU 3
D2_AUTH_REVOKED           EQU 4

D2_GRANT_FINAL_LM         EQU 0000000000000001h
D2_GRANT_TOKEN_SELECT     EQU 0000000000000002h
D2_GRANT_AR_COMMIT        EQU 0000000000000004h
D2_GRANT_GPU_ATTN         EQU 0000000000000008h
D2_GRANT_GPU_ROUTER       EQU 0000000000000010h
D2_GRANT_EXPERT_DISPATCH  EQU 0000000000000020h
D2_GRANT_GROUPED_TOP8     EQU 0000000000000040h
D2_GRANT_Q4_FUSED_GEMV    EQU 0000000000000080h
D2_GRANT_NORM_PROJ        EQU 0000000000000100h
D2_GRANT_RESIDUAL_NORM    EQU 0000000000000200h
D2_GRANT_ACT_PINGPONG     EQU 0000000000000400h
D2_GRANT_PERSIST_PLAN     EQU 0000000000000800h
D2_GRANT_NPLUS1           EQU 0000000000001000h
D2_GRANT_EXPERT_HOTSET    EQU 0000000000002000h
D2_GRANT_DECODE_FASTPATH  EQU 0000000000004000h

; Deep2AuthWitness (80 bytes)
D2_AW_SIZE                EQU 80
D2_AW_BIT                 EQU 0       ; qword grant bit
D2_AW_EXECUTED            EQU 8       ; dword
D2_AW_COMPLETED           EQU 12      ; dword
D2_AW_ERROR               EQU 16      ; dword
D2_AW_SYNTHETIC           EQU 20      ; dword
D2_AW_FALLBACK            EQU 24      ; dword
D2_AW_MODEL_GEN           EQU 28      ; dword
D2_AW_DECODE_GEN          EQU 32      ; dword
D2_AW_CUR_MODEL_GEN       EQU 36      ; dword
D2_AW_CUR_DECODE_GEN      EQU 40      ; dword
D2_AW_TICKET              EQU 44      ; dword
D2_AW_CUR_TICKET          EQU 48      ; dword
D2_AW_OBS_COUNTER         EQU 52      ; dword
D2_AW_EXP_COUNTER         EQU 56      ; dword
D2_AW_FLAGS               EQU 60      ; dword
D2_AW_REQ_FLAGS           EQU 64      ; dword
D2_AW_RESERVED            EQU 68

; Deep2AuthState
D2_AS_SIZE                EQU 32
D2_AS_GRANTED_MASK        EQU 0       ; qword
D2_AS_MODEL_GEN           EQU 8       ; dword
D2_AS_DECODE_GEN          EQU 12      ; dword
D2_AS_TICKET              EQU 16      ; dword
D2_AS_LAST_STATUS         EQU 20      ; dword
D2_AS_RESERVED            EQU 24
