option casemap:none

NILW_OK                         equ 0
NILW_E_NULL                     equ 1
NILW_E_INVALID                  equ 2

NILW_ERR_NULL_INPUT             equ 0000000000000001h
NILW_ERR_TOTAL_WEIGHTS_ZERO     equ 0000000000000002h
NILW_ERR_ACTIVE_WEIGHTS_ZERO    equ 0000000000000004h
NILW_ERR_ACTIVE_RANGE           equ 0000000000000008h
NILW_ERR_CODEC_BITS_ZERO        equ 0000000000000010h
NILW_ERR_NEW_GT_CODEC           equ 0000000000000020h
NILW_ERR_PAYLOAD_SUM_OVERFLOW   equ 0000000000000040h
NILW_ERR_IDENTITY_MISMATCH      equ 0000000000000080h
NILW_ERR_TARGET_NILW_ZERO       equ 0000000000000100h
NILW_ERR_PAYLOAD_CAP_ZERO       equ 0000000000000200h
NILW_ERR_RATE_CAP_ZERO          equ 0000000000000400h
NILW_ERR_TARGET_TPS_ZERO        equ 0000000000000800h
NILW_ERR_MIN_TOKENS_ZERO        equ 0000000000001000h
NILW_ERR_RUN_TOKENS_ZERO        equ 0000000000002000h
NILW_ERR_WALL_NS_ZERO           equ 0000000000004000h
NILW_ERR_BOOLEAN_RANGE          equ 0000000000008000h
NILW_ERR_RUN_PAYLOAD_TOO_SMALL  equ 0000000000010000h

NILW_G_INPUT_VALID              equ 0000000000000001h
NILW_G_IDENTITY                 equ 0000000000000002h
NILW_G_NILW_LIMIT               equ 0000000000000004h
NILW_G_TOKEN_PAYLOAD_CAP        equ 0000000000000008h
NILW_G_MEAN_PAYLOAD_CAP         equ 0000000000000010h
NILW_G_INFORMATION_RATE         equ 0000000000000020h
NILW_G_TARGET_TPS               equ 0000000000000040h
NILW_G_MIN_TOKEN_WINDOW         equ 0000000000000080h
NILW_G_NO_FULL_MATERIALIZATION  equ 0000000000000100h
NILW_G_NO_REPORTED_OVERFLOW     equ 0000000000000200h
NILW_G_NO_LONGRUN_FAILURES      equ 0000000000000400h
NILW_G_LIVE_WITNESS             equ 0000000000000800h
NILW_G_TOKEN_AUTHORITY          equ 0000000000001000h
NILW_G_DECODE_AUTHORITY         equ 0000000000002000h
NILW_G_NO_SUPERSEDED_FALLBACK   equ 0000000000004000h
NILW_G_SUSTAINABLE              equ 0000000000008000h
NILW_G_RUNTIME_AUTHORIZED       equ 0000000000010000h
NILW_G_SUSTAINABLE_REQUIRED     equ 00000000000007FFh
NILW_G_RUNTIME_REQUIRED         equ 000000000000F800h

NILW_INPUT STRUCT
    total_logical_weights        QWORD ?
    active_logical_weights       QWORD ?
    active_codec_bits            QWORD ?
    new_codec_bits               QWORD ?
    overhead_bits                QWORD ?
    observed_new_payload_bits    QWORD ?
    run_new_payload_bytes        QWORD ?
    run_generated_tokens         QWORD ?
    run_wall_ns                  QWORD ?
    payload_cap_bytes_per_token  QWORD ?
    information_rate_cap_bps     QWORD ?
    target_tps                   QWORD ?
    min_generated_tokens         QWORD ?
    target_nilw_num              QWORD ?
    target_nilw_den              QWORD ?
    live_runtime_witness_count   QWORD ?
    longrun_failures             QWORD ?
    token_authority_agrees       DWORD ?
    decode_authority_agrees      DWORD ?
    superseded_zero_path_used    DWORD ?
    full_materialization         DWORD ?
    reported_budget_overflow     DWORD ?
    reserved0                    DWORD ?
NILW_INPUT ENDS

NILW_RESULT STRUCT
    status                       DWORD ?
    reserved0                    DWORD ?
    error_mask                   QWORD ?
    gate_mask                    QWORD ?
    calculated_payload_bits      QWORD ?
    calculated_reuse_bits        QWORD ?
    active_codec_bpw_num         QWORD ?
    active_codec_bpw_den         QWORD ?
    physicalization_num          QWORD ?
    physicalization_den          QWORD ?
    new_information_num          QWORD ?
    new_information_den          QWORD ?
    overhead_num                 QWORD ?
    overhead_den                 QWORD ?
    token_nilw_num               QWORD ?
    token_nilw_den               QWORD ?
    mean_payload_bytes_num       QWORD ?
    mean_payload_tokens_den      QWORD ?
    information_rate_bytes_num   QWORD ?
    information_rate_wall_ns_den QWORD ?
    generation_tps_tokens_num    QWORD ?
    generation_tps_wall_ns_den   QWORD ?
NILW_RESULT ENDS

IF (SIZEOF NILW_INPUT) NE 160
    .ERR <NILW_INPUT ABI size drift>
ENDIF
IF (SIZEOF NILW_RESULT) NE 168
    .ERR <NILW_RESULT ABI size drift>
ENDIF

NilwEvaluate              PROTO
NilwValidateShape         PROTO
NilwDeriveExact           PROTO
NilwApplyPerformanceGates PROTO
NilwApplyAuthorityGates   PROTO
NilwU128MulLE             PROTO
