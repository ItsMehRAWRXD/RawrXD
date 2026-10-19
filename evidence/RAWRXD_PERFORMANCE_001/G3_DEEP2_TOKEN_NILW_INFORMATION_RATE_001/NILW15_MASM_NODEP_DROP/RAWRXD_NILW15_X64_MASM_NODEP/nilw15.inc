option casemap:none

PROOF_NOT_RUN equ 0
PROOF_FAIL    equ 1
PROOF_PASS    equ 2

NILW_FORM_A   equ 1
NILW_FORM_B   equ 2

WIT_ACTIVE_SUBSET      equ 0
WIT_NEW_PAYLOAD        equ 1
WIT_REUSE              equ 2
WIT_OVERHEAD           equ 3
WIT_FORM_SELECTION     equ 4
WIT_ACTIVE_BPW         equ 5
WIT_TOKEN_NILW         equ 6
WIT_BANDWIDTH          equ 7
WIT_TOKEN_RATE         equ 8
WIT_PAYLOAD_PER_TOKEN  equ 9
WIT_FULL_MATERIAL      equ 10
WIT_QUALITY            equ 11
WIT_LONGRUN            equ 12
WIT_ACCOUNTING         equ 13
WIT_AUTH_DERIVATION    equ 14
WITNESS_COUNT          equ 15

TOKEN_NILW_LIMIT_X1E9  equ 800000
PAYLOAD_BYTES_LIMIT    equ 100000000
TPS_X1000_MIN          equ 10000
INFO_RATE_BPS_MAX      equ 1000000000
TOKENS_MIN             equ 128

Nilw15Witness STRUCT
    form                        QWORD ?
    total_logical_weights       QWORD ?
    active_logical_weights      QWORD ?
    active_representation_bits  QWORD ?
    new_information_bits        QWORD ?
    new_payload_bits            QWORD ?
    overhead_bits               QWORD ?
    reused_bits                 QWORD ?
    reuse_events                QWORD ?
    generated_tokens            QWORD ?
    wall_ns                     QWORD ?
    run_new_payload_bytes       QWORD ?
    information_rate_bps        QWORD ?   ; OUTPUT derived
    tps_x1000                   QWORD ?   ; OUTPUT derived
    mean_payload_bytes_token    QWORD ?   ; OUTPUT derived
    full_model_materialization  QWORD ?
    full_layer_materialization  QWORD ?
    quality_metric_value        QWORD ?
    quality_baseline_value      QWORD ?
    quality_delta_value         QWORD ?
    longrun_failures            QWORD ?
    payload_budget_overflow     QWORD ?
    stale_generation_faults     QWORD ?
    component_bits_sum          QWORD ?   ; payload components only
    class_bits_sum              QWORD ?   ; payload classes only
    payload_bits_fetched        QWORD ?   ; payload only (excl overhead)
    unaccounted_bits            QWORD ?
    active_subset_measured      QWORD ?   ; OUTPUT derived
    reuse_measured              QWORD ?   ; OUTPUT derived
    overhead_accounted          QWORD ?   ; OUTPUT derived
    quality_gate_pass           QWORD ?   ; OUTPUT derived
    token_nilw_x1e9             QWORD ?   ; OUTPUT derived
    active_bpw_x1e6             QWORD ?   ; OUTPUT derived
    physicalization_ppm         QWORD ?   ; OUTPUT derived
    total_new_bits              QWORD ?   ; OUTPUT derived
    witness_state               QWORD WITNESS_COUNT dup(?)
Nilw15Witness ENDS

Nilw15Result STRUCT
    authorized_pass             QWORD ?
    passing_witnesses           QWORD ?
    failing_witnesses           QWORD ?
    notrun_witnesses            QWORD ?
Nilw15Result ENDS

; rcx=num rdx=scale r8=den → rax=quot; CF=1 fail
Nilw15MulDiv PROTO
Nilw15FormNumerator PROTO
Nilw15DeriveRates PROTO
Nilw15DeriveWitnesses PROTO
Nilw15Evaluate PROTO
