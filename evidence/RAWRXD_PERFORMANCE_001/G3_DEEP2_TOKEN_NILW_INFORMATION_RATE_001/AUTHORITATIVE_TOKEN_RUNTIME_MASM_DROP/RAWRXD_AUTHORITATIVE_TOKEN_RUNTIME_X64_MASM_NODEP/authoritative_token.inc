option casemap:none

PROOF_NOT_RUN equ 0
PROOF_FAIL    equ 1
PROOF_PASS    equ 2

NILW_FORM_A   equ 1
NILW_FORM_B   equ 2

W01_ACTIVE_SUBSET      equ 0
W02_NEW_PAYLOAD        equ 1
W03_REUSE              equ 2
W04_OVERHEAD           equ 3
W05_FORM_SELECTION     equ 4
W06_ACTIVE_BPW         equ 5
W07_TOKEN_NILW         equ 6
W08_BANDWIDTH          equ 7
W09_TOKEN_RATE         equ 8
W10_PAYLOAD_PER_TOKEN  equ 9
W11_FULL_MATERIAL      equ 10
W12_QUALITY            equ 11
W13_LONGRUN            equ 12
W14_ACCOUNTING         equ 13
W15_AUTH_DERIVATION    equ 14
WITNESS_COUNT          equ 15

; Raw measurements only. No derived PASS state is accepted from caller.
RawTokenRuntime STRUCT
    form                        QWORD ?

    total_logical_weights       QWORD ?
    active_logical_weight_visits QWORD ?

    ; Form A raw numerator family
    active_representation_bits  QWORD ?
    new_information_bits        QWORD ?

    ; Form B raw numerator family
    new_payload_bits            QWORD ?

    overhead_bits               QWORD ?

    reused_bits                 QWORD ?
    reuse_events                QWORD ?

    generated_tokens            QWORD ?
    wall_ns                     QWORD ?

    full_model_materialization  QWORD ?
    full_layer_materialization  QWORD ?

    quality_samples             QWORD ?
    quality_failures            QWORD ?

    longrun_failures            QWORD ?
    payload_budget_overflow     QWORD ?
    stale_generation_faults     QWORD ?

    component_bits_sum          QWORD ?
    class_bits_sum              QWORD ?
    payload_bits_fetched        QWORD ?
    unaccounted_bits            QWORD ?

    ; Explicit measurement-event counters.
    active_subset_samples       QWORD ?
    overhead_samples            QWORD ?
RawTokenRuntime ENDS

DerivedTokenRuntime STRUCT
    active_bpw_x1e6             QWORD ?
    token_nilw_x1e9             QWORD ?
    physicalization_ppm         QWORD ?
    new_information_fraction_ppm QWORD ?

    total_new_bits              QWORD ?
    new_payload_bytes_per_token QWORD ?
    tps_x1000                   QWORD ?
    information_rate_Bps        QWORD ?

    witness_state               QWORD WITNESS_COUNT dup(?)

    passing_witnesses           QWORD ?
    failing_witnesses           QWORD ?
    notrun_witnesses            QWORD ?
    arithmetic_fault            QWORD ?
    authorized_pass             QWORD ?
DerivedTokenRuntime ENDS

AuthoritativeTokenEvaluate PROTO
SetWitness PROTO
MulDivU64 PROTO
