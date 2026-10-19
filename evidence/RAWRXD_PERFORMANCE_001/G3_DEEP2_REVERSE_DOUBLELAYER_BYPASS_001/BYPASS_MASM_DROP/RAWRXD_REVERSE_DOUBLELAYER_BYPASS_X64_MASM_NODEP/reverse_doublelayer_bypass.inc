option casemap:none

RDL_FALSE equ 0
RDL_TRUE  equ 1

RDLRaw STRUCT
    generation_id                    QWORD ?

    scheduler_epoch                  QWORD ?
    token_epoch                      QWORD ?
    decode_epoch                     QWORD ?
    working_set_epoch                QWORD ?
    quality_epoch                    QWORD ?
    tensor_math_epoch                QWORD ?

    ; Normal positive-owner evidence.
    scheduler_authorized             QWORD ?
    token_authorized                 QWORD ?
    decode_authorized                QWORD ?
    working_set_authorized           QWORD ?
    quality_authorized               QWORD ?
    tensor_math_authorized           QWORD ?

    ; Product closure.
    product_open                     QWORD ?
    session_enter                    QWORD ?
    generated_tokens                 QWORD ?
    token_commit_count               QWORD ?
    decode_commit_count              QWORD ?

    ; Absolute stale-generation veto.
    stale_generation_faults          QWORD ?

    ; Explicit bypass lane.
    bypass_request                   QWORD ?
    bypass_epoch                     QWORD ?
    bypass_live_generation           QWORD ?
    bypass_token_commit_count        QWORD ?
    bypass_decode_commit_count       QWORD ?
    bypass_fault_count               QWORD ?
RDLRaw ENDS

RDLResult STRUCT
    normal_owner_ready               QWORD ?
    generation_coherent              QWORD ?
    product_closure                  QWORD ?

    bypass_generation_bound          QWORD ?
    bypass_commit_closure            QWORD ?
    bypass_fault_free                QWORD ?
    bypass_authorized                QWORD ?

    stale_generation_veto            QWORD ?
    final_authority                  QWORD ?
RDLResult ENDS

ReverseDoubleLayerEvaluate PROTO
