option casemap:none

TID_NOT_RUN equ 0
TID_FAIL    equ 1
TID_PASS    equ 2

TOKEN_ID_MODE_BOUNDED  equ 1
TOKEN_ID_MODE_U64_FULL equ 2

TokenIdRaw STRUCT
    generation_id              QWORD ?
    observation_epoch          QWORD ?
    generated                  QWORD ?

    token_id_mode              QWORD ?

    ; BOUNDED mode:
    ; valid IDs are [vocab_base_id, vocab_base_id + vocab_count)
    vocab_base_id              QWORD ?
    vocab_count                QWORD ?

    ; Observed runtime token-ID facts.
    token_id_check_count       QWORD ?
    min_observed_token_id      QWORD ?
    max_observed_token_id      QWORD ?
    out_of_vocab_count         QWORD ?
    negative_token_id_count    QWORD ?
    token_id_decode_mismatch   QWORD ?
    token_id_encode_mismatch   QWORD ?

    run_observed               QWORD ?
TokenIdRaw ENDS

TokenIdResult STRUCT
    generation_bound           QWORD ?
    mode_valid                 QWORD ?
    checks_complete            QWORD ?
    range_valid                QWORD ?
    no_oov                     QWORD ?
    no_negative_reinterpret    QWORD ?
    roundtrip_ids_match        QWORD ?
    token_id_authorized        QWORD ?

    bounded_end_exclusive      QWORD ?
    arithmetic_fault           QWORD ?
TokenIdResult ENDS

TokenIdEvaluate PROTO
