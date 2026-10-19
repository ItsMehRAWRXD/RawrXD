option casemap:none

TE_NOT_RUN equ 0
TE_FAIL    equ 1
TE_PASS    equ 2

TE01_GENERATION_BOUND          equ 0
TE02_GENERATED_NONZERO         equ 1
TE03_REQUEST_CLOSURE           equ 2
TE04_TOKENCODE_CLOSURE         equ 3
TE05_INPUT_CLOSURE             equ 4
TE06_OUTPUT_CLOSURE            equ 5
TE07_VOCAB_BOUNDS              equ 6
TE08_ENCODE_COMMIT_CLOSURE     equ 7
TE09_NO_DUPLICATE_ENCODE       equ 8
TE10_MONOTONIC_POSITION_SPAN   equ 9
TE11_POSITION_OBSERVATION      equ 10
TE12_DECODE_ROUNDTRIP          equ 11
TE13_OUTPUT_BYTES_CLOSURE      equ 12
TE14_BUFFER_AND_ERROR_FREE     equ 13
TE15_AUTH_DERIVATION           equ 14

TE_WITNESS_COUNT               equ 15

TokenCodeRaw STRUCT
    generation_id               QWORD ?
    observation_epoch           QWORD ?

    generated                   QWORD ?
    encode_request_count        QWORD ?
    tokencode_count             QWORD ?
    token_input_count           QWORD ?
    token_output_count          QWORD ?

    vocab_size                  QWORD ?
    min_token_id                QWORD ?
    max_token_id                QWORD ?
    out_of_vocab_count          QWORD ?

    encode_commit_count         QWORD ?
    duplicate_encode_count      QWORD ?

    first_position              QWORD ?
    last_position               QWORD ?
    position_observation_count  QWORD ?

    decode_roundtrip_count      QWORD ?
    roundtrip_mismatch_count    QWORD ?

    output_bytes_expected       QWORD ?
    output_bytes_written        QWORD ?

    buffer_overflow_count       QWORD ?
    encode_error_count          QWORD ?
    stale_generation_faults     QWORD ?
    nonfinite_state_count       QWORD ?

    run_observed                QWORD ?
TokenCodeRaw ENDS

TokenCodeResult STRUCT
    witness_state               QWORD TE_WITNESS_COUNT dup(?)
    passing_witnesses           QWORD ?
    failing_witnesses           QWORD ?
    notrun_witnesses            QWORD ?
    tokencode_authorized        QWORD ?
TokenCodeResult ENDS

TokenCodeEvaluate PROTO
