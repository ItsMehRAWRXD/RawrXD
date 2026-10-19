option casemap:none

PROOF_NOT_RUN equ 0
PROOF_FAIL    equ 1
PROOF_PASS    equ 2

PATH_NONE     equ 0
PATH_HOST     equ 1
PATH_GPU      equ 2
PATH_MIXED    equ 3

D01_PRODUCT_OPEN       equ 0
D02_SESSION_ENTER      equ 1
D03_DECODE_ENTER       equ 2
D04_LAYER_FORWARD      equ 3
D05_LMHEAD             equ 4
D06_LOGITS             equ 5
D07_TOKEN_SELECT       equ 6
D08_TOKEN_COMMIT       equ 7
D09_STEP_MONOTONIC     equ 8
D10_NO_DUP_COMMIT      equ 9
D11_OUTPUT_PROGRESS    equ 10
D12_ERROR_FREE         equ 11
D13_SINGLE_PATH_AUTH   equ 12
D14_COUNT_CLOSURE      equ 13
D15_AUTH_DERIVATION    equ 14
DECODE_WITNESS_COUNT   equ 15

RawDecodeRuntime STRUCT
    product_open_attempts      QWORD ?
    product_open_success       QWORD ?

    session_enter_attempts     QWORD ?
    session_enter_success      QWORD ?

    decode_enter_count         QWORD ?
    decode_exit_count          QWORD ?

    requested_tokens           QWORD ?
    generated_tokens           QWORD ?

    layer_forward_calls        QWORD ?
    expected_layer_forwards    QWORD ?

    lmhead_calls               QWORD ?
    logits_ready_count         QWORD ?
    token_select_count         QWORD ?
    token_commit_count         QWORD ?

    first_step_id              QWORD ?
    last_step_id               QWORD ?
    step_observation_count     QWORD ?
    step_regression_count      QWORD ?

    duplicate_commit_count     QWORD ?
    zero_token_commit_count    QWORD ?

    decode_fault_count         QWORD ?
    av_count                   QWORD ?
    heap_fault_count           QWORD ?

    host_forward_calls         QWORD ?
    gpu_forward_calls          QWORD ?
    declared_path              QWORD ?

    output_bytes               QWORD ?
    output_tokens_visible      QWORD ?

    full_model_materialization QWORD ?
    full_layer_materialization QWORD ?
RawDecodeRuntime ENDS

DerivedDecodeRuntime STRUCT
    witness_state              QWORD DECODE_WITNESS_COUNT dup(?)

    passing_witnesses          QWORD ?
    failing_witnesses          QWORD ?
    notrun_witnesses           QWORD ?

    count_closure_delta        QWORD ?
    decode_authorized          QWORD ?
DerivedDecodeRuntime ENDS

AuthoritativeDecodeEvaluate PROTO
