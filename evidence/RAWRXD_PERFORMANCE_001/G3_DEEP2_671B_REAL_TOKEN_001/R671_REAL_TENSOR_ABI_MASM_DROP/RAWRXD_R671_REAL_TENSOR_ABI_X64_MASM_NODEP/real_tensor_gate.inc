option casemap:none
include r671_abi.inc

RealTensorGateRaw STRUCT
    real_model                  QWORD ?
    synthetic_tensor            QWORD ?
    r671_acquire_count          QWORD ?
    r671_failed_acquires        QWORD ?
    full_tensor_fallback_count  QWORD ?
    wsc15_pass                  QWORD ?
    working_set_contract_pass   QWORD ?
    tokencode_authorized        QWORD ?
    tokensdecoded_authorized    QWORD ?
    generated_tokens            QWORD ?
    token_commit_count          QWORD ?
    decode_commit_count         QWORD ?
    peak_mapped_bytes           QWORD ?
    configured_bound            QWORD ?
    newly_mapped_bytes          QWORD ?
    stale_generation_faults     QWORD ?
    duplicate_commit_count      QWORD ?
    nonfinite_output_count      QWORD ?
RealTensorGateRaw ENDS

RealTensorGateResult STRUCT
    pass                        QWORD ?
RealTensorGateResult ENDS

G3Deep2R671RealTokenEvaluate PROTO
