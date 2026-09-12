; ============================================================================
; Deep2 full-decode token ABI — x64 MASM, no third-party dependencies
; This ABI deliberately contains NO TPS authority.
; Runtime flags are observations produced only after executed callback paths.
; ============================================================================

D2DEC_MAGIC             EQU 3243454432503244h    ; opaque ABI magic
D2DEC_VERSION           EQU 00010000h
D2DEC_CTX_SIZE          EQU 144
D2DEC_BIND_SIZE         EQU 32

; Deep2DecodeBinding
D2_BIND_USER_CTX        EQU 0
D2_BIND_FORWARD_FN      EQU 8
D2_BIND_COMMIT_FN       EQU 16
D2_BIND_ADVANCE_FN      EQU 24

; Deep2DecodeContext
D2_CTX_MAGIC            EQU 0       ; qword
D2_CTX_VERSION          EQU 8       ; dword
D2_CTX_SIZE             EQU 12      ; dword
D2_CTX_USER_CTX         EQU 16      ; qword
D2_CTX_FORWARD_FN       EQU 24      ; qword
D2_CTX_COMMIT_FN        EQU 32      ; qword
D2_CTX_ADVANCE_FN       EQU 40      ; qword
D2_CTX_POSITION         EQU 48      ; qword
D2_CTX_GENERATED        EQU 56      ; qword
D2_CTX_FORWARD_CALLS    EQU 64      ; qword
D2_CTX_COMMIT_CALLS     EQU 72      ; qword
D2_CTX_ADVANCE_CALLS    EQU 80      ; qword
D2_CTX_LAST_TOKEN       EQU 88      ; qword
D2_CTX_LAST_LOGITS      EQU 96      ; qword
D2_CTX_LAST_VOCAB       EQU 104     ; qword
D2_CTX_RUNTIME_FLAGS    EQU 112     ; qword
D2_CTX_ERROR_CODE       EQU 120     ; dword
D2_CTX_RESERVED0        EQU 124     ; dword
D2_CTX_TARGET_TOKENS    EQU 128     ; qword
D2_CTX_RESERVED1        EQU 136     ; qword

; Observed runtime flags. None may be set by declarations/config alone.
D2_FLAG_FULL_FORWARD_OBSERVED EQU 0000000000000001h
D2_FLAG_TOKEN_SELECTED        EQU 0000000000000002h
D2_FLAG_TOKEN_COMMITTED       EQU 0000000000000004h
D2_FLAG_STATE_ADVANCED        EQU 0000000000000008h
D2_FLAG_FULL_DECODE_OBSERVED  EQU 0000000000000010h
D2_REQUIRED_FULL_DECODE_FLAGS EQU 000000000000001Fh

; Error codes
D2_ERR_NONE              EQU 0
D2_ERR_BAD_CONTEXT       EQU 1
D2_ERR_BAD_ABI           EQU 2
D2_ERR_BAD_BINDING       EQU 3
D2_ERR_BAD_TARGET        EQU 4
D2_ERR_FORWARD_FAILED    EQU 5
D2_ERR_BAD_LOGITS        EQU 6
D2_ERR_SELECT_FAILED     EQU 7
D2_ERR_COMMIT_FAILED     EQU 8
D2_ERR_ADVANCE_FAILED    EQU 9
D2_ERR_COUNTER_MISMATCH  EQU 10

; Callback ABI (Microsoft x64):
;
; ForwardFn(
;   RCX = user_ctx,
;   RDX = absolute decode position,
;   R8  = qword* out_logits_f32,
;   R9  = qword* out_vocab_count
; ) -> EAX = 1 success, 0 failure
;
; Required contract:
;   out_logits_f32 points at the REAL logits produced from the completed
;   full-model forward + final norm + LM head for this position.
;   The decode module never fabricates or substitutes logits.
;
; CommitFn(
;   RCX = user_ctx,
;   RDX = token_id,
;   R8  = absolute decode position,
;   R9  = 0
; ) -> EAX = 1 only after the real token commit succeeded
;
; AdvanceFn(
;   RCX = user_ctx,
;   RDX = token_id,
;   R8  = next absolute position,
;   R9  = 0
; ) -> EAX = 1 only after autoregressive input/KV state is ready for next step
;
; No callback may claim success merely because work was scheduled.
