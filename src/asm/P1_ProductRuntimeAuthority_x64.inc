; ============================================================================
; P1_ProductRuntimeAuthority_x64.inc
; P1_PRODUCT_RUNTIME_AUTHORITY_002
; NO DEPS / NO STUBS / PHYSICAL REQUEST LEDGER
; Windows x64 ABI
; ============================================================================

OPTION CASEMAP:NONE

P1PRA_MAGIC                 EQU 41525031h ; "1PRA"
P1PRA_VERSION               EQU 00020000h

P1PRA_STAGE_NONE            EQU 0
P1PRA_STAGE_USER_PROMPT     EQU 1
P1PRA_STAGE_ROUTER          EQU 2
P1PRA_STAGE_GGUF_OPEN       EQU 3
P1PRA_STAGE_WEIGHT_ACCESS   EQU 4
P1PRA_STAGE_FORWARD         EQU 5
P1PRA_STAGE_SAMPLE          EQU 6
P1PRA_STAGE_DECODE          EQU 7
P1PRA_STAGE_UI_EMIT         EQU 8

; ---------------------------------------------------------------------------
; State layout
; ---------------------------------------------------------------------------

P1PRA_OFF_MAGIC                 EQU 000h
P1PRA_OFF_VERSION               EQU 008h
P1PRA_OFF_REQUEST_SEQUENCE      EQU 010h
P1PRA_OFF_CURRENT_REQUEST_ID    EQU 018h
P1PRA_OFF_CURRENT_STAGE         EQU 020h
P1PRA_OFF_PROMPT_COUNT          EQU 028h
P1PRA_OFF_PROMPT_BYTES          EQU 030h
P1PRA_OFF_PROMPT_TSC            EQU 038h
P1PRA_OFF_PROMPT_PTR            EQU 040h

P1PRA_OFF_ROUTER_COUNT          EQU 048h
P1PRA_OFF_GGUF_OPEN_COUNT       EQU 050h
P1PRA_OFF_WEIGHT_BYTES          EQU 058h
P1PRA_OFF_FORWARD_COUNT         EQU 060h
P1PRA_OFF_SAMPLE_COUNT          EQU 068h
P1PRA_OFF_DECODE_BYTES          EQU 070h
P1PRA_OFF_UI_BYTES              EQU 078h

P1PRA_OFF_FINALIZE_COUNT        EQU 080h
P1PRA_OFF_FAILURE_FLAGS         EQU 088h
P1PRA_OFF_RESERVED_090          EQU 090h

P1PRA_STATE_SIZE               EQU 100h

; ---------------------------------------------------------------------------
; Failure bits
; ---------------------------------------------------------------------------

P1PRA_FAIL_BAD_STATE            EQU 0000000000000001h
P1PRA_FAIL_BAD_PROMPT           EQU 0000000000000002h
P1PRA_FAIL_BAD_STAGE            EQU 0000000000000004h
P1PRA_FAIL_INCOMPLETE           EQU 0000000000000008h
