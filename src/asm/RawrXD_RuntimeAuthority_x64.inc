; ============================================================================
; RawrXD_RuntimeAuthority_x64.inc
; Verifiable Autonomous Runtime Authority
; Pure x64 / MASM / caller-owned storage / no CRT / no heap / no imports
; ============================================================================

RA_AUTH_MAGIC            EQU 5241575258415544h
RA_AUTH_VERSION          EQU 00010000h

RA_STATE_BASE            EQU 00h
RA_STATE_CAPACITY        EQU 08h
RA_STATE_HEAD            EQU 10h
RA_STATE_SEQUENCE        EQU 18h
RA_STATE_KEY0            EQU 20h
RA_STATE_KEY1            EQU 28h
RA_STATE_PREV_TAG        EQU 30h
RA_STATE_DROPPED         EQU 38h
RA_STATE_MAGIC           EQU 40h
RA_STATE_VERSION         EQU 48h
RA_STATE_SIZE            EQU 50h

RA_REC_SEQUENCE          EQU 00h
RA_REC_TSC               EQU 08h
RA_REC_KIND              EQU 10h
RA_REC_STAGE             EQU 14h
RA_REC_ARG0              EQU 18h
RA_REC_ARG1              EQU 20h
RA_REC_ARG2              EQU 28h
RA_REC_PREV_TAG          EQU 30h
RA_REC_TAG               EQU 38h
RA_REC_SIZE              EQU 40h

RA_EVT_MODEL_LOAD        EQU 00000001h
RA_EVT_PROMPT_ACCEPT     EQU 00000002h
RA_EVT_INFERENCE_BEGIN   EQU 00000003h
RA_EVT_INFERENCE_END     EQU 00000004h
RA_EVT_TOOL_PROPOSE      EQU 00000010h
RA_EVT_TOOL_ALLOW        EQU 00000011h
RA_EVT_TOOL_DENY         EQU 00000012h
RA_EVT_TOOL_EXECUTE      EQU 00000013h
RA_EVT_FILE_READ         EQU 00000020h
RA_EVT_FILE_WRITE        EQU 00000021h
RA_EVT_FILE_DELETE       EQU 00000022h
RA_EVT_HOTPATCH          EQU 00000023h
RA_EVT_ROLLBACK          EQU 00000024h
RA_EVT_BUILD             EQU 00000030h
RA_EVT_TEST              EQU 00000031h
RA_EVT_DECODE            EQU 00000040h
RA_EVT_UI_EMIT           EQU 00000041h
RA_EVT_FAULT             EQU 000000F0h
RA_EVT_SHUTDOWN          EQU 000000FFh

; Symbols defined in RawrXD_RuntimeAuthority_x64.asm