option casemap:none

DEEP2_GATE_MAGIC              EQU 3245544147503244h ; "D2PGATE2" little-endian-ish sentinel
DEEP2_GATE_VERSION            EQU 00010000h

; Permanent policy constants. SI units intentionally make 100 MB/token * 10 TPS = 1 GB/s exactly.
DEEP2_BYTES_PER_TOKEN_MAX     EQU 100000000
DEEP2_BYTES_PER_SEC_MAX       EQU 1000000000
DEEP2_TPS_MILLI_MIN           EQU 10000          ; 10.000 TPS
DEEP2_WINDOW_TOKENS_MIN       EQU 128
DEEP2_NILW_NUM                EQU 1
DEEP2_NILW_DEN                EQU 1250           ; 1/1250 = 0.0008 exactly

; Q4 is a witness only, never policy authority:
; (4000/1000) * (5/1000) * (4/100) = 1/1250 = 0.0008
DEEP2_Q4_BPW_NUM              EQU 4000
DEEP2_Q4_BPW_DEN              EQU 1000
DEEP2_Q4_PHYS_NUM             EQU 5
DEEP2_Q4_PHYS_DEN             EQU 1000
DEEP2_Q4_INFO_NUM             EQU 4
DEEP2_Q4_INFO_DEN             EQU 100

GatePolicy STRUCT
    magic               QWORD ?
    version             QWORD ?
    bytesPerTokenMax    QWORD ?
    bytesPerSecMax      QWORD ?
    tpsMilliMin         QWORD ?
    windowTokensMin     QWORD ?
    nilwNum             QWORD ?
    nilwDen             QWORD ?
GatePolicy ENDS

RuntimeSample STRUCT
    bytesPerToken       QWORD ?
    bytesPerSec         QWORD ?
    tpsMilli            QWORD ?
    windowTokens        QWORD ?
    nilwNum             QWORD ?
    nilwDen             QWORD ?
RuntimeSample ENDS

GateResult STRUCT
    passMask            QWORD ?
    failMask            QWORD ?
    policyValid         QWORD ?
    fixtureQ4Valid      QWORD ?
GateResult ENDS

GATE_BIT_BYTES_PER_TOKEN EQU 0001h
GATE_BIT_BYTES_PER_SEC   EQU 0002h
GATE_BIT_TPS             EQU 0004h
GATE_BIT_WINDOW          EQU 0008h
GATE_BIT_NILW            EQU 0010h
GATE_ALL_BITS            EQU 001Fh

Deep2FixedGatePolicy_Init        PROTO
Deep2FixedGatePolicy_Validate    PROTO
Deep2FixedGatePolicy_Q4Witness   PROTO
Deep2FixedGatePolicy_Evaluate    PROTO
