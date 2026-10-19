; deep2_lb.inc
; Pure x64 MASM, no CRT, no runtime dependency.
; Caller supplies timing samples; this module performs only integer math.

OPTION CASEMAP:NONE

D2LB_Q16_ONE              EQU 65536
D2LB_Q16_80_20_LANE1      EQU 13107       ; ~20.0% to slower lane (GPU1)
D2LB_Q16_MIN_LANE1        EQU 3277        ; 5.0%
D2LB_Q16_MAX_LANE1        EQU 32768       ; 50.0%
D2LB_EWMA_SHIFT           EQU 3           ; alpha = 1/8
D2LB_MIN_DEADBAND_NS      EQU 20000       ; 20 us
D2LB_ROLLBACK_PCT         EQU 105          ; >5% above best => pull toward best

D2LB_SAMPLE_VALID         EQU 00000001h
D2LB_SAMPLE_PARITY_OK     EQU 00000002h
D2LB_SAMPLE_DEVICE_OK     EQU 00000004h
D2LB_SAMPLE_REQUIRED      EQU 00000007h

D2LB_PLAN_DUAL_ACTIVE     EQU 00000001h
D2LB_PLAN_SINGLE_FALLBACK EQU 00000002h

; State layout, 128 bytes, caller-owned and naturally aligned.
D2LB_STATE STRUCT 16
    share1_q16            DWORD ? ; current slower-lane share
    best_share1_q16       DWORD ?
    min_share1_q16        DWORD ?
    max_share1_q16        DWORD ?

    samples_ok            DWORD ?
    samples_rejected      DWORD ?
    last_plan_flags       DWORD ?
    reserved0             DWORD ?

    ewma_nsrow0_q16       QWORD ?
    ewma_nsrow1_q16       QWORD ?
    last_duration0_ns     QWORD ?
    last_duration1_ns     QWORD ?
    last_skew_ns          QWORD ?
    last_critical_ns      QWORD ?
    best_critical_ns      QWORD ?
    last_overlap_ns       QWORD ?
    last_rows0            DWORD ?
    last_rows1            DWORD ?
    last_align_rows       DWORD ?
    reserved1             DWORD ?
D2LB_STATE ENDS

; Observation supplied after one same-token dual-lane launch.
D2LB_SAMPLE STRUCT 8
    rows0                 DWORD ?
    rows1                 DWORD ?
    flags                 DWORD ?
    reserved0             DWORD ?
    duration0_ns          QWORD ?
    duration1_ns          QWORD ?
    critical_ns           QWORD ? ; 0 => module uses max(duration0,duration1)
    overlap_ns            QWORD ?
D2LB_SAMPLE ENDS

D2LB_PLAN STRUCT 8
    rows0                 DWORD ?
    rows1                 DWORD ?
    share1_q16            DWORD ?
    flags                 DWORD ?
    predicted_ns0         QWORD ? ; 0 until EWMA exists
    predicted_ns1         QWORD ?
D2LB_PLAN ENDS

PUBLIC D2LbInit, D2LbPlan, D2LbObserve
; C prototypes (Windows x64 register ABI; no MASM PROTO — avoids A2111):
;   void D2LbInit(D2LB_STATE*);
;   void D2LbPlan(D2LB_STATE*, uint32_t totalRows, uint32_t alignRows, D2LB_PLAN*);
;   void D2LbObserve(D2LB_STATE*, const D2LB_SAMPLE*);
