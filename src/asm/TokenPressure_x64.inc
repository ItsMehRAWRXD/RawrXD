; ============================================================================
; TokenPressure_x64.inc — TOKEN_PRESSURE_VALVE_001
; ============================================================================
OPTION CASEMAP:NONE

TP_MAGIC                    EQU 50544B31h ; "1KTP"
TP_VERSION                  EQU 00010000h
TP_STATE_SIZE               EQU 100h

TP_OFF_MAGIC                EQU 000h
TP_OFF_VERSION              EQU 008h
TP_OFF_WIN0                 EQU 010h
TP_OFF_WIN_COUNT            EQU 050h
TP_OFF_REPEAT               EQU 058h
TP_OFF_STALL                EQU 060h
TP_OFF_CODE                 EQU 068h
TP_OFF_SPRAY                EQU 070h
TP_OFF_LAST_ACTION          EQU 078h
TP_OFF_FENCE_OPEN           EQU 080h

TP_ACT_PASS                 EQU 0
TP_ACT_PENALIZE_REPEAT      EQU 1
TP_ACT_PREFER_STOP          EQU 2
TP_ACT_STOP_REQUEST         EQU 3

TP_SPRAY_NEEDLE             EQU 0
TP_SPRAY_MIST               EQU 1
TP_SPRAY_PULSE              EQU 2
TP_SPRAY_RINSE              EQU 3
TP_SPRAY_CUTOFF             EQU 4
TP_SPRAY_REPAIR             EQU 5

TP_FLAG_NEWLINE             EQU 1
TP_FLAG_FENCE               EQU 2
TP_FLAG_BRACE               EQU 4
TP_FLAG_FILLER              EQU 8
