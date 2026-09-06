; Deep2Device.inc — topology-agnostic adapter scoring (x64 MASM)
OPTION CASEMAP:NONE

; Score bands (higher = better compute candidate)
DEV_SCORE_IGPU_MAX      EQU 10
DEV_SCORE_DISCRETE_BASE EQU 100

; Name hint flags (optional; scoring prefers VRAM)
DEV_NF_NAME_HINT_A      EQU 00000001h
DEV_NF_NAME_HINT_B      EQU 00000002h
DEV_NF_IGPU_HINT        EQU 00000004h

DEV_1GIB                EQU 40000000h
