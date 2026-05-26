; Sovereign_Telemetry.inc
EXTERNDEF Titan_Peak_Cycles : QWORD
EXTERNDEF Titan_Peak_ID     : QWORD

; Peak Tracker Constants
sizeof_HOTPATCH_TABLE EQU 32
offsetof_Hotpatch_Pool EQU 8
sizeof_GGUF_ARENA      EQU 32
offsetof_GGUF_Pool      EQU 3208

HOTPATCH_TABLE STRUCT
    Status dq ?
    pCallback dq ?
    Linked_Arena_ID dq ?
    Reserved dq ?
HOTPATCH_TABLE ENDS

GGUF_ARENA STRUCT
    Status dq ?
    Base_Ptr dq ?
    ArenaSize dq ?
    ModelID dq ?
GGUF_ARENA ENDS
