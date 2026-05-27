; ==============================================================================
; SOVEREIGN_TYPES.INC
; Architectural memory contracts and magic constants.
; ==============================================================================

SOVEREIGN_MAGIC_BYTES EQU 5241575258444E54h ; 'RAWRXDNT'
SOVEREIGN_SCHEMA_VER  EQU 0000000000000001h
SOVEREIGN_LANE_COUNT  EQU 16

; Ray-Marching Framebuffer Configuration
SCREEN_WIDTH          EQU 160
SCREEN_HEIGHT         EQU 128
BYTES_PER_PIXEL       EQU 4
LANE_ROW_COUNT        EQU 8  ; 128 / 16
SOVEREIGN_SLAB_SIZE   EQU 5120 ; 160 * 8 * 4
TOTAL_ARENA_SIZE      EQU 81920 ; 160 * 128 * 4

SOVEREIGN_ARENA_HEADER STRUCT
    Magic       QWORD ?
    Version     QWORD ?
    ArenaSize   QWORD ?
    Canary      QWORD ?
    Padding     QWORD 4 DUP(0) ; Cache-line isolation
SOVEREIGN_ARENA_HEADER ENDS

SOVEREIGN_LANE STRUCT
    Status          QWORD 0 ; 0: Idle, 1: Ready, 2: Busy, 3: Waiting
    Slab_Offset     QWORD 0 ; Pointer to this lane's 256B slab
    Cycle_Count     QWORD 0 ; Local telemetry
    Lane_Reserved   QWORD 5 DUP(0) ; Align to 64-byte cache line
SOVEREIGN_LANE ENDS

SOVEREIGN_HUD_HEADER STRUCT
    Signature   QWORD ? ; 'RAWRHUD0' (3044554852574152h)
    FrameCount  QWORD ? ; Monotonically increasing tick
    DataOffset  QWORD ? ; Offset from buffer start to ASCII payload
    DataSize    QWORD ? ; Length of the ASCII payload
    Padding     QWORD 4 DUP(0) ; 64-byte isolation alignment
SOVEREIGN_HUD_HEADER ENDS

SOVEREIGN_FABRIC_CONTEXT STRUCT
    Beacon_Registers  QWORD 8 DUP(0) ; +00h
    Tensor_Arena_Base QWORD 0        ; +40h
    Tensor_Arena_Size QWORD 0        ; +48h
    Fabric_Status     QWORD 0        ; +50h
    Current_Task_ID   QWORD 0        ; +58h
    Fence_State       QWORD 0        ; +60h (Global Barrier Sync)
    Lanes             SOVEREIGN_LANE SOVEREIGN_LANE_COUNT DUP(<>)
SOVEREIGN_FABRIC_CONTEXT ENDS

; Export for linking
EXTERNDEF g_FabricContext : SOVEREIGN_FABRIC_CONTEXT
