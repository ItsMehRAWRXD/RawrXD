; ==================================================================================

; SOVEREIGN CONFIGURATION SUBSTRATE - SECURITY DEFINITIONS

; File: Sovereign_Security.inc

; Architecture: x64 MASM Monolith (Zero-IAT, Strict 64-bit Slot ABI)

; ==================================================================================



IFNDEF SOVEREIGN_SECURITY_INC

SOVEREIGN_SECURITY_INC EQU 1



; --- Cryptographic Primitives ---

SOVEREIGN_SECRET        EQU 041534D5F454C4954h ; 'ASM_ELIT'

SOVEREIGN_SALT          EQU 09E3779B97F4A7C15h ; Symmetrical Golden Ratio Substrate Expansion



; --- Feature Bitfield Matrix ---

FEATURE_BASE_ENGINE     EQU 00000001h

FEATURE_PRO_TIER        EQU 00000002h

FEATURE_ENTERPRISE_TIER EQU 00000004h

FEATURE_800B_MODEL      EQU 00000008h

FEATURE_SWARM_MODE      EQU 00000010h

FEATURE_ALL_ENABLED     EQU 0000001Fh ; Full-spectrum active deployment capability mask



; --- Cache-Line Aligned Struct Layout ---

LICENSE_METADATA STRUCT

    HardwareID      QWORD 0

    FeatureMask     QWORD 0

    Signature       QWORD 0

    ExpiryTimestamp QWORD 0

    Padding         QWORD 4 DUP(0) ; Guarantees strict 64-byte structural cache isolation

LICENSE_METADATA ENDS

; --- Arena Integrity Definitions ---
SOVEREIGN_MAGIC_BYTES   EQU 5241575258444E54h ; 'RAWRXDNT'
SOVEREIGN_SCHEMA_VER    EQU 0000000000000001h

SOVEREIGN_ARENA_HEADER STRUCT
    Magic           QWORD 0
    Version         QWORD 0
    ArenaSize       QWORD 0
    Canary          QWORD 0
    Padding         QWORD 4 DUP(0) ; Guarantees strict 64-byte structural cache isolation
SOVEREIGN_ARENA_HEADER ENDS

KERNEL_ENTRY STRUCT
    BaseAddress     DQ ?
    ImageSize       DQ ?
    EntryPoint      DQ ?
    Checksum        DQ ?
KERNEL_ENTRY ENDS

SOVEREIGN_SECURITY_CONTEXT STRUCT
    Dynamic_Signature DQ 4 DUP(0)     ; 32-byte dynamic runtime signature
    Entropy_Pool      DQ 16 DUP(0)    ; 128-byte pool
    Kernel_Data       KERNEL_ENTRY <> ; Kernel entry metadata
    Entropy_Index     DQ 0
SOVEREIGN_SECURITY_CONTEXT ENDS

; --- Telemetry Buffer ---
TELEMETRY_BUFFER STRUCT
    Global_Tick      DQ ?        ; 00h: Tick/Cycle Count
    Signature_Snap   DQ 4 DUP(?) ; 08h: Snapshot of Dynamic_Signature
    Lane0_Result     DQ ?        ; 28h: First QWORD of Lane 0's Slab
    System_Status    DQ ?        ; 30h: The Handshake Signal
    Buffer_Padding   DQ 2 DUP(?) ; Align to 64 bytes for cache-line friendliness
TELEMETRY_BUFFER ENDS

; --- Fabric Context Mask (Pinned to R15) ---
SOVEREIGN_FABRIC_CONTEXT STRUCT
    Beacon_Registers    QWORD 8 DUP(0) ; +00h: L1 Cache-resident telemetry (64B)
    Tensor_Arena_Base   QWORD 0        ; +40h: Pointer to start of the Arena Header
    Tensor_Arena_Size   QWORD 0        ; +48h: Total bytes (Header + Payload)
    Fabric_Status       QWORD 0        ; +50h: Status/Error Bitmask
    Current_Task_ID     QWORD 0        ; +58h: Scheduler state
    Fence_State         QWORD 0        ; +60h: Barrier sync state
    Rolling_Signature   QWORD 0        ; +68h: Active rotational task secret
    Rotation_Salt       QWORD 0        ; +70h: Entropy anchor for rotation
    Tick_Count          QWORD 0        ; +78h: Global epoch counter
    Screen_Width        QWORD 0        ; +80h: Width of Ray-Marching Viewport
    Screen_Height       QWORD 0        ; +88h: Height of Ray-Marching Viewport
    Security_Context    SOVEREIGN_SECURITY_CONTEXT <> 
    Worker_Ready_Count  QWORD 0        ; Incremented by workers on start
    Telemetry           TELEMETRY_BUFFER <>
SOVEREIGN_FABRIC_CONTEXT ENDS

; --- Core Monolith Substrate API Links ---
EXTERN Sovereign_Generate_Key : PROC

EXTERNDEF Sovereign_Get_Hardware_ID : PROC
EXTERNDEF Sovereign_Verify_License  : PROC
EXTERNDEF Verify_Arena_Integrity : PROC
EXTERNDEF Sovereign_Rotate_Signature : PROC
EXTERNDEF Compute_Result_MAC : PROC
EXTERNDEF Verify_Task_Receipt : PROC
EXTERNDEF Fabric_Safe_Init : PROC

ENDIF

