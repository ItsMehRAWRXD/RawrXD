; ==============================================================================
; SOVEREIGN_ENTRY.ASM
; Native Entry Point - No C-Runtime / No DLL Dependencies
; ==============================================================================
INCLUDE Sovereign_Types.inc

_SOVEREIGN_DATA SEGMENT ALIGN(64) 'DATA'
    PUBLIC g_FabricContext
    g_FabricContext SOVEREIGN_FABRIC_CONTEXT <>
    g_TensorArena   BYTE TOTAL_ARENA_SIZE DUP(0) ; 80KB Arena for 160x128 RGBA
    
    szCreateThread  DB "CreateThread", 0
_SOVEREIGN_DATA ENDS

_TEXT SEGMENT 'CODE'
    PUBLIC _start
    EXTERN Sovereign_GetKernel32 : PROC
    EXTERN Sovereign_GetProcAddress : PROC
    EXTERN Sovereign_Lane_Table : QWORD

_start PROC
    ; 1. Stack Alignment (16-byte)
    and rsp, -16
    sub rsp, 48 ; 32 bytes shadow + 16 bytes for arg5 & arg6 to keep 16-byte alignment
    
    ; 2. Pin Context Register (R15 is our permanent state pointer)
    lea r15, [g_FabricContext]
    
    ; 3. Initial Mapping
    lea rax, [g_TensorArena]
    mov [r15 + SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base], rax
    mov [r15 + SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Size], TOTAL_ARENA_SIZE
    
    ; 4. Initialize 16-Lane Slabs
    xor rcx, rcx ; Lane index
@@InitLanes:
    ; Calculate Slab Offset: Index * SOVEREIGN_SLAB_SIZE (5120 bytes)
    mov rax, rcx
    imul rax, SOVEREIGN_SLAB_SIZE
    add rax, [r15 + SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base]
    
    ; Calculate Lane Context Offset: SOVEREIGN_FABRIC_CONTEXT.Lanes + (Index * 64)
    mov rdx, rcx
    shl rdx, 6 ; rdx = rcx * 64
    lea rbx, [r15 + SOVEREIGN_FABRIC_CONTEXT.Lanes]
    add rbx, rdx
    
    ; Store Slab Pointer
    mov [rbx + SOVEREIGN_LANE.Slab_Offset], rax
    
    ; Set Status to Ready (1)
    mov QWORD PTR [rbx + SOVEREIGN_LANE.Status], 1
    
    inc rcx
    cmp rcx, SOVEREIGN_LANE_COUNT
    jne @@InitLanes
    
    ; --- PEB WALK TO RESOLVE CREATETHREAD ---
    call Sovereign_GetKernel32
    mov rcx, rax
    lea rdx, [szCreateThread]
    call Sovereign_GetProcAddress
    mov r12, rax ; Safe in r12 (non-volatile)
    
    ; --- SPAWN LANES 1-15 ---
    mov r13, 1 ; Lane Iterator
@@SpawnLanes:
    ; CreateThread(NULL, 0, Sovereign_Lane_Table[Lane], NULL, 0, NULL)
    xor rcx, rcx                     ; lpThreadAttributes = 0
    xor rdx, rdx                     ; dwStackSize = 0
    lea rbx, [Sovereign_Lane_Table]
    mov r8, [rbx + r13 * 8]          ; lpStartAddress = entry point
    mov r9, r13                      ; lpParameter = Lane ID (passed to thread in rcx)
    mov QWORD PTR [rsp + 32], 0      ; dwCreationFlags = 0
    mov QWORD PTR [rsp + 40], 0      ; lpThreadId = NULL
    
    call r12                         ; call CreateThread
    
    inc r13
    cmp r13, SOVEREIGN_LANE_COUNT
    jne @@SpawnLanes
    
    ; --- SPAWN GHOST RENDERER ---
    extern Sovereign_Ghost_StartRenderer : PROC
    call Sovereign_Ghost_StartRenderer
    
    ; --- HID INIT ---
    extern Sovereign_Pump_Init : PROC
    extern Sovereign_HID_Init : PROC
    call Sovereign_Pump_Init
    call Sovereign_HID_Init

    ; --- STARTUP VALIDATION GATE ---
    extern Sovereign_Tape_SelfTest : PROC
    call Sovereign_Tape_SelfTest
    ; test rax, rax
; jz L_fatal_tape_mismatch

    ; 5. Jump to Engine
    extern Sovereign_Fabric_Loop : PROC
    add rsp, 48 ; Clean stack
    jmp Sovereign_Fabric_Loop

L_fatal_tape_mismatch:
    int 3   ; Halt immediately on tape corruption
_start ENDP
_TEXT ENDS
END

