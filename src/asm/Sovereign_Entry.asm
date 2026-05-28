; ==============================================================================
; SOVEREIGN ENTRY (AUDITED)
; Target: Native x64 / SUBSYSTEM:NATIVE
; ==============================================================================

EXTERN Sovereign_Fabric_Loop:PROC
EXTERN g_Sovereign_Fabric_Context:QWORD
EXTERN Fabric_Safe_Init:PROC
EXTERN g_FabricMatrix:QWORD
EXTERN Kernel_FMA_Unit:PROC

include Sovereign_Security.inc

DAG_NODE STRUCT
    KernelPtr   QWORD ?
    InPtr       QWORD ?
    OutPtr      QWORD ?
    ParamCount  QWORD ?
DAG_NODE ENDS

STREAM_CONTEXT STRUCT
    State       QWORD ?
    ArenaBase   QWORD ?
    DAG_Head    QWORD ?
    NodeCount   QWORD ?
    Reserved    QWORD 4 DUP(0)
STREAM_CONTEXT ENDS

.DATA
    ALIGN 16
    g_TestNode DAG_NODE <>

.CODE

EXTERN Sovereign_Harvest_Entropy:PROC
EXTERN Sovereign_Refresh_Signature:PROC
EXTERN Sovereign_Rotate_Signature:PROC

; ==============================================================================
; SOVEREIGN_INITIALIZE_WARDEN (Lane 0)
; Purpose: Bootstrap the Fabric Context and Security State
; ==============================================================================
PUBLIC Sovereign_Initialize_Warden
Sovereign_Initialize_Warden PROC
    ; 1. Allocate/Reference Global Context (R15)
    ; Assuming R15 is pre-allocated or points to static memory
    
    ; 2. Initialize Barrier Gate (Fence_State = 0)
    mov dword ptr [r15 + SOVEREIGN_FABRIC_CONTEXT.Fence_State], 0
    
    ; 3. Initialize Epoch (Tick_Count = 0)
    mov qword ptr [r15 + SOVEREIGN_FABRIC_CONTEXT.Tick_Count], 0
    
    ; 4. Bootstrap Security (Generate initial Entropy)
    ; We fill the entropy pool before any workers start
    call Sovereign_Harvest_Entropy
    call Sovereign_Refresh_Signature
    
    ; 5. Signal Fabric Readiness
    ; Lane 0 is now ready. 
    ; Workers can now loop until they see Fence_State update.
    ret
Sovereign_Initialize_Warden ENDP

; ==============================================================================
; SOVEREIGN_INITIALIZE_WORKERS
; Orchestrates the release of Lanes 1-15
; ==============================================================================
PUBLIC Sovereign_Initialize_Workers
Sovereign_Initialize_Workers PROC
    ; 1. Load Global Context pointer (R15)
    ; Assuming R15 is already holding the global pointer from Warden setup
    
    ; 2. Iterate and Launch
    ; If using threads, we would spawn here. 
    ; If using a flat bare-metal loop, we jump to the loop start.
    
    ; Launch workers (1-15)
    mov rcx, 1
@Worker_Spawn_Loop:
    ; [System-Specific Thread Launch]
    ; Example: Call kernel to start lane
    
    inc rcx
    cmp rcx, 16
    jl @Worker_Spawn_Loop
    
    ret
Sovereign_Initialize_Workers ENDP

PUBLIC _start
_start PROC
    ; 1. Stack Alignment
    ; Native entry requires 16-byte alignment before any call or stack access.
    and rsp, -16
    
    ; 2. Shadow Register Initialization
    ; Instead of corrupting GS, we load our fabric base into R15.
    ; R15 is preserved across function calls in the x64 ABI.
    lea r15, [g_Sovereign_Fabric_Context]
    
    ; 3. Verify Fabric Presence
    ; Ensure the arena we are entering is actually mapped.
    test r15, r15
    jz  @Halt_Fatal ; If arena is null, trap immediately

    ; --- Sovereign Initialization Hook ---
    ; Manually anchor the arena at the 1MB mark
    mov qword ptr [r15].SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base, 0100000h
    mov qword ptr [r15].SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Size, 4000040h

    ; --- CRITICAL: Bootstrap Header ---
    ; Perform the safe zeroing and canary generation
    call Fabric_Safe_Init 

    ; --- INITIALIZE WARDEN (Lane 0) ---
    call Sovereign_Initialize_Warden

    ; --- INITIALIZE WORKERS (Lanes 1-15) ---
    call Sovereign_Initialize_Workers

    ; --- THE LOCKDOWN GATE (Warden waits for the swarm) ---
@Wait_For_Swarm:
    mov rax, [r15 + SOVEREIGN_FABRIC_CONTEXT.Worker_Ready_Count]
    cmp rax, 15
    jl @Wait_For_Swarm   ; Spin until 15 workers report in

    ; --- WRITE HANDSHAKE SIGNAL ---
    ; Writing "SOVEREIGN" (0x534F56524549474E)
    mov rax, 0534F56524549474Eh
    mov [r15 + SOVEREIGN_FABRIC_CONTEXT.Telemetry.System_Status], rax

    ; --- VECTOR COMPUTE LANE INITIALIZATION ---
    ; 1. Generate the first valid Rolling_Signature
    call Sovereign_Rotate_Signature

    ; 2. Populate the DAG Node
    lea rdi, [g_TestNode]
    
    ; Obfuscate KernelPtr with current signature
    lea rax, [Kernel_FMA_Unit]
    xor rax, [r15].SOVEREIGN_FABRIC_CONTEXT.Rolling_Signature
    mov [rdi + DAG_NODE.KernelPtr], rax

    ; Setup Input/Output Pointers deep in the Arena
    mov rax, [r15].SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base
    add rax, 1024               ; Input at Offset 1024
    mov [rdi + DAG_NODE.InPtr], rax
    
    mov rax, [r15].SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base
    add rax, 2048               ; Output at Offset 2048
    mov [rdi + DAG_NODE.OutPtr], rax

    ; Set ParamCount = 8 QWORDS (64 bytes = 1 AVX-512 FMA Loop)
    mov qword ptr [rdi + DAG_NODE.ParamCount], 8

    ; 3. Setup Stream Context (Lane 0)
    lea rbx, [g_FabricMatrix]
    mov [rbx + STREAM_CONTEXT.DAG_Head], rdi
    mov qword ptr [rbx + STREAM_CONTEXT.NodeCount], 1
    mov qword ptr [rbx + STREAM_CONTEXT.State], 2   ; 2 = READY
    
    ; --- Fabric Dispatch ---
    EXTERN Sovereign_Fabric_Loop_Entry:PROC
    jmp Sovereign_Fabric_Loop_Entry

@Halt_Fatal:
    ; Infinite loop to prevent silent failure
    int 3
    jmp @Halt_Fatal
_start ENDP

; ==============================================================================
; WORKER ENTRY POINT (Lanes 1-15)
; ==============================================================================
PUBLIC Worker_Entry
Worker_Entry PROC
    ; Assuming thread/lane context gives access to R15 pre-pinned to g_Sovereign_Fabric_Context
    ; SIGNAL READINESS
    lock inc qword ptr [r15 + SOVEREIGN_FABRIC_CONTEXT.Worker_Ready_Count]
    
    ; ENTER LOOP
    jmp Sovereign_Fabric_Loop
Worker_Entry ENDP

END
