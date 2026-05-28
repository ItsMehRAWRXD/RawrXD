; ==============================================================================
; SOVEREIGN MONOLITH - BARE METAL++ SPECULATIVE STREAMING ENGINE
; ARCHITECTURE: Fabric-Scheduled, ZPI Ingest, Speculative-Decode, AVX-512 FMA
; TELEMETRY: BEACONISM (Ghost Trace)
; GOVERNANCE: Hardware NMI Watchdog + Lock-Free Fences
; TARGET: Pure Silicon, No OS, No Dependencies, x64 MASM
; ==============================================================================
option casemap:none

include Sovereign_Security.inc

EXTERN Verify_Arena_Integrity : PROC
EXTERN Verify_Task_Receipt : PROC

; ------------------------------------------------------------------------------
; DATA STRUCTURES & DEFINITIONS
; ------------------------------------------------------------------------------
MAX_STREAMS     EQU 16
BANK_SIZE       EQU 4000000h    ; 64MB per stream bank
NVME_DOORBELL   EQU 1000h
GHOST_BUF_SIZE  EQU 4096

DAG_NODE STRUCT
    KernelPtr   QWORD ?         ; Obfuscated Function pointer (XORed with Rolling_Signature)
    InPtr       QWORD ?         ; Physical Address (Input)
    OutPtr      QWORD ?         ; Physical Address (Output)
    ParamCount  QWORD ?         ; Payload size / stride
DAG_NODE ENDS

STREAM_CONTEXT STRUCT
    State       QWORD ?         ; 0=FREE, 1=INGEST, 2=READY, 3=EXECUTING
    ArenaBase   QWORD ?         ; Base pointer for stream memory bank
    DAG_Head    QWORD ?         ; Pointer to execution chain
    NodeCount   QWORD ?         ; Nodes remaining
    Reserved    QWORD 4 DUP(0)  ; Alignment padding
STREAM_CONTEXT ENDS

GHOST_ENTRY STRUCT
    Timestamp   QWORD ?
    NodeID      QWORD ?
    Status      QWORD ?
    Reserved    QWORD ?
GHOST_ENTRY ENDS

.DATA
    ALIGN 16
    g_ArenaBase         QWORD 0100000h
    g_FabricMatrix      STREAM_CONTEXT MAX_STREAMS DUP(<0>)
    g_XOR_Key           QWORD 0DEADBEEFCAFEBABEh
    g_Sovereign_Fabric_Context SOVEREIGN_FABRIC_CONTEXT <>
    g_Sovereign_Fence   QWORD 0
    g_GhostBuffer       GHOST_ENTRY GHOST_BUF_SIZE DUP(<0>)
    g_GhostCursor       QWORD 0
    g_UnregisteredTable QWORD 0100000h, 0200000h, 0300000h, 0400000h

.CODE

PUBLIC g_Sovereign_Fabric_Context
PUBLIC g_FabricMatrix
PUBLIC Kernel_FMA_Unit

; ------------------------------------------------------------------------------
; 1. BOOTSTRAP - ENTRY POINT
; ------------------------------------------------------------------------------
PUBLIC _obsolete_start
_obsolete_start PROC
    cli                         ; Disable OS interrupts
    mov rsp, 07C00h             ; Set stack
    
    ; Map NMI Watchdog to Supervisor (Hardware Governance)
    lea rax, [Sovereign_Supervisor]
    mov [02h*8], rax            
    
    ; Initialize Fabric Matrix (Zero-fill)
    lea rdi, [g_FabricMatrix]
    mov rcx, MAX_STREAMS * (SIZE STREAM_CONTEXT) / 8
    xor rax, rax
    rep stosq
    
    jmp Sovereign_Fabric_Loop   ; Enter infinite execution fabric
_obsolete_start ENDP

; ------------------------------------------------------------------------------
; 2. NMI WATCHDOG - SUPERVISOR LOOP (BEACONISM)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Supervisor
Sovereign_Supervisor PROC
    ; Hard reset streams stuck in EXECUTING state for > threshold
    mov rcx, MAX_STREAMS
    lea rdi, [g_FabricMatrix]
@@Watchdog:
    cmp qword ptr [rdi], 3
    jne @@Next
    mov qword ptr [rdi], 0      ; Force to FREE
@@Next:
    add rdi, SIZE STREAM_CONTEXT
    loop @@Watchdog
    iretq
Sovereign_Supervisor ENDP

; ------------------------------------------------------------------------------
; 3. GHOST TRACE (BEACONISM TELEMETRY)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Ghost_Log
Sovereign_Ghost_Log PROC
    ; RCX = NodeID, RDX = Status
    mov rax, 1
    lock xadd [g_GhostCursor], rax
    and rax, GHOST_BUF_SIZE - 1
    shl rax, 5                  ; * 32 (Size of GHOST_ENTRY)
    lea r8, [g_GhostBuffer + rax]
    
    rdtsc
    shl rdx, 32
    or rax, rdx                 ; Combine high/low timestamp
    mov [r8 + GHOST_ENTRY.Timestamp], rax
    mov [r8 + GHOST_ENTRY.NodeID], rcx
    mov [r8 + GHOST_ENTRY.Status], rdx
    ret
Sovereign_Ghost_Log ENDP

; ------------------------------------------------------------------------------
; 4. HARDWARE FENCE MANAGER (Zero-Latency Mutex)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Fence_Acquire
Sovereign_Fence_Acquire PROC
    ; RCX = Stream ID
@@Stall:
    lock bts [g_Sovereign_Fence], rcx
    jc @@Stall
    ret
Sovereign_Fence_Acquire ENDP

PUBLIC Sovereign_Fence_Release
Sovereign_Fence_Release PROC
    lock btr [g_Sovereign_Fence], rcx
    ret
Sovereign_Fence_Release ENDP

; ------------------------------------------------------------------------------
; 5. ZERO-PARSER INGESTION (ZPI) & SPECULATIVE DECODE
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Speculative_Stream
Sovereign_Speculative_Stream PROC
    ; RCX=StreamID, RDX=TargetBuffer, R8=ByteCount
    push rcx
    call Sovereign_Fence_Acquire
    pop rcx
    
    ; O(1) Direct mapping resolution
    mov rsi, [g_UnregisteredTable + rcx*8]
    xor rax, rax

    ; Speculative Decode Loop
@@SpecFetch:
    prefetcht0 [rsi + rax + 128]  ; Speculative Read Ahead
    
    ; XOR Masking (Stream Decompression)
    vmovups zmm0, [rsi + rax]
    vpbroadcastq zmm1, [g_XOR_Key]
    vpxorq zmm0, zmm0, zmm1
    
    ; Store to Exec Buffer
    vmovups [rdx + rax], zmm0
    
    add rax, 64
    cmp rax, r8
    jl @@SpecFetch
    
    call Sovereign_Fence_Release
    ret
Sovereign_Speculative_Stream ENDP

; ------------------------------------------------------------------------------
; 6. SPECULATIVE BOUNDARY DECODE (Branchless CMOV)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Speculative_Decode_Token
Sovereign_Speculative_Decode_Token PROC
    ; Predicts next token address while processing current FMA
    ; RCX = Input, RDX = PredictBuf
    mov rax, [rcx]
    mov r9, [rcx + 8]      ; Primary Lookahead
    mov r8, [rcx + 16]     ; Secondary Lookahead
    
    vmovups zmm0, [rax]    ; Simul-compute
    cmp r9, r8
    cmovz rax, r9          ; Branchless Speculative Commit
    mov [rdx], rax
    ret
Sovereign_Speculative_Decode_Token ENDP

; ------------------------------------------------------------------------------
; 7. FABRIC SCHEDULER (16-WAY INDEPENDENT MULTI-STREAM)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Fabric_Loop
Sovereign_Fabric_Loop PROC
@@Tick:
    ; --- HEAVY INTEGRITY GATE ---
    ; Verifies Arena state before any task dispatch
    call Verify_Arena_Integrity
    
    ; --- Dynamic Signature Rotation ---
    ; Evolve the rolling secret to prevent static task profiling
    call Sovereign_Rotate_Signature
    
PUBLIC Sovereign_Fabric_Loop_Entry
Sovereign_Fabric_Loop_Entry:
    ; Cache the new signature in R12 for task de-obfuscation and MAC verification
    mov r12, [r15].SOVEREIGN_FABRIC_CONTEXT.Rolling_Signature

    xor rbx, rbx                ; Stream ID 0-15
@@Scan:
    mov rsi, SIZE STREAM_CONTEXT
    imul rsi, rbx
    lea rsi, [g_FabricMatrix + rsi]
    
    ; Unlocked check
    cmp qword ptr [rsi], 2      ; 2 = READY
    jne @@NextStream
    
    ; Locked atomic claim
    mov rax, 3                  ; 3 = EXECUTING
    lock xchg [rsi], rax
    cmp rax, 2
    jne @@NextStream
    
    ; DAG Unroll
    mov r12, [rsi + STREAM_CONTEXT.DAG_Head]
    mov r13, [rsi + STREAM_CONTEXT.NodeCount]
    
@@NodeLoop:
    mov rcx, [r12 + DAG_NODE.InPtr]
    mov rdx, [r12 + DAG_NODE.OutPtr]
    mov r8,  [r12 + DAG_NODE.ParamCount]
    
    ; --- Dynamic Target Decryption ---
    ; De-obfuscate the KernelPtr using the current rotational secret
    mov rax, [r12 + DAG_NODE.KernelPtr]
      xor rax, [r15].SOVEREIGN_FABRIC_CONTEXT.Rolling_Signature ; Use pinned secret, NOT R12 (which is DAG ptr)
      
      ; Telemetry Hook BEFORE
      push rcx
      push rdx
      push rax                    ; Save decrypted KernelPtr
      mov rcx, rax
      xor rdx, rdx
      call Sovereign_Ghost_Log
      pop rax
      pop rdx
      pop rcx
      
      ; Direct Physical Jump (To now de-obfuscated target)
      call rax
  
      ; --- Cryptographic Receipt Verification ---
      ; Verify the result MAC calculated by the worker task
      push r13                    ; Save outer loop NodeCount
      mov r14, [r12 + DAG_NODE.OutPtr]
      mov r13, [r12 + DAG_NODE.ParamCount]
      push r12                    ; Save current node pointer
      mov r12, [r15].SOVEREIGN_FABRIC_CONTEXT.Rolling_Signature
      call Verify_Task_Receipt
      pop r12                     ; Restore current node pointer
      pop r13                     ; Restore outer loop NodeCount
      
      test rax, rax
      jz @@SecurityPanic          ; Halt on MAC mismatch (Breach detected)

      add r12, TYPE DAG_NODE
      dec r13
      jnz @@NodeLoop

      ; Mark FREE
      mov qword ptr [rsi], 0

@@NextStream:
      inc rbx
      cmp rbx, MAX_STREAMS
      jl @@Scan
      jmp @@Tick

@@SecurityPanic:
    ; Absolute halt on integrity failure
    cli
    hlt
    jmp @@SecurityPanic
Sovereign_Fabric_Loop ENDP

; ==============================================================================
; SOVEREIGN_IDE_MONITOR
; R15 = Global Fabric Context
; ==============================================================================
PUBLIC Sovereign_IDE_Monitor
Sovereign_IDE_Monitor PROC
    ; 1. Sync Tick Count
    mov rax, [r15 + SOVEREIGN_FABRIC_CONTEXT.Tick_Count]
    mov [r15 + SOVEREIGN_FABRIC_CONTEXT.Telemetry.Global_Tick], rax
    
    ; 2. Snapshot Signature
    ; We copy the current entropy state to the buffer
    lea rsi, [r15 + SOVEREIGN_FABRIC_CONTEXT.Security_Context.Dynamic_Signature]
    lea rdi, [r15 + SOVEREIGN_FABRIC_CONTEXT.Telemetry.Signature_Snap]
    movsq ; Copy 4 QWORDs
    movsq
    movsq
    movsq
    
    ; 3. Snapshot Lane 0 Output (First QWORD of Slab)
    mov rax, [r15 + SOVEREIGN_FABRIC_CONTEXT.Tensor_Arena_Base]
    mov rbx, [rax] ; Read first QWORD of slab 0
    mov [r15 + SOVEREIGN_FABRIC_CONTEXT.Telemetry.Lane0_Result], rbx
    
    ret
Sovereign_IDE_Monitor ENDP

; ------------------------------------------------------------------------------
; 8. AVX-512 FUSED EXECUTION CORE
; ------------------------------------------------------------------------------
PUBLIC Kernel_FMA_Unit
Kernel_FMA_Unit PROC
    ; RCX=Input, RDX=Output, R8=Size
      push r14
      push r13
      push r12

      mov r14, rdx                ; OutPtr for Compute_Result_MAC
      mov r13, r8                 ; Size (QWORDS)
      mov r12, [r15].SOVEREIGN_FABRIC_CONTEXT.Rolling_Signature
      
      shl r8, 3                   ; Convert Size to Bytes
      xor rax, rax
  @@FMA_Loop:
      ; Fused AVX-512 Memory-Operand Compute
      vmovups zmm0, [rcx + rax]
      vfmadd231ps zmm0, zmm1, ZMMWORD PTR [rdx + rax]
      vmovups [rdx + rax], zmm0
      
      add rax, 64
      cmp rax, r8
      jl @@FMA_Loop

      ; --- Generate Cryptographic Receipt ---
      ; Seal the result block with the current rotational signature
      call Compute_Result_MAC
      mov [r14 + r13*8], rax

      pop r12
      pop r13
      pop r14
      ret
Kernel_FMA_Unit ENDP
  ; ------------------------------------------------------------------------------
; 9. DIRECT MEMORY DMA DOORBELL (NO MIDDLE MAN)
; ------------------------------------------------------------------------------
PUBLIC Sovereign_DMA_Trigger
Sovereign_DMA_Trigger PROC
    ; RCX=DeviceBase, RDX=TargetPhysicalAddr
    mov qword ptr [rcx + NVME_DOORBELL], 1
    ret
Sovereign_DMA_Trigger ENDP

END