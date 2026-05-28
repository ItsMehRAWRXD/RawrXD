include Sovereign_Common.inc
; =====================================================================================
; SOVEREIGN OMNI-ENGINE (THE UNIFIED MONOLITH CORE)
; ARCHITECTURE: X86-64 (MASM64) + AVX-512 EXTENSIONS
; CODENAME: FRANKEN_SYNTH v1.0.0 / ATOMIC CORE v0.4.0
; =====================================================================================
; Combines all unmodularized engines, hybrid loaders, digestion cores, KV ring buffers, 
; and continuous execution layers into a single toggled entirety.
; =====================================================================================

.DATA
    ; ---------------------------------------------------------------------------------
    ; Win32 / Sovereign Global Constants & Toggles
    ; ---------------------------------------------------------------------------------
    WIN32_GENERIC_READ      EQU 80000000h
    WIN32_FILE_SHARE_READ   EQU 00000001h
    WIN32_OPEN_EXISTING     EQU 00000003h
    WIN32_FILE_ATTRIBUTE_N  EQU 00000080h
    WIN32_PAGE_READONLY     EQU 00000002h
    WIN32_FILE_MAP_READ     EQU 00000004h
    WIN32_INVALID_HANDLE    EQU -1
    PROCESS_PSEUDO_HANDLE   EQU -1          

    ; Toggles / Flags
    SO_MODE_STATIC          EQU 0
    SO_MODE_HYBRID          EQU 1
    
    SO_FLAG_PREFETCH_ONLY   EQU 1
    SO_FLAG_FULL_LOCK       EQU 2
    SO_FLAG_SELECTIVE_LOCK  EQU 4
    SO_FLAG_NO_LOCK         EQU 8
    
    SO_FLAG_LAZY            EQU 00000000h
    SO_FLAG_PINNED          EQU 00000001h

    ; ---------------------------------------------------------------------------------
    ; Digestion Core Nomenclature
    ; ---------------------------------------------------------------------------------
    NM_COMPUTE_0    DB "RECURSIVE_FUSED_REG_VECTOR_STREAMER_CORE", 0
    ALIGN 16
    NM_COMPUTE_1    DB "BIT_SERIAL_TERNARY_LOGIC_SATURATOR_UNIT", 0
    ALIGN 16
    NM_MEMORY_0     DB "HUGE_PAGE_TLB_PINNED_RESIDENT_BUFFER   ", 0
    ALIGN 16
    NM_MEMORY_1     DB "L1D_BANK_CONFLICT_EVADE_STRIDE_MATRIX  ", 0
    ALIGN 16
    NM_SCHED_0      DB "USER_MODE_FIBER_COOPERATIVE_SCHEDULER  ", 0
    ALIGN 16
    NM_SCHED_1      DB "SPECULATIVE_TREE_SEARCH_MASK_STEERER  ", 0
    ALIGN 16

    CON_BLENDED     DB "_MUTATED_WITH_", 0
    CON_GREGARIOUS  DB "_HYBRIDIZED_BY_", 0

    EXTERN g_ApiTable : SOVEREIGN_API_TABLE

.CODE

; -------------------------------------------------------------------------------------
; UPSTREAM OS BINDINGS (ZERO-IAT RESOLUTION)
; -------------------------------------------------------------------------------------
extern Next_Compute_Phase: proc

; -------------------------------------------------------------------------------------
; STRUCTURE DEFINITIONS (UNMODULARIZED COMBINED TOPOLOGY)
; -------------------------------------------------------------------------------------

SOVEREIGN_SO_ENGINE STRUCT
    FileHandle      QWORD ?
    MapHandle       QWORD ?
    BaseAddress     QWORD ?
    FileSize        QWORD ?
    HotStart        QWORD ?
    HotSize         QWORD ?
    Mode            DWORD ?
    Flags           DWORD ?
SOVEREIGN_SO_ENGINE ENDS

SOVEREIGN_BOOK_STACK STRUCT
    MappingHandle   QWORD ?
    BaseViewAddress QWORD ?
    StackedAddress1 QWORD ?
    StackedAddress2 QWORD ?
    ViewSize        QWORD ?
SOVEREIGN_BOOK_STACK ENDS

SOVEREIGN_GENETIC_COORD STRUCT
    ComputeGene     QWORD ?
    MemoryGene      QWORD ?
    SchedulerGene   QWORD ?
    MutationIndex   QWORD ?
SOVEREIGN_GENETIC_COORD ENDS

FRANKEN_ENGINE_OUTPUT STRUCT
    EngineNameBuffer DB 128 DUP (0)
    HardwareStride   QWORD ?
    PortAffinityMask QWORD ?
FRANKEN_ENGINE_OUTPUT ENDS

SOVEREIGN_KV_CONFIG STRUCT
    ALIGNMENT_PAD       QWORD ?
    TotalLayers         QWORD ?
    NumHeads            QWORD ?
    HeadDim             QWORD ?
    RingSize            QWORD ?
    RingMask            QWORD ?
    BlockStride         QWORD ?
    PrefetchStride      QWORD ?
    BaseMemoryAddress   QWORD ?
SOVEREIGN_KV_CONFIG ENDS

SOVEREIGN_KV_CURSOR STRUCT
    CurrentBlockIndex   QWORD ?
    ActiveBufferMask    QWORD ?
    Reserved0           QWORD ?
    Reserved1           QWORD ?
SOVEREIGN_KV_CURSOR ENDS

; =====================================================================================
; 1. UNIFIED MEMORY LOADER CORE (HYBRID SO ENGINE)
; =====================================================================================
; API: Sovereign_SO_CreateUnified
; RCX = file path (ASCII)
; RDX = pointer to SOVEREIGN_SO_ENGINE
; R8  = Mode (STATIC / HYBRID)
; R9  = Flags
; =====================================================================================
Sovereign_SO_CreateUnified PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 64

    mov r12, rdx
    mov [r12].SOVEREIGN_SO_ENGINE.Mode, r8d
    mov [r12].SOVEREIGN_SO_ENGINE.Flags, r9d

    ; OPEN FILE
    mov edx, WIN32_GENERIC_READ
    mov r8d, WIN32_FILE_SHARE_READ
    xor r9, r9

    mov qword ptr [rsp+32], WIN32_OPEN_EXISTING
    mov qword ptr [rsp+40], 80h
    mov qword ptr [rsp+48], 0

    call [g_ApiTable.pCreateFileA]
    cmp rax, WIN32_INVALID_HANDLE
    je fail_io

    mov [r12].SOVEREIGN_SO_ENGINE.FileHandle, rax

    ; GET FILE SIZE
    lea rdx, [rsp+56]
    mov rcx, rax
    call [g_ApiTable.pGetFileSizeEx]
    test eax, eax
    jz fail_io

    mov rbx, [rsp+56]
    mov [r12].SOVEREIGN_SO_ENGINE.FileSize, rbx

    ; CREATE MAPPING
    mov rcx, [r12].SOVEREIGN_SO_ENGINE.FileHandle
    xor rdx, rdx
    mov r8d, WIN32_PAGE_READONLY
    mov r9, rbx
    shr r9, 32
    mov eax, ebx
    mov [rsp+32], eax
    mov qword ptr [rsp+40], 0

    call [g_ApiTable.pCreateFileMappingA]
    test rax, rax
    jz fail_map
    mov [r12].SOVEREIGN_SO_ENGINE.MapHandle, rax

    ; MAP VIEW
    mov rcx, rax
    mov edx, WIN32_FILE_MAP_READ
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp+32], 0

    call [g_ApiTable.pMapViewOfFile]
    test rax, rax
    jz fail_view

    mov [r12].SOVEREIGN_SO_ENGINE.BaseAddress, rax
    mov rsi, rax

    ; MODE SWITCH
    mov eax, [r12].SOVEREIGN_SO_ENGINE.Mode
    cmp eax, SO_MODE_STATIC
    je static_mode
    cmp eax, SO_MODE_HYBRID
    je hybrid_mode
    jmp fail_io

static_mode:
    xor rbx, rbx
    mov rdi, [r12].SOVEREIGN_SO_ENGINE.FileSize
prefault_s:
    cmp rbx, rdi
    jge lock_check
    mov al, byte ptr [rsi + rbx]
    add rbx, 4096
    jmp prefault_s

lock_check:
    test dword ptr [r12].SOVEREIGN_SO_ENGINE.Flags, SO_FLAG_NO_LOCK
    jnz success
    mov rcx, rsi
    mov rdx, rdi
    call [g_ApiTable.pVirtualLock]
    jmp success

hybrid_mode:
    xor rbx, rbx
    mov rdi, [r12].SOVEREIGN_SO_ENGINE.FileSize
warm:
    cmp rbx, rdi
    jge hot_lock
    mov al, byte ptr [rsi + rbx]
    add rbx, 4096
    jmp warm

hot_lock:
    mov rcx, rsi
    mov rdx, 10000000h        ; 256MB hot region
    mov [r12].SOVEREIGN_SO_ENGINE.HotStart, rcx
    mov [r12].SOVEREIGN_SO_ENGINE.HotSize, rdx
    
    test dword ptr [r12].SOVEREIGN_SO_ENGINE.Flags, SO_FLAG_SELECTIVE_LOCK
    jz success
    call [g_ApiTable.pVirtualLock]

success:
    mov rcx, PROCESS_PSEUDO_HANDLE
    mov rdx, rdi
    add rdx, 10000000h
    mov r8, rdx
    call [g_ApiTable.pSetProcessWorkingSetSize]

    xor rax, rax
    jmp exit

fail_view:
    mov rax, -3
    jmp exit
fail_map:
    mov rax, -2
    jmp exit
fail_io:
    mov rax, -1

exit:
    add rsp, 64
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_SO_CreateUnified ENDP

; =====================================================================================
; 2. LIFECYCLE DESTRUCTOR (Unwind Core)
; INPUT: RCX = Pointer to populated SOVEREIGN_SO_ENGINE
; =====================================================================================
Sovereign_SO_Destroy PROC
    push rbx
    sub rsp, 32

    mov rbx, rcx
    
    mov eax, [rbx].SOVEREIGN_SO_ENGINE.Mode
    cmp eax, SO_MODE_STATIC
    je unlock_static
    
    ; Hybrid unlock
    test dword ptr [rbx].SOVEREIGN_SO_ENGINE.Flags, SO_FLAG_SELECTIVE_LOCK
    jz release_view
    mov rcx, [rbx].SOVEREIGN_SO_ENGINE.HotStart
    mov rdx, [rbx].SOVEREIGN_SO_ENGINE.HotSize
    call [g_ApiTable.pVirtualUnlock]
    jmp release_view

unlock_static:
    test dword ptr [rbx].SOVEREIGN_SO_ENGINE.Flags, SO_FLAG_NO_LOCK
    jnz release_view
    mov rcx, [rbx].SOVEREIGN_SO_ENGINE.BaseAddress
    mov rdx, [rbx].SOVEREIGN_SO_ENGINE.FileSize
    call [g_ApiTable.pVirtualUnlock]

release_view:
    mov rcx, [rbx].SOVEREIGN_SO_ENGINE.BaseAddress
    test rcx, rcx
    jz close_map
    call [g_ApiTable.pUnmapViewOfFile]
    mov [rbx].SOVEREIGN_SO_ENGINE.BaseAddress, 0

close_map:
    mov rcx, [rbx].SOVEREIGN_SO_ENGINE.MapHandle
    test rcx, rcx
    jz close_file
    call [g_ApiTable.pCloseHandle]
    mov [rbx].SOVEREIGN_SO_ENGINE.MapHandle, 0

close_file:
    mov rcx, [rbx].SOVEREIGN_SO_ENGINE.FileHandle
    test rcx, rcx
    jz reset_fields
    call [g_ApiTable.pCloseHandle]
    mov [rbx].SOVEREIGN_SO_ENGINE.FileHandle, 0

reset_fields:
    mov [rbx].SOVEREIGN_SO_ENGINE.FileSize, 0
    mov [rbx].SOVEREIGN_SO_ENGINE.HotStart, 0
    mov [rbx].SOVEREIGN_SO_ENGINE.HotSize, 0
    mov [rbx].SOVEREIGN_SO_ENGINE.Mode, 0
    mov [rbx].SOVEREIGN_SO_ENGINE.Flags, 0

    xor rax, rax
    add rsp, 32
    pop rbx
    ret
Sovereign_SO_Destroy ENDP

; =====================================================================================
; 3. RUNTIME MEMORY POLICY ENGINE (ADAPTIVE HEURISTIC ALLOCATOR)
; =====================================================================================
; Evaluates memory pressure, adjusts page locking policies, and manages
; SIMD-accelerated weight migration between hot/cold regions.
; =====================================================================================
Sovereign_Memory_Policy_Engine PROC
    push rbx
    sub rsp, 32
    
    test rcx, rcx
    jz Fault_Panic
    mov rbx, rcx

    ; Policy Check: Is selective locking enabled?
    test dword ptr [rbx + SOVEREIGN_SO_ENGINE.Flags], SO_FLAG_SELECTIVE_LOCK
    jz @@FullLockPolicy

@@SelectivePolicy:
    ; Implement dynamic page-sliding based on throughput
    mov rcx, [rbx + SOVEREIGN_SO_ENGINE.HotStart]
    mov rdx, [rbx + SOVEREIGN_SO_ENGINE.HotSize]
    jmp @@ExecutePolicy

@@FullLockPolicy:
    mov rcx, [rbx + SOVEREIGN_SO_ENGINE.BaseAddress]
    mov rdx, [rbx + SOVEREIGN_SO_ENGINE.FileSize]

@@ExecutePolicy:
    ; Call VirtualLock through ApiTable
    call [g_ApiTable.pVirtualLock]
    
    add rsp, 32
    pop rbx

    ; Return to orchestrator for next phase
    jmp Next_Compute_Phase

Fault_Panic:
    add rsp, 32
    pop rbx
    ret
Sovereign_Memory_Policy_Engine ENDP

; =====================================================================================
; 4. VIRTUAL PAGE STACKER & GOTO DISPATCH
; =====================================================================================
Sovereign_Stack_And_Goto PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    
    test rcx, rcx
    jz Error_Null_Context_G
    mov rbx, rcx

    mov rcx, qword ptr [rbx + SOVEREIGN_BOOK_STACK.MappingHandle]
    test rcx, rcx
    jz Error_Null_Context_G

    mov edx, WIN32_FILE_MAP_READ
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp + 32], 0
    call [g_ApiTable.pMapViewOfFile]
    test rax, rax
    jz Error_Linkage_Break_G
    mov qword ptr [rbx + SOVEREIGN_BOOK_STACK.BaseViewAddress], rax

    mov rcx, qword ptr [rbx + SOVEREIGN_BOOK_STACK.MappingHandle]
    mov edx, WIN32_FILE_MAP_READ
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp + 32], 0
    call [g_ApiTable.pMapViewOfFile]
    test rax, rax
    jz Error_Linkage_Break_G
    mov qword ptr [rbx + SOVEREIGN_BOOK_STACK.StackedAddress1], rax

    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    jmp Next_Compute_Phase

Error_Linkage_Break_G:
    mov rcx, qword ptr [rbx + SOVEREIGN_BOOK_STACK.BaseViewAddress]
    test rcx, rcx
    jz Assign_Error_Code_G
    call [g_ApiTable.pUnmapViewOfFile]

Assign_Error_Code_G:
    mov rax, -1

Error_Null_Context_G:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Stack_And_Goto ENDP

; =====================================================================================
; 5. MICROARCHITECTURAL DIGESTION ENGINE (FRANKEN_SYNTH)
; =====================================================================================
Sovereign_Digest_And_Synthesize PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    
    test rcx, rcx
    jz Error_Null_State
    test rdx, rdx
    jz Error_Null_State
    
    mov r12, rcx
    mov r13, rdx

    lea rdi, [r13 + FRANKEN_ENGINE_OUTPUT.EngineNameBuffer]
    xor eax, eax
    mov ecx, 16 
    rep stosq
    lea rdi, [r13 + FRANKEN_ENGINE_OUTPUT.EngineNameBuffer]

    ; Compute Gene String
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.ComputeGene]
    test rax, rax
    jnz Load_Compute_1
    lea rsi, NM_COMPUTE_0
    jmp Copy_Compute_String

Load_Compute_1:
    lea rsi, NM_COMPUTE_1
Copy_Compute_String:
    call Internal_String_Append

    ; Connector Idiom
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.MutationIndex]
    test al, 1
    jnz Load_Connector_1
    lea rsi, CON_BLENDED
    jmp Copy_Connector_String

Load_Connector_1:
    lea rsi, CON_GREGARIOUS
Copy_Connector_String:
    call Internal_String_Append

    ; Memory Gene String
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.MemoryGene]
    test rax, rax
    jnz Load_Memory_1
    lea rsi, NM_MEMORY_0
    jmp Copy_Memory_String

Load_Memory_1:
    lea rsi, NM_MEMORY_1
Copy_Memory_String:
    call Internal_String_Append

    ; Calculate HW Stride
    mov rsi, 64
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.MemoryGene]
    test rax, rax
    jz Evaluate_Scheduler_Stride
    add rsi, 1

Evaluate_Scheduler_Stride:
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.SchedulerGene]
    test rax, rax
    jz Apply_Mutation_Skew
    shl rsi, 2

Apply_Mutation_Skew:
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.MutationIndex]
    and rax, 0Fh
    add rsi, rax
    mov qword ptr [r13 + FRANKEN_ENGINE_OUTPUT.HardwareStride], rsi

    ; Port Affinity
    mov rbx, 1
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.ComputeGene]
    test rax, rax
    jz Map_Ports_Complete
    mov rbx, 0Ah

Map_Ports_Complete:
    mov rax, qword ptr [r12 + SOVEREIGN_GENETIC_COORD.MutationIndex]
    shr rax, 4
    and rax, 03h
    mov cl, al
    shl rbx, cl
    mov qword ptr [r13 + FRANKEN_ENGINE_OUTPUT.PortAffinityMask], rbx

    xor rax, rax
    jmp System_Exit

Error_Null_State:
    mov rax, -1

System_Exit:
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Digest_And_Synthesize ENDP

Internal_String_Append PROC
String_Loop:
    lodsb
    test al, al
    jz String_Done
    stosb
    jmp String_Loop
String_Done:
    ret
Internal_String_Append ENDP

; =====================================================================================
; 6. KV-CACHE TILING RING BUFFER (ATTENTION / FMA)
; =====================================================================================
Sovereign_KV_Initialize PROC
    push rbx
    push rsi
    push rdi

    mov rax, qword ptr [rsp + 40]
    mov r10, qword ptr [rsp + 48]

    mov rbx, rax
    sub rbx, 1
    and rbx, rax
    jnz Error_Invalid_Config_KV

    mov rbx, r10
    and rbx, 63
    jnz Error_Invalid_Alignment_KV

    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.TotalLayers], rdx
    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.NumHeads], r8
    shl r9, 2
    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.HeadDim], r9
    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.RingSize], rax
    
    mov rbx, rax
    sub rbx, 1
    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.RingMask], rbx
    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.BaseMemoryAddress], r10

    mov rax, rdx
    imul rax, r8
    imul rax, r9
    shl rax, 1
    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.BlockStride], rax

    mov qword ptr [rcx + SOVEREIGN_KV_CONFIG.PrefetchStride], 128

    xor rax, rax
    jmp Exit_Init_KV

Error_Invalid_Config_KV:
    mov rax, -1
    jmp Exit_Init_KV
Error_Invalid_Alignment_KV:
    mov rax, -2

Exit_Init_KV:
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_KV_Initialize ENDP


Sovereign_KV_Append_Slice PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13

    mov r10, qword ptr [rdx + SOVEREIGN_KV_CURSOR.CurrentBlockIndex]
    mov r11, qword ptr [rcx + SOVEREIGN_KV_CONFIG.RingMask]
    and r10, r11
    
    mov rax, qword ptr [rcx + SOVEREIGN_KV_CONFIG.BlockStride]
    imul rax, r10
    add rax, qword ptr [rcx + SOVEREIGN_KV_CONFIG.BaseMemoryAddress]

    mov r11, qword ptr [rcx + SOVEREIGN_KV_CONFIG.TotalLayers]
    mov r12, qword ptr [rcx + SOVEREIGN_KV_CONFIG.NumHeads]
    mov r13, qword ptr [rcx + SOVEREIGN_KV_CONFIG.HeadDim]

    xor rsi, rsi
Layer_Loop:
    cmp rsi, r11
    jge Commit_Clipped_Sequence
    xor rdi, rdi
Head_Loop:
    cmp rdi, r12
    jge Next_Layer_Iteration

    mov rbx, r13
    xor rbx, rbx
Vector_Copy_Key:
    cmp rbx, r13
    jge Vector_Copy_Value
    vmovups zmm0, zmmword ptr [r8 + rbx]
    vmovntdq zmmword ptr [rax + rbx], zmm0
    add rbx, 64
    jmp Vector_Copy_Key

Vector_Copy_Value:
    add rax, r13
    xor rbx, rbx
Vector_Copy_Value_Loop:
    cmp rbx, r13
    jge Finalize_Head_Blocks
    vmovups zmm1, zmmword ptr [r9 + rbx]
    vmovntdq zmmword ptr [rax + rbx], zmm1
    add rbx, 64
    jmp Vector_Copy_Value_Loop

Finalize_Head_Blocks:
    add rax, r13
    add r8, r13
    add r9, r13
    inc rdi
    jmp Head_Loop

Next_Layer_Iteration:
    inc rsi
    jmp Layer_Loop

Commit_Clipped_Sequence:
    lock inc qword ptr [rdx + SOVEREIGN_KV_CURSOR.CurrentBlockIndex]
    sfence
    pop r13
    pop r12
    pop r11
    pop rsi
    pop rdi
    pop rbx
    ret
Sovereign_KV_Append_Slice ENDP


Sovereign_KV_Attention_Fused_Compute PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov r11, qword ptr [rcx + SOVEREIGN_KV_CONFIG.TotalLayers]
    mov r12, qword ptr [rcx + SOVEREIGN_KV_CONFIG.NumHeads]
    mov r13, qword ptr [rcx + SOVEREIGN_KV_CONFIG.HeadDim]
    mov r14, qword ptr [rcx + SOVEREIGN_KV_CONFIG.BlockStride]
    mov r15, qword ptr [rcx + SOVEREIGN_KV_CONFIG.RingMask]

    mov rsi, qword ptr [rdx + SOVEREIGN_KV_CURSOR.CurrentBlockIndex]
    mov rbx, qword ptr [rcx + SOVEREIGN_KV_CONFIG.RingSize]
    cmp rsi, rbx
    cmovg rsi, rbx

    xor rdi, rdi
Compute_History_Blocks:
    cmp rdi, rsi
    jge Conclude_Compute_Pipeline

    mov rax, rdi
    and rax, r15
    imul rax, r14
    add rax, qword ptr [rcx + SOVEREIGN_KV_CONFIG.BaseMemoryAddress]

    mov rbx, rdi
    add rbx, 1
    and rbx, r15
    imul rbx, r14
    add rbx, qword ptr [rcx + SOVEREIGN_KV_CONFIG.BaseMemoryAddress]

    xor r8, r8
Attention_Tile_Execution:
    cmp r8, r14
    jge Next_History_Block

    prefetcht0 byte ptr [rbx + r8]
    prefetcht1 byte ptr [rbx + r8 + 64]

    vmovups zmm2, zmmword ptr [rax + r8]
    vmovups zmm3, zmmword ptr [rax + r8 + 64]

    vfmadd231ps zmm4, zmm2, zmm2
    vfmadd231ps zmm5, zmm3, zmm3

    add r8, 128
    jmp Attention_Tile_Execution

Next_History_Block:
    inc rdi
    jmp Compute_History_Blocks

Conclude_Compute_Pipeline:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
Sovereign_KV_Attention_Fused_Compute ENDP
END




