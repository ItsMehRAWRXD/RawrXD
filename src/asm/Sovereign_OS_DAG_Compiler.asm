; Sovereign_OS_DAG_Compiler.asm - Production Audit (Static Execution Compiler)

include Sovereign_Common.inc

.code

; --- Compiler-Time Mutable Node (Internal Use) ---
XR_COMPILER_NODE STRUCT
    TensorIndex     dd ?
    LayerType       dd ?
    DependencyMask  dq ?
    InDegree        dd ?
    Visited         dd ?
    ChildCount      dq ?
    ChildListPtr    dq ?
    Flags           dq ?
XR_COMPILER_NODE ENDS

; --- Runtime Sealed Node (32 Bytes, Production Spec) ---
XR_EXEC_NODE STRUCT
    NodeId          dd ? ; 0
    TensorIndex     dd ? ; 4 (Union: OpType)
    FirstUse        dd ? ; 8
    LastUse         dd ? ; 12
    ByteExtent      dq ? ; 16
    VramOffset      dq ? ; 24
XR_EXEC_NODE ENDS

; --- Hardware Binding Entry (32 Bytes, Production Spec) ---
XR_BINDING_ENTRY STRUCT
    TensorIdx       dq ? ; 0
    PhysicalBase    dq ? ; 8
    LockFlags       dd ? ; 16
    Pad             dd ? ; 20
    Reserved        dq ? ; 24 (Padding to 32B)
XR_BINDING_ENTRY ENDS

; --- Hardware Command Stream Entry (64 Bytes) ---
XR_COMMAND_STREAM_ENTRY STRUCT
    NodeId          dd ? ; 0
    Lane            dd ? ; 4
    OpType          dd ? ; 8
    Flags           dd ? ; 12
    VRAMPtr         dq ? ; 16
    SrcOffset       dq ? ; 24
    ByteExtent      dq ? ; 32
    SyncTag         dq ? ; 40
    Reserved        dq 2 DUP(?) ; 48-64 padding
XR_COMMAND_STREAM_ENTRY ENDS

; --- Execution Graph Header ---
XR_EXEC_GRAPH STRUCT
    NodesPtr    dq ?
    EdgeMasks   dq ?
    NodeCount   dq ?
    Flags       dq ?
XR_EXEC_GRAPH ENDS

; --- Constants ---
MAX_EXEC_NODES         EQU 1024
MAX_TENSORS            EQU 65536
SIZEOF_XR_TENSOR_ENTRY EQU 32
SIZEOF_XR_EXEC_NODE    EQU 32
SIZEOF_XR_BINDING_ENTRY EQU 32

.data
; Globals are now in Sovereign_Common.inc as EXTERNDEFs

PUBLIC g_ExecNodes
PUBLIC g_ExecNodeCount
PUBLIC g_PeakVramUsage
PUBLIC g_TensorBindingTable
PUBLIC g_BindingCount
PUBLIC g_VRAMPoolBase
PUBLIC g_VRAMPoolSize

    g_CompileNodes      XR_COMPILER_NODE MAX_EXEC_NODES DUP(<>)
    g_ExecNodes         XR_EXEC_NODE     MAX_EXEC_NODES DUP(<>)
    
    ALIGN 16
    g_TensorBindingTable XR_BINDING_ENTRY MAX_TENSORS DUP(<>)
    
    g_ExecNodeCount     dd 0
    g_BindingCount      dq 0
    g_PeakVramUsage     dq 0
    g_VRAMPoolBase      dq 0000000040000000h  ; 1GB Base Boundary
    g_VRAMPoolSize      dq 0000000400000000h  ; 16GB Total Linear Pool Size
    
    g_ChildLists        dq MAX_EXEC_NODES * 64 DUP(0)
    g_ExecGraph         XR_EXEC_GRAPH <offset g_ExecNodes, 0, 0, 0>

.code

; ---------------------------------------------
; XR_BuildExecutionDAG
; Traverses the GGUF Tensor Registry and translates layers to Compiler Nodes
; ---------------------------------------------
PUBLIC XR_BuildExecutionDAG
XR_BuildExecutionDAG PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    
    mov r13, [g_TensorCount]
    xor rsi, rsi
    
@@init_loop:
    cmp rsi, r13
    jge @@build_done
    
    ; Target Compiler Node Address Array [rsi * sizeof XR_COMPILER_NODE]
    lea rbx, g_CompileNodes
    mov rax, SIZEOF XR_COMPILER_NODE
    imul rax, rsi
    add rbx, rax
    
    ; Source Tensor Address Array [rsi * sizeof XR_TENSOR_ENTRY]
    lea r12, g_TensorRegistry
    mov rax, 32                 ; SIZEOF_XR_TENSOR_ENTRY
    imul rax, rsi
    add r12, rax
    
    ; Bind Tensor Node State
    mov dword ptr [rbx], esi    ; TensorIndex -> Compiler Node
    
    ; Assess GGML Type for dispatch mapping
    mov eax, dword ptr [r12 + 24] ; GGMLType offset
    cmp eax, 10                 ; Q2_K Type
    je @@map_q2k
    cmp eax, 6                  ; F32 Type
    je @@map_f32
    
@@map_default:
    mov dword ptr [rbx + 4], 0  ; Default / Unmapped Layer 
    jmp @@node_finalize
    
@@map_q2k:
    mov dword ptr [rbx + 4], 2  ; LayerType 2 = MATMUL_Q2_K
    jmp @@node_finalize
    
@@map_f32:
    mov dword ptr [rbx + 4], 1  ; LayerType 1 = MATMUL_FMA
    
@@node_finalize:
    mov dword ptr [rbx + 16], 0 ; InDegree 
    mov dword ptr [rbx + 20], 0 ; Visited
    inc rsi
    jmp @@init_loop
    
@@build_done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
XR_BuildExecutionDAG ENDP

; ------------------------------------------------------------
; XR_SealExecutionGraph
; ------------------------------------------------------------
PUBLIC XR_SealExecutionGraph
XR_SealExecutionGraph PROC
    push rbx
    push rsi
    push rdi
    push r12
    mov r12, rdx
    xor rsi, rsi
@@seal_loop:
    cmp rsi, r12
    jae @@seal_done
    lea rbx, g_CompileNodes
    mov rax, SIZEOF XR_COMPILER_NODE
    imul rax, rsi
    add rbx, rax
    lea rdi, g_ExecNodes
    mov rax, rsi
    shl rax, 5 ; 32B aligned
    add rdi, rax
    ; Copy TensorIndex from CompileNode to ExecNode
    mov eax, [rbx]
    mov [rdi + 4], eax ; TensorIndex is at offset 4
    ; Set NodeId
    mov eax, esi
    mov [rdi], eax   ; NodeId is at offset 0
    inc rsi
    jmp @@seal_loop
@@seal_done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
XR_SealExecutionGraph ENDP

; -----------------------------------------------------------------------------------------
; XR_ComputeLifetimeRanges
; Implements the Forward/Backward propagation pass for tensor residency intervals.
; -----------------------------------------------------------------------------------------
PUBLIC XR_ComputeLifetimeRanges
XR_ComputeLifetimeRanges PROC
    push    r15
    push    r14
    push    r13
    push    r12
    push    rbx
    sub     rsp, 40

    mov     r12d, [g_ExecNodeCount]
    test    r12d, r12d
    jz      _LifetimeDone

    lea     r13, [g_ExecNodes]
    
    ; [Pass 1] Global Initialization
    xor     rcx, rcx
_InitLoop:
    cmp     ecx, r12d
    jae     _Pass2_Start
    
    mov     rax, rcx
    shl     rax, 5                      ; SIZEOF_XR_EXEC_NODE = 32
    lea     rdx, [r13 + rax]
    
    mov     dword ptr [rdx + 8], 0FFFFFFFFh ; FirstUse = INF
    mov     dword ptr [rdx + 12], 0         ; LastUse = 0
    inc     ecx
    jmp     _InitLoop

_Pass2_Start:
    ; [Pass 2] Temporal Correlation
    ; We iterate every node and update the lifetime of its target tensor
    xor     r14, r14                    ; i = current tick
_CorrelationLoop:
    cmp     r14d, r12d
    jae     _LifetimeDone

    mov     rax, r14
    shl     rax, 5
    lea     rbx, [r13 + rax]            ; pNode = &g_ExecNodes[i]
    
    ; Update FirstUse
    mov     eax, [rbx + 8]
    cmp     eax, r14d
    jbe     _UpdateLast
    mov     [rbx + 8], r14d             ; FirstUse = i

_UpdateLast:
    ; Update LastUse
    mov     eax, [rbx + 12]
    cmp     eax, r14d
    jae     _NextTick
    mov     [rbx + 12], r14d            ; LastUse = i

_NextTick:
    inc     r14
    jmp     _CorrelationLoop

_LifetimeDone:
    xor     eax, eax
    add     rsp, 40
    pop     rbx
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret
XR_ComputeLifetimeRanges ENDP

PUBLIC XR_FinalizeTensorBindingTable
XR_FinalizeTensorBindingTable PROC
    push    r15
    push    r14
    push    r13
    push    r12
    push    rbx
    sub     rsp, 40

    xor     r12, r12                    ; r12 = i = 0
    mov     r13, [g_TensorCount]
    test    r13, r13
    jz      _BindDone

    mov     r14, [g_TensorRegistry]
    lea     r15, [g_TensorBindingTable]
    mov     rbx, [g_VRAMPoolBase]

_BindLoop:
    cmp     r12, r13
    jge     _BindDone

    ; Fetch absolute unaligned allocation footprint size
    mov     rax, [r14 + 16]             ; XR_TENSOR_ENTRY.ByteSize
    
    ; Strict 64-bit alignment: (ByteSize + 63) & ~63
    add     rax, 63
    and     rax, -64

    ; Structural Overflow Check
    mov     rcx, rbx
    add     rcx, rax
    jc      _PoolExhausted

    ; Boundary Pool Limit Check: (ProposedEnd - PoolBase) <= PoolSize
    sub     rcx, [g_VRAMPoolBase]
    cmp     rcx, [g_VRAMPoolSize]
    ja      _PoolExhausted

    ; Write allocation descriptors
    mov     [r15 + 0], r12              ; XR_BINDING_ENTRY.TensorIdx
    mov     [r15 + 8], rbx              ; XR_BINDING_ENTRY.PhysicalBase

    ; Evaluate Operational Lifetimes for Kernel Lock Heuristics
    xor     edx, edx
    mov     r8d, [g_ExecNodeCount]
    cmp     r12, r8
    jae     _CommitFlags

    ; Correlate matching execution graph ranges 1:1
    lea     rcx, g_ExecNodes
    mov     rax, r12
    shl     rax, 5                      ; Index * 32
    
    mov     eax, [rcx + rax + 8]        ; XR_EXEC_NODE.FirstUse
    test    eax, eax
    jnz     _CommitFlags
    mov     edx, 1                      ; HOT Pipeline Allocation

_CommitFlags:
    mov     [r15 + 16], edx             ; XR_BINDING_ENTRY.LockFlags

    ; Advance
    mov     rax, [r14 + 16]
    add     rax, 63
    and     rax, -64
    add     rbx, rax
    add     r14, SIZEOF_XR_TENSOR_ENTRY
    add     r15, SIZEOF_XR_BINDING_ENTRY
    inc     r12
    jmp     _BindLoop

_PoolExhausted:
    mov     eax, 0BADF200h
    jmp     _ExitFinalizer

_BindDone:
    mov     [g_BindingCount], r12
    xor     eax, eax

_ExitFinalizer:
    add     rsp, 40
    pop     rbx
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret
XR_FinalizeTensorBindingTable ENDP

EXTERN XR_Emit_PE_Header : PROC

; -----------------------------------------------------------------------------------------
; XR_Seal_To_Artifact
; Inputs:  RCX = Buffer to receive the PE artifact
; Outputs: RAX = Size of generated binary
; -----------------------------------------------------------------------------------------
PUBLIC XR_Seal_To_Artifact
XR_Seal_To_Artifact PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 48

    mov     rbx, rcx                    ; rbx = Target Buffer
    
    ; [1] Emit PE Headers
    ; RCX = DestBuf, RDX = EntryPointRVA, R8 = ImageBase
    mov     rcx, rbx
    mov     edx, 1000h                  ; .text starts at 0x1000
    mov     r8, [g_VRAMPoolBase]        ; Use the VRAM Base as the virtual ImageBase
    call    XR_Emit_PE_Header
    
    mov     r12, rax                    ; r12 = Header Size

    ; [2] Copy Exec Nodes (The ".data" payload of the artifact)
    lea     rsi, [g_ExecNodes]
    mov     eax, [g_ExecNodeCount]
    shl     rax, 5                      ; NodeCount * 32
    mov     r13, rax                    ; r13 = Payload Size
    
    lea     rdi, [rbx + 1000h]          ; Move to Start of Section Data (simplified alignment)
    mov     rcx, r13
    rep     movsb

    ; [3] Return Total Artifact Size
    mov     rax, r12
    add     rax, 1000h                  ; Header + Padding
    add     rax, r13                    ; + Payload

    add     rsp, 48
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
XR_Seal_To_Artifact ENDP
PUBLIC XR_EmitGPUCommandStream
XR_EmitGPUCommandStream PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov rsi, rcx
    mov rdi, r8
    mov r15, r9
    xor rbx, rbx
    xor r12, r12
    xor r13, r13
loop_stream:
    cmp rbx, rdx
    jge emit_done
    mov rax, rbx
    shl rax, 6 ; 64B records
    mov ecx, [rsi + rax + 0]
    mov edx, [rsi + rax + 4]
    mov r8,  [rsi + rax + 16]
    mov r9,  [rsi + rax + 24]
    mov r10, [rsi + rax + 32]
    xor r11d, r11d
    cmp edx, 2 ; LANE_IO
    je lbl_op_prefetch
    cmp edx, 1 ; LANE_CPU
    je lbl_op_copy
    mov r11d, 0 ; OP_COMPUTE
    jmp emit_packet
lbl_op_copy:
    mov r11d, 1 ; OP_COPY
    jmp emit_packet
lbl_op_prefetch:
    mov r11d, 2 ; OP_PREFETCH
emit_packet:
    mov rax, r12
    shl rax, 6
    lea r14, [r15 + rax]
    mov [r14 + 0], ecx
    mov [r14 + 4], edx
    mov [r14 + 8], r11d
    mov [r14 + 12], r13d
    mov [r14 + 16], r8
    mov [r14 + 24], r9
    mov [r14 + 32], r10
    mov [r14 + 40], r13
    inc r13d
    inc r12
    inc rbx
    jmp loop_stream
emit_done:
    mov rax, r12
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
XR_EmitGPUCommandStream ENDP

; -----------------------------------------------------------------------------------------
; XR_Compiler_FusePass
; Populates g_ExecutionPlan with JIT-synthesized microkernels derived from the DAG
; -----------------------------------------------------------------------------------------
EXTERN XR_JIT_Emit_Kernel : PROC
EXTERN XR_JIT_Emit_LoadImm64 : PROC
EXTERN XR_JIT_Emit_LoopEnd : PROC
EXTERN XR_JIT_Emit_AddImm32 : PROC
EXTERN XR_Promote_To_Executable : PROC

XR_Compiler_FusePass PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 32

    ; 1. Resolve starting pointers
    lea     r12, g_ExecutionPlan        ; R12 = Plan Cursor
    lea     r13, g_JIT_StagingArea      ; R13 = JIT Staging Cursor
    
    ; Load Tensor/DAG Count
    mov     r14, [g_TensorCount]
    xor     rsi, rsi

@@fuse_loop:
    cmp     rsi, r14
    jae     @@fuse_terminate
    
    ; Load Compiler Node properties
    lea     rbx, g_CompileNodes
    mov     rax, SIZEOF XR_COMPILER_NODE
    imul    rax, rsi
    mov     r8d, dword ptr [rbx + rax]     ; [CompilerNode + 0] = TensorIndex
    mov     edx, dword ptr [rbx + rax + 4] ; [CompilerNode + 4] = LayerType
    
    test    edx, edx
    jz      @@fuse_next                 ; Skip unmapped / unrecognized operations
    
    ; Commit the unified block start address to the linear execution plan
    mov     [r12], r13
    add     r12, 8                      ; Advance plan cursor
    
    ; --- Dynamic Memory Binding Injection ---
    ; Emits 'mov rcx, [PhysicalBase]' into the stream to bind directly to hardware addresses
    push    rdx                         ; Preserve OpType
    push    r8                          ; Preserve TensorIndex
    lea     r9, g_TensorBindingTable
    mov     eax, r8d
    shl     rax, 5                      ; TensorIndex * 32 (SIZEOF_XR_BINDING_ENTRY)
    mov     r8, qword ptr [r9 + rax + 8] ; g_TensorBindingTable[TensorIndex].PhysicalBase
    mov     rdx, 1                      ; Target Register: RCX
    mov     rcx, r13                    ; Dest = Staging Area
    call    XR_JIT_Emit_LoadImm64       ; Inject literal payload address
    add     r13, rax                    ; Advance cursor
    pop     r8                          ; Restore TensorIndex

    ; --- Execution Dimension Routing ---
    ; Emits 'mov rdx, [ElementCount]' scaled for AVX-512 FMA vector lengths
    lea     r9, g_TensorRegistry
    mov     eax, r8d
    shl     rax, 5                      ; TensorIndex * 32 (SIZEOF_XR_TENSOR_ENTRY)
    mov     r8, qword ptr [r9 + rax + 16] ; XR_TENSOR_ENTRY.ElementCount
    shr     r8, 6                       ; SIMD Scale (ElementCount / 64 bytes)
    test    r8, r8
    jnz     @@record_loop_bound
    mov     r8, 1                       ; Clamp min 1 iteration
@@record_loop_bound:
    mov     rdx, 2                      ; Target Register: RDX
    mov     rcx, r13
    call    XR_JIT_Emit_LoadImm64       ; Inject iteration parameter
    add     r13, rax
    pop     rdx                         ; Restore OpType

    ; Snapshot internal loop target anchor
    mov     r15, r13

    ; --- JIT Operation Synthesis ---
    mov     rcx, r13                    ; Dest = Staging Area
    call    XR_JIT_Emit_Kernel
    add     r13, rax                    ; Advance cursor
    
    ; --- Stride Pointer Traversal ---
    ; Emits 'add rcx, 64' to advance physical pointer for AVX-512 chunk processing (ZMM = 64 bytes)
    mov     rcx, r13
    push    rdx                         ; Preserve OpType
    mov     rdx, 1                      ; Target Register: RCX
    mov     r8, 64                      ; Stride: 64 Bytes for ZMM
    call    XR_JIT_Emit_AddImm32
    pop     rdx                         ; Restore OpType
    add     r13, rax
    
    ; --- JIT Module Edge Linker / Loop Frame Terminator ---
    mov     rcx, r13
    push    rdx
    mov     rdx, r15                    ; Provide internal loop anchor target for backjump
    call    XR_JIT_Emit_LoopEnd
    pop     rdx
    add     r13, rax

@@fuse_next:
    inc     rsi
    jmp     @@fuse_loop

@@fuse_terminate:
    ; 4. Null-terminate the execution plan
    xor     rax, rax
    mov     [r12], rax

    ; 5. Secure memory and flush I-cache
    ; Calculate total size of emitted JIT code
    lea     rdx, g_JIT_StagingArea
    mov     rcx, rdx
    mov     rdx, r13
    sub     rdx, rcx                    ; RDX = Total bytes emitted
    
    call    XR_Promote_To_Executable    ; Applies VirtualProtect RX + FlushInstructionCache

    add     rsp, 32
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
XR_Compiler_FusePass ENDP

END
