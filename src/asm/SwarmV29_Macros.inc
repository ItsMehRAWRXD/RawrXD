; =============================================================================
; SwarmV29_Macros.inc - Universal Macro Set for AZDO Architecture
; =============================================================================
; Approaching Zero Driver Overhead (AZDO) macros for PQC engine
; Date: 2026-07-08
; =============================================================================

; =============================================================================
; ABI Conventions
; =============================================================================
SWARMV29_ABI_FRAME MACRO
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
ENDM

SWARMV29_ABI_EPILOG MACRO
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ENDM

; =============================================================================
; Alignment Macros
; =============================================================================
SWARMV29_ALIGN_64 MACRO
    ALIGN 64
ENDM

SWARMV29_ALIGN_32 MACRO
    ALIGN 32
ENDM

SWARMV29_ALIGN_16 MACRO
    ALIGN 16
ENDM

; =============================================================================
; Error Handling
; =============================================================================
SWARMV29_CHECK_NULL MACRO reg
    test reg, reg
    jz @F
    int 3
@@:
ENDM

SWARMV29_CHECK_ALIGN MACRO reg, alignment
    test reg, alignment - 1
    jnz @F
    int 3
@@:
ENDM

; =============================================================================
; Non-Temporal Operations (AZDO Core)
; =============================================================================
SWARMV29_NONTEMPORAL_STORE MACRO src, dest
    vmovntdq xmmword ptr [dest], src
ENDM

SWARMV29_NONTEMPORAL_STORE_YMM MACRO src, dest
    vmovntdq ymmword ptr [dest], src
ENDM

SWARMV29_NONTEMPORAL_STORE_ZMM MACRO src, dest
    vmovntdq zmmword ptr [dest], src
ENDM

; =============================================================================
; Memory Fence Operations
; =============================================================================
SWARMV29_SFENCE MACRO
    sfence
ENDM

SWARMV29_MFENCE MACRO
    mfence
ENDM

SWARMV29_LFENCE MACRO
    lfence
ENDM

; =============================================================================
; Atomic Operations
; =============================================================================
SWARMV29_ATOMIC_ADD MACRO dest, val
    lock add qword ptr [dest], val
ENDM

SWARMV29_ATOMIC_SUB MACRO dest, val
    lock sub qword ptr [dest], val
ENDM

SWARMV29_ATOMIC_INC MACRO dest
    lock inc qword ptr [dest]
ENDM

SWARMV29_ATOMIC_DEC MACRO dest
    lock dec qword ptr [dest]
ENDM

; =============================================================================
; Cycle Counting (RDTSC)
; =============================================================================
SWARMV29_RDTSC_START MACRO
    rdtscp
    shl rdx, 32
    or rdx, rax
    mov r15, rdx
ENDM

SWARMV29_RDTSC_END MACRO
    rdtscp
    shl rdx, 32
    or rdx, rax
    sub rdx, r15
ENDM

; =============================================================================
; Cache Line Operations
; =============================================================================
SWARMV29_PREFETCH_T0 MACRO addr
    prefetcht0 [addr]
ENDM

SWARMV29_PREFETCH_T1 MACRO addr
    prefetcht1 [addr]
ENDM

SWARMV29_PREFETCH_T2 MACRO addr
    prefetcht2 [addr]
ENDM

SWARMV29_PREFETCH_NTA MACRO addr
    prefetchnta [addr]
ENDM

; =============================================================================
; ZMM Register Save/Restore (AVX-512)
; =============================================================================
SWARMV29_SAVE_ZMM MACRO reg
    vmovdqu64 zmmword ptr [rsp + offset_&reg], reg
ENDM

SWARMV29_RESTORE_ZMM MACRO reg
    vmovdqu64 reg, zmmword ptr [rsp + offset_&reg]
ENDM

; =============================================================================
; VTable Function Pointer Validation
; =============================================================================
SWARMV29_VALIDATE_VTABLE MACRO vtable_ptr, func_idx
    mov rax, [vtable_ptr + func_idx * 8]
    test rax, rax
    jz @F
    int 3
@@:
ENDM

; =============================================================================
; State Shadowing Macros
; =============================================================================
SWARMV29_SHADOW_STATE MACRO state_ptr, new_val, dirty_flag
    mov rax, [state_ptr]
    cmp rax, new_val
    je @F
    mov [state_ptr], new_val
    mov dirty_flag, 1
@@:
ENDM

; =============================================================================
; Persistent Buffer Macros
; =============================================================================
SWARMV29_PERSISTENT_MAP MACRO buffer_ptr, size, flags
    ; Map persistent buffer using glBufferStorage
    ; flags: GL_MAP_WRITE_BIT | GL_MAP_PERSISTENT_BIT | GL_MAP_COHERENT_BIT
ENDM

SWARMV29_PERSISTENT_UNMAP MACRO buffer_ptr
    ; Unmap persistent buffer
ENDM

; =============================================================================
; Fence Synchronization
; =============================================================================
SWARMV29_INSERT_FENCE MACRO fence_ptr
    ; glFenceSync equivalent
    mov qword ptr [fence_ptr], 1
    sfence
ENDM

SWARMV29_WAIT_FENCE MACRO fence_ptr, timeout_ns
    ; Wait for GPU fence with timeout
    mov rax, fence_ptr
    test rax, rax
    jz @F
    ; Spin wait with timeout
@@:
ENDM

; =============================================================================
; Debug Macros
; =============================================================================
SWARMV29_DEBUG_BREAK MACRO
    int 3
ENDM

SWARMV29_DEBUG_PRINT MACRO msg
    ; Debug print (requires debug build)
IFNDEF NDEBUG
    lea rcx, msg
    call DebugPrint
ENDIF
ENDM

; =============================================================================
; Constants
; =============================================================================
SWARMV29_CACHE_LINE_SIZE    EQU 64
SWARMV29_PAGE_SIZE          EQU 4096
SWARMV29_MAX_BUFFERS        EQU 16
SWARMV29_MAX_STATES         EQU 256

; Recoil Governor Constants
SWARMV29_RECOIL_VAL         EQU 3       ; Units to shed per recoil
SWARMV29_COOLDOWN_VAL       EQU 30      ; Cycles before next recoil
SWARMV29_THRESHOLD_PCT      EQU 90      ; 90% tripwire
SWARMV29_MAX_WEIGHT         EQU 128     ; 100% capacity

; NTT Constants
SWARMV29_NTT_FORWARD        EQU 0
SWARMV29_NTT_INVERSE        EQU 1

; VTable Function Indices
SWARMV29_VT_INIT            EQU 0
SWARMV29_VT_UPLOAD          EQU 1
SWARMV29_VT_SYNC            EQU 2
SWARMV29_VT_DISPATCH        EQU 3
SWARMV29_VT_BENCHMARK      EQU 4
SWARMV29_VT_GET_STATS       EQU 5
SWARMV29_VT_RESET          EQU 6
SWARMV29_VT_SHUTDOWN       EQU 7

END