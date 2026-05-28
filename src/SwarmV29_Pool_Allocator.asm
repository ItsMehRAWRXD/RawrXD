; ==============================================================================
; SwarmV29_Pool_Allocator.asm
; PHASE-29f: Cache-Aligned Slab Allocator
; Target: 70B @ 150TPS via Zero-Syscall Memory Management
; ------------------------------------------------------------------------------
; High-performance memory pool for PQC coefficient buffers.
; Eliminates VirtualAlloc syscall overhead by pre-reserving a large slab.
; All allocations are 64-byte aligned for AVX-512 vmovdqa64 compatibility.
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Dependencies: kernel32.lib (VirtualAlloc/VirtualFree)
;
; Pool Layout:
;   [PoolBase] -----> [Metadata: 64 bytes] -----> [Aligned Blocks...]
;   Metadata contains: PoolSize, UsedSize, BlockCount
;
; CRITICAL: Call Init_Pool once before any allocations.
;           Call Reset_Pool between PQC rounds (fast, no syscalls).
;           Call Destroy_Pool only when shutting down.
; ==============================================================================

EXTERN VirtualAlloc : PROC
EXTERN VirtualFree : PROC

; Pool Configuration Constants
POOL_SIZE_DEFAULT    EQU 1048576      ; 1 MB default pool
POOL_METADATA_SIZE   EQU 64           ; Metadata header size
POOL_ALIGNMENT       EQU 64           ; 64-byte alignment for AVX-512

.data

; Pool State (Global)
; Note: Using ALIGN 16 for MASM compatibility (64-byte alignment handled at runtime)
ALIGN 16

PoolBase    DQ 0                      ; Base address of reserved memory
PoolPtr     DQ 0                      ; Current allocation pointer
PoolLimit   DQ 0                      ; End of reserved memory
PoolSize    DQ 0                      ; Total pool size
AllocCount  DQ 0                      ; Number of allocations made
            DQ 0                      ; Padding to 64 bytes
            DQ 0
            DQ 0
            DQ 0
            DQ 0
            DQ 0

.code
ALIGN 16

; ==============================================================================
; SwarmV29_Init_Pool
; Initialize the memory pool with a default 1MB reservation.
; Input: RCX = Pool size in bytes (0 = use default 1MB)
; Output: RAX = Pool base address (0 on failure)
; ==============================================================================
SwarmV29_Init_Pool PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi
    sub rsp, 32                       ; Shadow space for VirtualAlloc

    ; Use default size if 0 specified
    test rcx, rcx
    jnz Custom_Size_PA
    mov rcx, POOL_SIZE_DEFAULT
    jmp Allocate_PA

Custom_Size_PA:
    ; Round up to 64KB page boundary
    add rcx, 65535
    and rcx, -65536

Allocate_PA:
    ; Save requested size
    mov rbx, rcx

    ; Call VirtualAlloc
    ; RCX = 0 (let system choose address)
    ; RDX = size
    ; R8 = MEM_COMMIT | MEM_RESERVE (0x3000)
    ; R9 = PAGE_READWRITE (0x04)
    xor rcx, rcx
    mov rdx, rbx
    mov r8, 03000h
    mov r9, 04h
    call VirtualAlloc

    ; Check for failure
    test rax, rax
    jz Error_PA

    ; Initialize pool state
    mov [PoolBase], rax
    mov [PoolPtr], rax
    mov [PoolSize], rbx

    ; Calculate limit
    add rax, rbx
    mov [PoolLimit], rax

    ; Reset allocation counter
    mov qword ptr [AllocCount], 0

    ; Return base address
    mov rax, [PoolBase]

    ; ABI Epilogue
    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

Error_PA:
    xor rax, rax                      ; Return NULL on failure
    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Init_Pool ENDP

; ==============================================================================
; SwarmV29_Alloc_Slab
; Allocate an aligned block from the pool.
; Input: RCX = Size in bytes (will be rounded up to 64-byte boundary)
; Output: RAX = Aligned pointer (0 on failure)
; Note: Zero-syscall allocation, just pointer arithmetic
; ==============================================================================
SwarmV29_Alloc_Slab PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi

    ; Get current pool pointer
    mov rax, [PoolPtr]
    test rax, rax
    jz Error_Not_Initialized_PA

    ; Align size to 64-byte boundary
    add rcx, 63
    and rcx, -64

    ; Calculate aligned allocation address
    mov rbx, rax
    add rbx, 63
    and rbx, -64                      ; Align to 64 bytes

    ; Calculate new pool pointer after allocation
    mov rdi, rbx
    add rdi, rcx

    ; Check bounds
    cmp rdi, [PoolLimit]
    ja Error_Out_Of_Memory_PA

    ; Update pool pointer
    mov [PoolPtr], rdi

    ; Increment allocation counter
    inc qword ptr [AllocCount]

    ; Return aligned pointer
    mov rax, rbx

    ; ABI Epilogue
    pop rdi
    pop rbx
    pop rbp
    ret

Error_Not_Initialized_PA:
    xor rax, rax
    pop rdi
    pop rbx
    pop rbp
    ret

Error_Out_Of_Memory_PA:
    xor rax, rax
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Alloc_Slab ENDP

; ==============================================================================
; SwarmV29_Reset_Pool
; Reset pool for reuse (fast, no syscalls).
; Input: None
; Output: RAX = 0 on success
; Note: Does NOT zero memory, just resets pointer
; ==============================================================================
SwarmV29_Reset_Pool PROC

    ; Reset pointer to base
    mov rax, [PoolBase]
    mov [PoolPtr], rax
    mov qword ptr [AllocCount], 0

    xor rax, rax
    ret

SwarmV29_Reset_Pool ENDP

; ==============================================================================
; SwarmV29_Destroy_Pool
; Release pool memory back to OS.
; Input: None
; Output: RAX = 0 on success, non-zero on failure
; ==============================================================================
SwarmV29_Destroy_Pool PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    sub rsp, 32                       ; Shadow space

    ; Get base address
    mov rcx, [PoolBase]
    test rcx, rcx
    jz Already_Destroyed_PA

    ; Call VirtualFree
    ; RCX = base address
    ; RDX = 0 (size, must be 0 for MEM_RELEASE)
    ; R8 = MEM_RELEASE (0x8000)
    xor rdx, rdx
    mov r8, 08000h
    call VirtualFree

    ; Clear pool state
    mov qword ptr [PoolBase], 0
    mov qword ptr [PoolPtr], 0
    mov qword ptr [PoolLimit], 0
    mov qword ptr [PoolSize], 0
    mov qword ptr [AllocCount], 0

    xor rax, rax

    ; ABI Epilogue
    add rsp, 32
    pop rbp
    ret

Already_Destroyed_PA:
    xor rax, rax
    add rsp, 32
    pop rbp
    ret

SwarmV29_Destroy_Pool ENDP

; ==============================================================================
; SwarmV29_Get_Pool_Stats
; Get current pool statistics.
; Input: None
; Output: RAX = Used bytes, RCX = Total bytes, RDX = Allocation count
; ==============================================================================
SwarmV29_Get_Pool_Stats PROC

    ; Calculate used bytes
    mov rax, [PoolPtr]
    sub rax, [PoolBase]

    ; Get total size
    mov rcx, [PoolSize]

    ; Get allocation count
    mov rdx, [AllocCount]

    ret

SwarmV29_Get_Pool_Stats ENDP

; ==============================================================================
; SwarmV29_Alloc_Slab_Zeroed
; Allocate and zero-initialize an aligned block.
; Input: RCX = Size in bytes
; Output: RAX = Aligned pointer (0 on failure)
; ==============================================================================
SwarmV29_Alloc_Slab_Zeroed PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi

    ; Allocate slab
    call SwarmV29_Alloc_Slab
    test rax, rax
    jz Error_Zero_PA

    ; Zero the memory
    mov rdi, rax
    mov rsi, rcx
    shr rsi, 3                        ; Divide by 8 (qword count)
    test rsi, rsi
    jz Done_Zero_PA

Zero_Loop_PA:
    mov qword ptr [rdi], 0
    add rdi, 8
    dec rsi
    jnz Zero_Loop_PA

Done_Zero_PA:
    ; RAX already contains pointer
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

Error_Zero_PA:
    xor rax, rax
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Alloc_Slab_Zeroed ENDP

; ==============================================================================
; SwarmV29_Alloc_NTT_Buffers
; Convenience function to allocate all NTT buffers at once.
; Input: RCX = Polynomial size N (e.g., 256 for Kyber)
; Output: RAX = Coefficients buffer, RCX = Twiddle buffer, RDX = Temp buffer
; ==============================================================================
SwarmV29_Alloc_NTT_Buffers PROC

    ; ABI Prologue
    push rbp
    mov rbp, rsp
    push rbx
    push rdi
    push rsi
    sub rsp, 32

    ; Save N
    mov rbx, rcx

    ; Calculate buffer sizes (N * 8 bytes for 64-bit coefficients)
    shl rbx, 3                        ; N * 8

    ; Allocate coefficient buffer
    mov rcx, rbx
    call SwarmV29_Alloc_Slab
    mov rsi, rax                      ; Save coeff buffer

    ; Allocate twiddle buffer
    mov rcx, rbx
    call SwarmV29_Alloc_Slab
    mov rdi, rax                      ; Save twiddle buffer

    ; Allocate temp buffer
    mov rcx, rbx
    call SwarmV29_Alloc_Slab

    ; Return values
    mov rax, rsi                      ; Coeff buffer
    mov rcx, rdi                      ; Twiddle buffer
    ; RDX already has temp buffer

    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

SwarmV29_Alloc_NTT_Buffers ENDP

END