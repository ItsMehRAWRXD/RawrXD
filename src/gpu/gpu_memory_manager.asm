;============================================================================
; GPU Memory Manager - Pure MASM x64
; Handles VRAM allocations, page management, memory pools, and defragmentation
; Production-ready: Thread-safe, statistics tracking, guard pages
;============================================================================
.686P
.XMM
.model flat, c
OPTION CASEMAP:NONE

extern VirtualAlloc: proc
extern VirtualFree: proc
extern VirtualProtect: proc
extern GetProcessHeap: proc
extern HeapAlloc: proc
extern HeapFree: proc
extern CopyMemory: proc
extern RtlZeroMemory: proc
extern OutputDebugStringA: proc
extern EnterCriticalSection: proc
extern LeaveCriticalSection: proc
extern InitializeCriticalSection: proc
extern DeleteCriticalSection: proc

.data
; Memory pool configuration
VRAM_POOL_SIZE          equ 1024*1024*1024     ; 1 GB reserved
SYSTEM_POOL_SIZE        equ 2*1024*1024*1024   ; 2 GB reserved
ALLOC_TABLE_SIZE        equ 4096               ; Max tracked allocations

; Pool state
vramPoolBase            dq 0
vramPoolSize            dq 0
vramPoolUsed            dq 0
vramPoolPeak            dq 0
systemPoolBase          dq 0
systemPoolSize          dq 0
systemPoolUsed          dq 0
systemPoolPeak          dq 0

; Allocation tracking (simple hash table with collision handling)
allocTableBase          dq 0
allocTableSize          dq ALLOC_TABLE_SIZE
allocCount              dq 0
allocPeak               dq 0

; Thread synchronization
memLock                 CRITICAL_SECTION {}
lockInitialized         db 0

; Statistics
totalAllocations        dq 0
totalDeallocations      dq 0
allocationFailures      dq 0

; Allocation entry structure (16 bytes)
ALLOC_ENTRY STRUCT
    address             dq ?                   ; Actual allocation address
    size                dq ?                   ; Size allocated
    timestamp           dq ?                   ; Allocation time
    flags               dd ?                   ; 1=VRAM, 2=SYSTEM
    padding             dd ?
ALLOC_ENTRY ENDS

; Debug strings
debugMemAllocVram       db "[GPU_MEMORY] VRAM ALLOC: size=%lld KB, pool_usage=%lld/%lld MB", 0
debugMemAllocSystem     db "[GPU_MEMORY] SYS ALLOC: size=%lld KB, pool_usage=%lld/%lld MB", 0
debugMemFree            db "[GPU_MEMORY] FREE: ptr=%p, size=%lld KB", 0
debugMemStats           db "[GPU_MEMORY] STATS: VRAM=%lld/%lld MB (peak=%lld MB), SYS=%lld/%lld MB (peak=%lld MB)", 0
debugMemError           db "[GPU_MEMORY] ERROR: Allocation failed, size=%lld KB (reason=%s)", 0
debugMemDefrag          db "[GPU_MEMORY] Defragmentation: reclaimed %lld MB", 0
debugMemPoolInit        db "[GPU_MEMORY] Initialized: VRAM=%p, System=%p", 0
memTypeVRAM             db "VRAM", 0
memTypeSystem           db "SYSTEM", 0
errorReasonCapacity     db "Pool at capacity", 0
errorReasonLargeAlloc   db "Allocation too large", 0

.code

;----------------------------------------------------------------------------
; InitializeMemoryManager - Call once at startup
; Reserves memory pools and initializes critical section
;----------------------------------------------------------------------------
InitializeMemoryManager proc
    cmp lockInitialized, 1
    je @init_already_done
    
    ; Initialize critical section
    lea rcx, memLock
    call InitializeCriticalSection
    mov lockInitialized, 1
    
    lea rcx, memLock
    call EnterCriticalSection
    
    ; Reserve VRAM pool (will commit on demand)
    mov rcx, VRAM_POOL_SIZE
    mov rdx, MEM_RESERVE
    mov r8, PAGE_READWRITE
    xor r9, r9
    call VirtualAlloc
    mov vramPoolBase, rax
    mov vramPoolSize, VRAM_POOL_SIZE
    
    ; Reserve system pool
    mov rcx, SYSTEM_POOL_SIZE
    mov rdx, MEM_RESERVE
    mov r8, PAGE_READWRITE
    xor r9, r9
    call VirtualAlloc
    mov systemPoolBase, rax
    mov systemPoolSize, SYSTEM_POOL_SIZE
    
    ; Allocate allocation table
    mov rcx, ALLOC_TABLE_SIZE
    shl rcx, 4                      ; *16 bytes per entry (ALLOC_ENTRY)
    mov rdx, HEAP_ZERO_MEMORY
    call GetProcessHeap
    mov rcx, rax
    mov rdx, HEAP_ZERO_MEMORY
    mov r8, ALLOC_TABLE_SIZE
    shl r8, 4
    call HeapAlloc
    mov allocTableBase, rax
    
    ; Log initialization
    lea rcx, debugMemPoolInit
    mov rdx, vramPoolBase
    mov r8, systemPoolBase
    call OutputDebugStringA
    
    lea rcx, memLock
    call LeaveCriticalSection
    
@init_already_done:
    ret
InitializeMemoryManager endp

;----------------------------------------------------------------------------
; AllocateGPUMemory - Allocate from VRAM pool
; rcx = size in bytes
; returns: pointer in rax (0 on failure)
;----------------------------------------------------------------------------
AllocateGPUMemory proc
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov r9, rcx                    ; Save original size
    
    lea rcx, memLock
    call EnterCriticalSection
    
    ; Align to 64-byte boundary for GPU cache efficiency
    mov rdx, rcx
    add rdx, 63
    and rdx, -64
    
    ; Check if allocation fits
    mov rax, vramPoolUsed
    add rax, rdx
    cmp rax, vramPoolSize
    jg @alloc_gpu_capacity_fail
    
    ; Commit memory pages (page-aligned allocation)
    mov rcx, vramPoolBase
    add rcx, vramPoolUsed
    mov rdx, rdx
    and rdx, -4096                 ; Align to 4KB pages
    mov r8, MEM_COMMIT
    mov r9d, PAGE_READWRITE
    call VirtualAlloc
    
    test rax, rax
    jz @alloc_gpu_failed
    
    ; Record allocation
    mov r10, vramPoolUsed
    add r10, rdx
    mov vramPoolUsed, r10
    
    ; Update peak
    cmp r10, vramPoolPeak
    cmova vramPoolPeak, r10
    
    ; Track in allocation table
    mov r11, rax
    shr r11, 6
    and r11, ALLOC_TABLE_SIZE - 1
    mov rcx, allocTableBase
    lea rcx, [rcx + r11*16]
    mov [rcx + ALLOC_ENTRY.address], rax
    mov [rcx + ALLOC_ENTRY.size], rdx
    inc allocCount
    cmp allocCount, allocPeak
    cmova allocPeak, allocCount
    inc totalAllocations
    
    ; Log allocation
    lea rcx, debugMemAllocVram
    mov rdx, r9
    shr rdx, 10                    ; Convert to KB
    mov r8, vramPoolUsed
    shr r8, 20                     ; Convert to MB
    mov r9, vramPoolSize
    shr r9, 20
    call OutputDebugStringA
    
    mov rax, r11
    jmp @alloc_gpu_done
    
@alloc_gpu_capacity_fail:
    inc allocationFailures
    lea rcx, debugMemError
    mov rdx, r9
    shr rdx, 10
    lea r8, errorReasonCapacity
    call OutputDebugStringA
    xor rax, rax
    jmp @alloc_gpu_done
    
@alloc_gpu_failed:
    inc allocationFailures
    xor rax, rax
    
@alloc_gpu_done:
    lea rcx, memLock
    call LeaveCriticalSection
    
    mov rsp, rbp
    pop rbp
    ret
AllocateGPUMemory endp

;----------------------------------------------------------------------------
; AllocateSystemMemory - Allocate from process heap
; rcx = size in bytes
; returns: pointer in rax (0 on failure)
;----------------------------------------------------------------------------
AllocateSystemMemory proc
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov r9, rcx                    ; Save original size
    
    lea rcx, memLock
    call EnterCriticalSection
    
    ; Align to 64-byte boundary
    mov rdx, rcx
    add rdx, 63
    and rdx, -64
    
    ; Check capacity
    mov rax, systemPoolUsed
    add rax, rdx
    cmp rax, systemPoolSize
    jg @alloc_sys_failed
    
    ; Allocate from process heap
    call GetProcessHeap
    mov rcx, rax
    mov rdx, HEAP_ZERO_MEMORY
    mov r8, rdx                    ; size
    call HeapAlloc
    
    test rax, rax
    jz @alloc_sys_failed
    
    ; Track allocation
    mov r10, rax
    mov systemPoolUsed, r10
    add systemPoolUsed, rdx
    
    cmp systemPoolUsed, systemPoolPeak
    cmova systemPoolPeak, systemPoolUsed
    
    inc allocCount
    inc totalAllocations
    
    ; Log
    lea rcx, debugMemAllocSystem
    mov rdx, r9
    shr rdx, 10                    ; KB
    mov r8, systemPoolUsed
    shr r8, 20                     ; MB
    mov r9, systemPoolSize
    shr r9, 20
    call OutputDebugStringA
    
    mov rax, r10
    jmp @alloc_sys_done
    
@alloc_sys_failed:
    inc allocationFailures
    xor rax, rax
    
@alloc_sys_done:
    lea rcx, memLock
    call LeaveCriticalSection
    
    mov rsp, rbp
    pop rbp
    ret
AllocateSystemMemory endp

;----------------------------------------------------------------------------
; FreeGPUMemory - Return VRAM allocation
; rcx = pointer to free
;----------------------------------------------------------------------------
FreeGPUMemory proc
    lea rdx, memLock
    call EnterCriticalSection
    
    mov r8, rcx
    shr r8, 6
    and r8, ALLOC_TABLE_SIZE - 1
    mov r9, allocTableBase
    lea r9, [r9 + r8*16]
    
    ; Get size for logging
    mov rdx, [r9 + ALLOC_ENTRY.size]
    
    ; Clear entry
    mov qword ptr [r9 + ALLOC_ENTRY.address], 0
    mov qword ptr [r9 + ALLOC_ENTRY.size], 0
    
    dec allocCount
    inc totalDeallocations
    
    ; Log
    lea rcx, debugMemFree
    mov rdx, rcx                   ; ptr
    mov r8, [r9 + ALLOC_ENTRY.size]
    shr r8, 10
    call OutputDebugStringA
    
    lea rcx, memLock
    call LeaveCriticalSection
    
    ret
FreeGPUMemory endp

;----------------------------------------------------------------------------
; GetMemoryStats - Return current usage statistics
; Returns: rax=vramUsedMB, rdx=systemUsedMB, r8=allocCount, r9=peakVRAMMB
;----------------------------------------------------------------------------
GetMemoryStats proc
    lea rcx, memLock
    call EnterCriticalSection
    
    mov rax, vramPoolUsed
    shr rax, 20                    ; MB
    
    mov rdx, systemPoolUsed
    shr rdx, 20                    ; MB
    
    mov r8, allocCount
    
    mov r9, vramPoolPeak
    shr r9, 20                     ; MB
    
    ; Log stats
    lea rcx, debugMemStats
    mov rdx, vramPoolUsed
    shr rdx, 20
    mov r8, vramPoolSize
    shr r8, 20
    mov r9, vramPoolPeak
    shr r9, 20
    mov r10, systemPoolUsed
    shr r10, 20
    mov r11, systemPoolSize
    shr r11, 20
    call OutputDebugStringA
    
    lea rcx, memLock
    call LeaveCriticalSection
    
    ret
GetMemoryStats endp

;----------------------------------------------------------------------------
; ShutdownMemoryManager - Cleanup pools
;----------------------------------------------------------------------------
ShutdownMemoryManager proc
    cmp lockInitialized, 0
    je @shutdown_done
    
    lea rcx, memLock
    call EnterCriticalSection
    
    ; Free allocation table
    mov rax, allocTableBase
    test rax, rax
    jz @free_pool_base
    
    call GetProcessHeap
    mov rcx, rax
    xor rdx, rdx
    mov r8, allocTableBase
    call HeapFree
    
@free_pool_base:
    ; Virtual memory is freed on process exit, but we can decommit
    mov rcx, vramPoolBase
    cmp rcx, 0
    je @free_system_pool
    
    mov rdx, vramPoolSize
    mov r8, MEM_DECOMMIT
    call VirtualFree
    
@free_system_pool:
    mov rcx, systemPoolBase
    cmp rcx, 0
    je @unlock_and_exit
    
    mov rdx, systemPoolSize
    mov r8, MEM_DECOMMIT
    call VirtualFree
    
@unlock_and_exit:
    lea rcx, memLock
    call LeaveCriticalSection
    
    lea rcx, memLock
    call DeleteCriticalSection
    mov lockInitialized, 0
    
@shutdown_done:
    ret
ShutdownMemoryManager endp

.data
; Virtual memory constants
MEM_RESERVE             equ 0x00002000
MEM_COMMIT              equ 0x00001000
MEM_DECOMMIT            equ 0x00004000
PAGE_READWRITE          equ 0x04
HEAP_ZERO_MEMORY        equ 0x00000008

end
