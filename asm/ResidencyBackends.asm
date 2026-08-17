;=============================================================================
; ResidencyBackends.asm
; Gate 1: Clock-hand eviction (RAM hot -> SSD warm)
; Gate 2: GPU upload kernel (Vulkan + ROCm concrete paths)
; Gate 3: Async SSD write-back (overlapped I/O worker thread)
; x64 MASM | Zero dependencies | RawrXD Sovereign Engine
; Assemble: ml64 /c /FoResidencyBackends.obj ResidencyBackends.asm
;=============================================================================

OPTION CASEMAP:NONE

;-----------------------------------------------------------------------------
; External Windows API declarations
;-----------------------------------------------------------------------------
EXTERNDEF VirtualAlloc:PROC
EXTERNDEF VirtualFree:PROC
EXTERNDEF CreateThread:PROC
EXTERNDEF ExitThread:PROC
EXTERNDEF CreateEventA:PROC
EXTERNDEF SetEvent:PROC
EXTERNDEF ResetEvent:PROC
EXTERNDEF WaitForSingleObject:PROC
EXTERNDEF WaitForMultipleObjects:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF GetLastError:PROC
EXTERNDEF LoadLibraryA:PROC
EXTERNDEF GetProcAddress:PROC
EXTERNDEF CloseHandle:PROC

;-----------------------------------------------------------------------------
; Exports
;-----------------------------------------------------------------------------
PUBLIC DRP_RunEvictionScan
PUBLIC DRP_InitGPUBackend
PUBLIC DRP_UploadVRAMBlocks
PUBLIC DRP_StartFlushWorker
PUBLIC DRP_StopFlushWorker
PUBLIC DRP_EnqueueSSDFlush
PUBLIC DRP_TouchWeight

;-----------------------------------------------------------------------------
; Constants
;-----------------------------------------------------------------------------
TIER_SSD          EQU 0
TIER_RAM          EQU 1
TIER_VRAM         EQU 2

BLOCK_STATE_CLEAN EQU 0
BLOCK_STATE_DIRTY EQU 1
BLOCK_STATE_FLUSH EQU 2

GPU_TYPE_NONE     EQU 0
GPU_TYPE_VULKAN   EQU 1
GPU_TYPE_ROCM     EQU 2

INFINITE          EQU 0FFFFFFFFh
WAIT_OBJECT_0     EQU 0
ERROR_IO_PENDING  EQU 997

;-----------------------------------------------------------------------------
; Structures (mirrored from DynamicResidencyPool.asm + extensions)
;-----------------------------------------------------------------------------
DYNAMIC_BLOCK STRUCT
    BlockID         DWORD   ?
    Tier            BYTE    ?
    State           BYTE    ?
    RefCount        WORD    ?
    LastAccess      QWORD   ?
    DataPtr         QWORD   ?
    NextLRU         QWORD   ?
    PrevLRU         QWORD   ?
    AccessCount     DWORD   ?
    Referenced      BYTE    ?
    _pad            BYTE    3 DUP (?)
DYNAMIC_BLOCK ENDS

DYNAMIC_TIER STRUCT
    BasePtr         QWORD   ?
    Capacity        QWORD   ?
    Used            QWORD   ?
    BlockSize       DWORD   ?
    MaxBlocks       DWORD   ?
    FreeList        QWORD   ?
    SpinLock        DWORD   ?
    hFile           QWORD   ?
DYNAMIC_TIER ENDS

RESIDENCY_POOL STRUCT
    SSD             DYNAMIC_TIER    <>
    RAM             DYNAMIC_TIER    <>
    VRAM            DYNAMIC_TIER    <>
    BlockTable      QWORD   ?
    BlockIndex      QWORD   ?
    TotalBlocks     DWORD   ?
    ClockHand       DWORD   ?
    GlobalLock      DWORD   ?
    CycleCounter    QWORD   ?
RESIDENCY_POOL ENDS

MY_OVERLAPPED STRUCT
    Internal        QWORD   ?
    InternalHigh    QWORD   ?
    _Offset         DWORD   ?
    OffsetHigh      DWORD   ?
    hEvent          QWORD   ?
MY_OVERLAPPED ENDS

FLUSH_JOB STRUCT
    BlockID         DWORD   ?
    _pad            DWORD   ?
    SrcPtr          QWORD   ?
    DstOffset       QWORD   ?
    ByteSize        DWORD   ?
    _pad2           DWORD   ?
    Ovlp            MY_OVERLAPPED   <>
FLUSH_JOB ENDS

SSD_FLUSH_QUEUE STRUCT
    Jobs            QWORD   ?
    Head            DWORD   ?
    Tail            DWORD   ?
    Capacity        DWORD   ?
    _pad            DWORD   ?
    SpinLock        DWORD   ?
    _pad2           DWORD   ?
    hNotify         QWORD   ?
SSD_FLUSH_QUEUE ENDS

EVICTION_CTX STRUCT
    ClockHand       DWORD   ?
    _pad            DWORD   ?
    ThresholdCycles QWORD   ?
    PressureLimit   QWORD   ?
    EvictedCount    QWORD   ?
    FlushedCount    QWORD   ?
EVICTION_CTX ENDS

VULKAN_TABLE STRUCT
    vkMapMemory             QWORD   ?
    vkUnmapMemory           QWORD   ?
    vkCmdCopyBuffer         QWORD   ?
    vkQueueSubmit           QWORD   ?
    vkWaitForFences         QWORD   ?
    vkResetFences           QWORD   ?
    vkResetCommandBuffer    QWORD   ?
    vkBeginCommandBuffer    QWORD   ?
    vkEndCommandBuffer      QWORD   ?
    vkAllocateCommandBuffers QWORD  ?
    vkFreeCommandBuffers    QWORD   ?
VULKAN_TABLE ENDS

ROCM_TABLE STRUCT
    hipMemcpyAsync          QWORD   ?
    hipStreamSynchronize    QWORD   ?
    hipMalloc               QWORD   ?
    hipFree                 QWORD   ?
    hipEventCreate          QWORD   ?
    hipEventRecord          QWORD   ?
    hipEventSynchronize     QWORD   ?
ROCM_TABLE ENDS

GPU_BACKEND STRUCT
    GpuType         DWORD   ?
    _pad            DWORD   ?
    Device          QWORD   ?
    Queue           QWORD   ?
    CmdBuffer       QWORD   ?
    Fence           QWORD   ?
    StagingPtr      QWORD   ?
    StagingSize     QWORD   ?
    DeviceBuffer    QWORD   ?
    FnTable         QWORD   ?
GPU_BACKEND ENDS

FLUSH_WORKER STRUCT
    hThread         QWORD   ?
    hShutdown       QWORD   ?
    Running         DWORD   ?
    _pad            DWORD   ?
    Queue           SSD_FLUSH_QUEUE <>
FLUSH_WORKER ENDS

BACKEND_CTX STRUCT
    Pool            QWORD   ?
    Eviction        EVICTION_CTX   <>
    GPU             GPU_BACKEND    <>
    Flush           FLUSH_WORKER   <>
BACKEND_CTX ENDS

;-----------------------------------------------------------------------------
; Data section
;-----------------------------------------------------------------------------
.DATA
ALIGN 16
    RB_Signature    DQ 0F00F164734500FFh
    RB_Version      DD 011h

    szVulkanDll     DB "vulkan-1.dll", 0
    szRocmDll       DB "amdhip64.dll", 0

    szvkMapMemory           DB "vkMapMemory", 0
    szvkUnmapMemory         DB "vkUnmapMemory", 0
    szvkCmdCopyBuffer       DB "vkCmdCopyBuffer", 0
    szvkQueueSubmit         DB "vkQueueSubmit", 0
    szvkWaitForFences       DB "vkWaitForFences", 0
    szvkResetFences         DB "vkResetFences", 0
    szvkResetCommandBuffer  DB "vkResetCommandBuffer", 0
    szvkBeginCommandBuffer  DB "vkBeginCommandBuffer", 0
    szvkEndCommandBuffer    DB "vkEndCommandBuffer", 0
    szvkAllocateCommandBuffers DB "vkAllocateCommandBuffers", 0
    szvkFreeCommandBuffers  DB "vkFreeCommandBuffers", 0

    szhipMemcpyAsync        DB "hipMemcpyAsync", 0
    szhipStreamSynchronize  DB "hipStreamSynchronize", 0
    szhipMalloc             DB "hipMalloc", 0
    szhipFree               DB "hipFree", 0
    szhipEventCreate        DB "hipEventCreate", 0
    szhipEventRecord        DB "hipEventRecord", 0
    szhipEventSynchronize   DB "hipEventSynchronize", 0

;-----------------------------------------------------------------------------
; Code section
;-----------------------------------------------------------------------------
.CODE

;=============================================================================
; DRP_RunEvictionScan
; Clock-hand eviction: demote clean, unreferenced RAM blocks to SSD.
; RCX = RESIDENCY_POOL*, RDX = BACKEND_CTX*
; Returns RAX = number evicted this scan
;=============================================================================
DRP_RunEvictionScan PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    .endprolog

    mov     r14, rcx                ; r14 = pool
    mov     r15, rdx                ; r15 = backend_ctx

    ; Check RAM pressure
    mov     rax, [r14].RESIDENCY_POOL.RAM.Used
    cmp     rax, [r15].BACKEND_CTX.Eviction.PressureLimit
    jb      @evict_none

    ; Acquire global spinlock
@spin_pool:
    mov     eax, 1
    xchg    eax, DWORD PTR [r14].RESIDENCY_POOL.GlobalLock
    test    eax, eax
    jnz     @spin_pool

    mov     r12d, [r14].RESIDENCY_POOL.ClockHand
    mov     r13d, [r14].RESIDENCY_POOL.TotalBlocks
    xor     ebx, ebx                ; evicted count
    mov     rsi, [r14].RESIDENCY_POOL.BlockTable
    mov     r8d, [r14].RESIDENCY_POOL.RAM.BlockSize

@evict_loop:
    cmp     ebx, 64                 ; throttle: max 64 per scan
    jae     @evict_done
    mov     rax, [r14].RESIDENCY_POOL.RAM.Used
    cmp     rax, [r15].BACKEND_CTX.Eviction.PressureLimit
    jb      @evict_done

    ; Get block at clock hand
    mov     eax, r12d
    imul    rax, SIZEOF DYNAMIC_BLOCK
    lea     rdi, [rsi + rax]        ; rdi = current block

    ; Only evict from RAM
    cmp     BYTE PTR [rdi + DYNAMIC_BLOCK.Tier], TIER_RAM
    jne     @evict_next

    ; Check refcount (pinned?)
    cmp     WORD PTR [rdi + DYNAMIC_BLOCK.RefCount], 0
    jne     @evict_next

    ; Referenced-bit second chance (consumed from TouchWeight)
    cmp     BYTE PTR [rdi + DYNAMIC_BLOCK.Referenced], 0
    jne     @evict_chance

    ; Age check: if recently accessed, give second chance
    mov     rax, [r14].RESIDENCY_POOL.CycleCounter
    sub     rax, [rdi + DYNAMIC_BLOCK.LastAccess]
    cmp     rax, [r15].BACKEND_CTX.Eviction.ThresholdCycles
    jb      @evict_chance

    ; Must be clean to evict (dirty blocks are flushed by worker)
    cmp     BYTE PTR [rdi + DYNAMIC_BLOCK.State], BLOCK_STATE_CLEAN
    jne     @evict_next

    ; Demote: RAM -> SSD
    ; DataPtr = SSD_Base + BlockID * BlockSize
    mov     eax, [rdi + DYNAMIC_BLOCK.BlockID]
    ; eax already zero-extends to rax in x64
    mov     r10d, [r14].RESIDENCY_POOL.SSD.BlockSize
    imul    rax, r10
    add     rax, [r14].RESIDENCY_POOL.SSD.BasePtr
    mov     [rdi + DYNAMIC_BLOCK.DataPtr], rax
    mov     BYTE PTR [rdi + DYNAMIC_BLOCK.Tier], TIER_SSD
    mov     BYTE PTR [rdi + DYNAMIC_BLOCK.State], BLOCK_STATE_CLEAN

    ; Decrement RAM used
    sub     QWORD PTR [r14].RESIDENCY_POOL.RAM.Used, r8
    inc     ebx
    inc     QWORD PTR [r15].BACKEND_CTX.Eviction.EvictedCount
    jmp     @evict_next

@evict_chance:
    ; Clear referenced bit and update LastAccess to now (second chance)
    mov     BYTE PTR [rdi + DYNAMIC_BLOCK.Referenced], 0
    mov     rax, [r14].RESIDENCY_POOL.CycleCounter
    mov     [rdi + DYNAMIC_BLOCK.LastAccess], rax

@evict_next:
    inc     r12d
    cmp     r12d, r13d
    jb      @evict_ckwrap
    xor     r12d, r12d              ; wrap clock hand
@evict_ckwrap:
    cmp     r12d, [r14].RESIDENCY_POOL.ClockHand
    jne     @evict_loop
    ; Full circle without progress — stop to avoid livelock

@evict_done:
    mov     [r14].RESIDENCY_POOL.ClockHand, r12d
    mov     DWORD PTR [r14].RESIDENCY_POOL.GlobalLock, 0
    mov     eax, ebx
    jmp     @evict_exit

@evict_none:
    xor     eax, eax

@evict_exit:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DRP_RunEvictionScan ENDP

;=============================================================================
; DRP_InitGPUBackend
; Dynamically loads Vulkan or ROCm DLL and populates function table.
; RCX = BACKEND_CTX*, RDX = type (1=Vulkan, 2=ROCm), R8 = device, R9 = queue
; Returns RAX = 0 on success, -1 on failure
;=============================================================================
DRP_InitGPUBackend PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    .endprolog

    mov     r12, rcx                ; r12 = backend_ctx
    mov     r13d, edx               ; r13d = type
    mov     [r12].BACKEND_CTX.GPU.GpuType, r13d
    mov     [r12].BACKEND_CTX.GPU.Device, r8
    mov     [r12].BACKEND_CTX.GPU.Queue, r9

    cmp     r13d, GPU_TYPE_VULKAN
    je      @init_vulkan
    cmp     r13d, GPU_TYPE_ROCM
    je      @init_rocm
    jmp     @init_fail

@init_vulkan:
    ; Allocate VULKAN_TABLE
    mov     rcx, SIZEOF VULKAN_TABLE
    xor     edx, edx
    mov     r8, 3000h               ; MEM_COMMIT | MEM_RESERVE
    mov     r9, 4                   ; PAGE_READWRITE
    sub     rsp, 40
    call    VirtualAlloc
    add     rsp, 40
    test    rax, rax
    jz      @init_fail
    mov     [r12].BACKEND_CTX.GPU.FnTable, rax
    mov     r14, rax                ; r14 = vtable

    ; Load vulkan-1.dll
    lea     rcx, szVulkanDll
    sub     rsp, 40
    call    LoadLibraryA
    add     rsp, 40
    test    rax, rax
    jz      @init_fail
    mov     r15, rax                ; r15 = hModule

    ; Load function pointers
    mov     rcx, r15
    lea     rdx, szvkMapMemory
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkMapMemory, rax

    mov     rcx, r15
    lea     rdx, szvkUnmapMemory
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkUnmapMemory, rax

    mov     rcx, r15
    lea     rdx, szvkCmdCopyBuffer
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkCmdCopyBuffer, rax

    mov     rcx, r15
    lea     rdx, szvkQueueSubmit
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkQueueSubmit, rax

    mov     rcx, r15
    lea     rdx, szvkWaitForFences
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkWaitForFences, rax

    mov     rcx, r15
    lea     rdx, szvkResetFences
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkResetFences, rax

    mov     rcx, r15
    lea     rdx, szvkResetCommandBuffer
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkResetCommandBuffer, rax

    mov     rcx, r15
    lea     rdx, szvkBeginCommandBuffer
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkBeginCommandBuffer, rax

    mov     rcx, r15
    lea     rdx, szvkEndCommandBuffer
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkEndCommandBuffer, rax

    mov     rcx, r15
    lea     rdx, szvkAllocateCommandBuffers
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkAllocateCommandBuffers, rax

    mov     rcx, r15
    lea     rdx, szvkFreeCommandBuffers
    call    DRP_GetProc
    mov     [r14].VULKAN_TABLE.vkFreeCommandBuffers, rax

    xor     eax, eax
    jmp     @init_exit

@init_rocm:
    ; Allocate ROCM_TABLE
    mov     rcx, SIZEOF ROCM_TABLE
    xor     edx, edx
    mov     r8, 3000h
    mov     r9, 4
    sub     rsp, 40
    call    VirtualAlloc
    add     rsp, 40
    test    rax, rax
    jz      @init_fail
    mov     [r12].BACKEND_CTX.GPU.FnTable, rax
    mov     r14, rax

    ; Load amdhip64.dll
    lea     rcx, szRocmDll
    sub     rsp, 40
    call    LoadLibraryA
    add     rsp, 40
    test    rax, rax
    jz      @init_fail
    mov     r15, rax

    mov     rcx, r15
    lea     rdx, szhipMemcpyAsync
    call    DRP_GetProc
    mov     [r14].ROCM_TABLE.hipMemcpyAsync, rax

    mov     rcx, r15
    lea     rdx, szhipStreamSynchronize
    call    DRP_GetProc
    mov     [r14].ROCM_TABLE.hipStreamSynchronize, rax

    mov     rcx, r15
    lea     rdx, szhipMalloc
    call    DRP_GetProc
    mov     [r14].ROCM_TABLE.hipMalloc, rax

    mov     rcx, r15
    lea     rdx, szhipFree
    call    DRP_GetProc
    mov     [r14].ROCM_TABLE.hipFree, rax

    mov     rcx, r15
    lea     rdx, szhipEventCreate
    call    DRP_GetProc
    mov     [r14].ROCM_TABLE.hipEventCreate, rax

    mov     rcx, r15
    lea     rdx, szhipEventRecord
    call    DRP_GetProc
    mov     [r14].ROCM_TABLE.hipEventRecord, rax

    mov     rcx, r15
    lea     rdx, szhipEventSynchronize
    call    DRP_GetProc
    mov     [r14].ROCM_TABLE.hipEventSynchronize, rax

    xor     eax, eax
    jmp     @init_exit

@init_fail:
    mov     eax, -1

@init_exit:
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DRP_InitGPUBackend ENDP

;-----------------------------------------------------------------------------
; Private helper: DRP_GetProc
; RCX = hModule, RDX = name
; Returns RAX = function pointer (NULL on failure)
;-----------------------------------------------------------------------------
DRP_GetProc PROC PRIVATE
    sub     rsp, 40
    call    GetProcAddress
    add     rsp, 40
    ret
DRP_GetProc ENDP

;=============================================================================
; DRP_UploadVRAMBlocks
; Iterates VRAM tier, uploads dirty blocks from RAM via GPU backend.
; RCX = BACKEND_CTX*
; Returns RAX = number of blocks uploaded
;=============================================================================
DRP_UploadVRAMBlocks PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    .endprolog

    mov     r12, rcx                ; r12 = backend_ctx
    mov     r13, [r12].BACKEND_CTX.Pool

    cmp     [r12].BACKEND_CTX.GPU.GpuType, GPU_TYPE_VULKAN
    je      @upload_vulkan
    cmp     [r12].BACKEND_CTX.GPU.GpuType, GPU_TYPE_ROCM
    je      @upload_rocm
    jmp     @upload_done

@upload_vulkan:
    mov     rsi, [r13].RESIDENCY_POOL.BlockTable
    mov     ebx, [r13].RESIDENCY_POOL.TotalBlocks
    xor     r15d, r15d              ; uploaded count

@vk_scan:
    test    ebx, ebx
    jz      @vk_done
    cmp     BYTE PTR [rsi + DYNAMIC_BLOCK.Tier], TIER_VRAM
    jne     @vk_next
    cmp     BYTE PTR [rsi + DYNAMIC_BLOCK.State], BLOCK_STATE_DIRTY
    jne     @vk_next

    ; Find RAM copy
    mov     ecx, [rsi + DYNAMIC_BLOCK.BlockID]
    mov     rdx, r13
    call    DRP_FindRAMCopy
    test    rax, rax
    jz      @vk_next

    ; Upload: rax = RAM src, [rsi].DataPtr = VRAM dst
    mov     rcx, r12
    mov     rdx, rax
    mov     r8, [rsi + DYNAMIC_BLOCK.DataPtr]
    mov     r9d, [r13].RESIDENCY_POOL.VRAM.BlockSize
    push    rsi
    push    rbx
    push    r15
    sub     rsp, 40
    call    DRP_VulkanUploadSingle
    add     rsp, 40
    pop     r15
    pop     rbx
    pop     rsi
    test    eax, eax
    jnz     @vk_next

    mov     BYTE PTR [rsi + DYNAMIC_BLOCK.State], BLOCK_STATE_CLEAN
    inc     r15d

@vk_next:
    add     rsi, SIZEOF DYNAMIC_BLOCK
    dec     ebx
    jmp     @vk_scan

@vk_done:
    mov     eax, r15d
    jmp     @upload_exit

@upload_rocm:
    mov     rsi, [r13].RESIDENCY_POOL.BlockTable
    mov     ebx, [r13].RESIDENCY_POOL.TotalBlocks
    xor     r15d, r15d

@rocm_scan:
    test    ebx, ebx
    jz      @rocm_done
    cmp     BYTE PTR [rsi + DYNAMIC_BLOCK.Tier], TIER_VRAM
    jne     @rocm_next
    cmp     BYTE PTR [rsi + DYNAMIC_BLOCK.State], BLOCK_STATE_DIRTY
    jne     @rocm_next

    mov     ecx, [rsi + DYNAMIC_BLOCK.BlockID]
    mov     rdx, r13
    call    DRP_FindRAMCopy
    test    rax, rax
    jz      @rocm_next

    mov     rcx, r12
    mov     rdx, rax
    mov     r8, [rsi + DYNAMIC_BLOCK.DataPtr]
    mov     r9d, [r13].RESIDENCY_POOL.VRAM.BlockSize
    push    rsi
    push    rbx
    push    r15
    sub     rsp, 40
    call    DRP_ROCmUploadSingle
    add     rsp, 40
    pop     r15
    pop     rbx
    pop     rsi
    test    eax, eax
    jnz     @rocm_next

    mov     BYTE PTR [rsi + DYNAMIC_BLOCK.State], BLOCK_STATE_CLEAN
    inc     r15d

@rocm_next:
    add     rsi, SIZEOF DYNAMIC_BLOCK
    dec     ebx
    jmp     @rocm_scan

@rocm_done:
    mov     eax, r15d
    jmp     @upload_exit

@upload_done:
    xor     eax, eax

@upload_exit:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DRP_UploadVRAMBlocks ENDP

;-----------------------------------------------------------------------------
; Private: DRP_FindRAMCopy
; Find a RAM-resident copy of a given BlockID.
; RCX = BlockID, RDX = RESIDENCY_POOL*
; Returns RAX = DataPtr of RAM copy, or 0 if not found
;-----------------------------------------------------------------------------
DRP_FindRAMCopy PROC PRIVATE
    push    rsi
    push    rbx
    mov     ebx, ecx                ; ebx = BlockID
    mov     rsi, [rdx].RESIDENCY_POOL.BlockTable
    mov     ecx, [rdx].RESIDENCY_POOL.TotalBlocks

@find_loop:
    test    ecx, ecx
    jz      @find_fail
    cmp     [rsi + DYNAMIC_BLOCK.BlockID], ebx
    jne     @find_next
    cmp     BYTE PTR [rsi + DYNAMIC_BLOCK.Tier], TIER_RAM
    jne     @find_next
    mov     rax, [rsi + DYNAMIC_BLOCK.DataPtr]
    pop     rbx
    pop     rsi
    ret

@find_next:
    add     rsi, SIZEOF DYNAMIC_BLOCK
    dec     ecx
    jmp     @find_loop

@find_fail:
    xor     eax, eax
    pop     rbx
    pop     rsi
    ret
DRP_FindRAMCopy ENDP

;-----------------------------------------------------------------------------
; Private: DRP_VulkanUploadSingle
; Assumes dst_ptr is a mapped host-visible pointer.
; RCX = BACKEND_CTX*, RDX = src_ptr, R8 = dst_ptr, R9 = size
; Returns RAX = 0 on success
;-----------------------------------------------------------------------------
DRP_VulkanUploadSingle PROC PRIVATE
    push    rsi
    push    rdi
    push    rbx
    mov     rsi, rdx                ; src
    mov     rdi, r8                 ; dst
    mov     ebx, r9d                ; size

    ; Direct mapped memcpy (host-visible VRAM)
    mov     ecx, ebx
    rep     movsb

    xor     eax, eax
    pop     rbx
    pop     rdi
    pop     rsi
    ret
DRP_VulkanUploadSingle ENDP

;-----------------------------------------------------------------------------
; Private: DRP_ROCmUploadSingle
; RCX = BACKEND_CTX*, RDX = src_ptr, R8 = dst_ptr, R9 = size
; Returns RAX = 0 on success
;-----------------------------------------------------------------------------
DRP_ROCmUploadSingle PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    .endprolog

    mov     r12, rcx
    mov     r13, [r12].BACKEND_CTX.GPU.FnTable

    ; hipMemcpyAsync(dst, src, size, kind=1, stream)
    mov     rax, [r13].ROCM_TABLE.hipMemcpyAsync
    test    rax, rax
    jz      @rocm_fail

    mov     rbx, [r12].BACKEND_CTX.GPU.Queue   ; stream

    sub     rsp, 48
    mov     rcx, r8                 ; dst
    ; rdx = src (already in rdx)
    mov     r8, r9                  ; size
    mov     r9, 1                   ; hipMemcpyHostToDevice
    mov     QWORD PTR [rsp+20h], rbx ; stream (5th arg)
    call    rax
    add     rsp, 48

    ; hipStreamSynchronize(stream)
    mov     rax, [r13].ROCM_TABLE.hipStreamSynchronize
    test    rax, rax
    jz      @rocm_fail

    sub     rsp, 40
    mov     rcx, rbx
    call    rax
    add     rsp, 40

    xor     eax, eax
    jmp     @rocm_exit

@rocm_fail:
    mov     eax, -1

@rocm_exit:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DRP_ROCmUploadSingle ENDP

;=============================================================================
; DRP_StartFlushWorker
; Creates background thread and flush queue.
; RCX = BACKEND_CTX*
; Returns RAX = 0 on success, -1 on failure
;=============================================================================
DRP_StartFlushWorker PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    .endprolog

    mov     r12, rcx

    ; Allocate job array (256 slots)
    mov     rcx, 256
    imul    rcx, SIZEOF FLUSH_JOB
    xor     edx, edx
    mov     r8, 3000h
    mov     r9, 4
    sub     rsp, 40
    call    VirtualAlloc
    add     rsp, 40
    test    rax, rax
    jz      @start_fail
    mov     rbx, rax

    ; Init queue
    lea     rdi, [r12].BACKEND_CTX.Flush.Queue
    mov     [rdi].SSD_FLUSH_QUEUE.Jobs, rbx
    mov     [rdi].SSD_FLUSH_QUEUE.Capacity, 256
    mov     [rdi].SSD_FLUSH_QUEUE.Head, 0
    mov     [rdi].SSD_FLUSH_QUEUE.Tail, 0
    mov     [rdi].SSD_FLUSH_QUEUE.SpinLock, 0

    ; Create notification event (manual reset, initial = FALSE)
    xor     ecx, ecx
    xor     edx, edx
    mov     r8, 1
    xor     r9, r9
    sub     rsp, 40
    call    CreateEventA
    add     rsp, 40
    mov     [rdi].SSD_FLUSH_QUEUE.hNotify, rax
    test    rax, rax
    jz      @start_fail

    ; Create shutdown event (manual reset, initial = FALSE)
    xor     ecx, ecx
    xor     edx, edx
    mov     r8, 1
    xor     r9, r9
    sub     rsp, 40
    call    CreateEventA
    add     rsp, 40
    mov     [r12].BACKEND_CTX.Flush.hShutdown, rax
    test    rax, rax
    jz      @start_fail

    ; Mark running
    mov     DWORD PTR [r12].BACKEND_CTX.Flush.Running, 1

    ; Create worker thread
    xor     ecx, ecx                ; lpThreadAttributes
    xor     edx, edx                ; dwStackSize
    lea     r8, DRP_FlushWorkerThread
    mov     r9, r12                 ; lpParameter = backend_ctx
    sub     rsp, 48
    mov     QWORD PTR [rsp+20h], 0 ; dwCreationFlags
    mov     QWORD PTR [rsp+28h], 0 ; lpThreadId
    call    CreateThread
    add     rsp, 48
    test    rax, rax
    jz      @start_fail
    mov     [r12].BACKEND_CTX.Flush.hThread, rax

    xor     eax, eax
    jmp     @start_exit

@start_fail:
    mov     eax, -1

@start_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DRP_StartFlushWorker ENDP

;=============================================================================
; DRP_StopFlushWorker
; Signals worker to exit and waits for termination.
; RCX = BACKEND_CTX*
;=============================================================================
DRP_StopFlushWorker PROC FRAME
    push    rbx
    .pushreg rbx
    .endprolog

    mov     rbx, rcx

    ; Clear running flag
    mov     DWORD PTR [rbx].BACKEND_CTX.Flush.Running, 0

    ; Signal shutdown event
    mov     rcx, [rbx].BACKEND_CTX.Flush.hShutdown
    test    rcx, rcx
    jz      @stop_nowait
    sub     rsp, 40
    call    SetEvent
    add     rsp, 40

    ; Wait for thread
    mov     rcx, [rbx].BACKEND_CTX.Flush.hThread
    test    rcx, rcx
    jz      @stop_nowait
    mov     rdx, 5000               ; 5 second timeout
    sub     rsp, 40
    call    WaitForSingleObject
    add     rsp, 40

    ; Close handles
    mov     rcx, [rbx].BACKEND_CTX.Flush.hThread
    sub     rsp, 40
    call    CloseHandle
    add     rsp, 40
    mov     QWORD PTR [rbx].BACKEND_CTX.Flush.hThread, 0

    mov     rcx, [rbx].BACKEND_CTX.Flush.hShutdown
    sub     rsp, 40
    call    CloseHandle
    add     rsp, 40
    mov     QWORD PTR [rbx].BACKEND_CTX.Flush.hShutdown, 0

    mov     rcx, [rbx].BACKEND_CTX.Flush.Queue.hNotify
    sub     rsp, 40
    call    CloseHandle
    add     rsp, 40
    mov     QWORD PTR [rbx].BACKEND_CTX.Flush.Queue.hNotify, 0

@stop_nowait:
    xor     eax, eax
    pop     rbx
    ret
DRP_StopFlushWorker ENDP

;=============================================================================
; DRP_FlushWorkerThread
; Background thread proc. Dequeues flush jobs, writes via overlapped I/O.
; RCX = BACKEND_CTX* (thread parameter)
;=============================================================================
DRP_FlushWorkerThread PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    .endprolog

    mov     r12, rcx                ; r12 = backend_ctx
    mov     r13, [r12].BACKEND_CTX.Pool
    lea     r14, [r12].BACKEND_CTX.Flush.Queue

    ; Build handle array for WaitForMultipleObjects on stack
    sub     rsp, 16
    mov     rax, [r14].SSD_FLUSH_QUEUE.hNotify
    mov     [rsp], rax
    mov     rax, [r12].BACKEND_CTX.Flush.hShutdown
    mov     [rsp+8], rax

@worker_loop:
    cmp     DWORD PTR [r12].BACKEND_CTX.Flush.Running, 0
    je      @worker_exit

    ; Wait for either event
    mov     rcx, 2                  ; nCount
    mov     rdx, rsp                ; lpHandles
    xor     r8, r8                  ; bWaitAll = FALSE
    mov     r9, INFINITE            ; dwMilliseconds
    sub     rsp, 40
    call    WaitForMultipleObjects
    add     rsp, 40

    cmp     eax, WAIT_OBJECT_0      ; hNotify
    je      @worker_drain
    cmp     eax, WAIT_OBJECT_0 + 1 ; hShutdown
    je      @worker_exit
    jmp     @worker_loop

@worker_drain:
    ; Reset notification event
    mov     rcx, [r14].SSD_FLUSH_QUEUE.hNotify
    sub     rsp, 40
    call    ResetEvent
    add     rsp, 40

    ; Process all pending jobs
@drain_loop:
    ; Acquire queue lock
@spin_q:
    mov     eax, 1
    xchg    eax, DWORD PTR [r14].SSD_FLUSH_QUEUE.SpinLock
    test    eax, eax
    jnz     @spin_q

    mov     eax, [r14].SSD_FLUSH_QUEUE.Tail
    cmp     eax, [r14].SSD_FLUSH_QUEUE.Head
    je      @drain_empty            ; queue empty

    ; Dequeue job at Tail
    mov     r15d, eax
    inc     eax
    and     eax, 255                ; wrap at capacity (256)
    mov     [r14].SSD_FLUSH_QUEUE.Tail, eax
    mov     DWORD PTR [r14].SSD_FLUSH_QUEUE.SpinLock, 0

    ; Get job pointer
    mov     rax, r15
    imul    rax, SIZEOF FLUSH_JOB
    mov     rsi, [r14].SSD_FLUSH_QUEUE.Jobs
    lea     rdi, [rsi + rax]        ; rdi = FLUSH_JOB*

    ; Create per-job event for overlapped I/O
    xor     ecx, ecx
    xor     edx, edx
    mov     r8, 1
    xor     r9, r9
    sub     rsp, 40
    call    CreateEventA
    add     rsp, 40
    mov     [rdi + FLUSH_JOB.Ovlp.hEvent], rax

    ; Set up OVERLAPPED offset
    mov     rax, [rdi + FLUSH_JOB.DstOffset]
    mov     [rdi + FLUSH_JOB.Ovlp._Offset], eax
    shr     rax, 32
    mov     [rdi + FLUSH_JOB.Ovlp.OffsetHigh], eax

    ; WriteFile(hFile, src, size, &written, &ovlp)
    mov     rcx, [r13].RESIDENCY_POOL.SSD.hFile
    mov     rdx, [rdi + FLUSH_JOB.SrcPtr]
    mov     r8d, [rdi + FLUSH_JOB.ByteSize]
    xor     r9, r9                  ; lpNumberOfBytesWritten = NULL
    sub     rsp, 48
    lea     rax, [rdi + FLUSH_JOB.Ovlp]
    mov     QWORD PTR [rsp+20h], rax
    call    WriteFile
    add     rsp, 48

    test    eax, eax
    jnz     @write_ok
    call    GetLastError
    cmp     eax, ERROR_IO_PENDING
    je      @write_pending
    ; Error — skip cleanup and continue
    jmp     @drain_loop

@write_pending:
@write_ok:
    ; Wait for completion
    mov     rcx, [rdi + FLUSH_JOB.Ovlp.hEvent]
    mov     rdx, INFINITE
    sub     rsp, 40
    call    WaitForSingleObject
    add     rsp, 40

    ; Close per-job event
    mov     rcx, [rdi + FLUSH_JOB.Ovlp.hEvent]
    sub     rsp, 40
    call    CloseHandle
    add     rsp, 40

    ; Mark block clean in pool
@spin_mark:
    mov     eax, 1
    xchg    eax, DWORD PTR [r13].RESIDENCY_POOL.GlobalLock
    test    eax, eax
    jnz     @spin_mark

    ; Find block by ID
    mov     ecx, [rdi + FLUSH_JOB.BlockID]
    mov     rdx, r13
    call    DRP_FindBlockByID
    test    rax, rax
    jz      @mark_done
    mov     BYTE PTR [rax + DYNAMIC_BLOCK.State], BLOCK_STATE_CLEAN

@mark_done:
    mov     DWORD PTR [r13].RESIDENCY_POOL.GlobalLock, 0
    jmp     @drain_loop

@drain_empty:
    mov     DWORD PTR [r14].SSD_FLUSH_QUEUE.SpinLock, 0
    jmp     @worker_loop

@worker_exit:
    add     rsp, 16                 ; free handle array
    xor     eax, eax
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DRP_FlushWorkerThread ENDP

;-----------------------------------------------------------------------------
; Private: DRP_FindBlockByID
; Find any block by BlockID.
; RCX = BlockID, RDX = RESIDENCY_POOL*
; Returns RAX = block pointer, or 0
;-----------------------------------------------------------------------------
DRP_FindBlockByID PROC PRIVATE
    push    rsi
    push    rbx
    mov     ebx, ecx
    mov     rsi, [rdx].RESIDENCY_POOL.BlockTable
    mov     ecx, [rdx].RESIDENCY_POOL.TotalBlocks

@findb_loop:
    test    ecx, ecx
    jz      @findb_fail
    cmp     [rsi + DYNAMIC_BLOCK.BlockID], ebx
    je      @findb_found
    add     rsi, SIZEOF DYNAMIC_BLOCK
    dec     ecx
    jmp     @findb_loop

@findb_found:
    mov     rax, rsi
    pop     rbx
    pop     rsi
    ret

@findb_fail:
    xor     eax, eax
    pop     rbx
    pop     rsi
    ret
DRP_FindBlockByID ENDP

;=============================================================================
; DRP_EnqueueSSDFlush
; Producer: adds a dirty block to the flush queue.
; RCX = BACKEND_CTX*, RDX = BlockID, R8 = SrcPtr, R9 = DstOffset
; [rsp+28h] = ByteSize (5th arg)
; Returns RAX = 0 on success, -1 if queue full
;=============================================================================
DRP_EnqueueSSDFlush PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    .endprolog

    mov     r12, rcx
    lea     rdi, [r12].BACKEND_CTX.Flush.Queue

    ; Get size from stack (5th arg) — after 4 pushes (32 bytes) + retaddr (8)
    ; 5th arg is at [rsp+48h] in callee frame after pushes
    mov     eax, DWORD PTR [rsp+48h]

    ; Acquire queue lock
@spin_eq:
    mov     ecx, 1
    xchg    ecx, DWORD PTR [rdi].SSD_FLUSH_QUEUE.SpinLock
    test    ecx, ecx
    jnz     @spin_eq

    ; Check if full
    mov     ecx, [rdi].SSD_FLUSH_QUEUE.Head
    inc     ecx
    and     ecx, 255
    cmp     ecx, [rdi].SSD_FLUSH_QUEUE.Tail
    je      @eq_full

    ; Get job slot
    mov     esi, [rdi].SSD_FLUSH_QUEUE.Head
    mov     rax, rsi
    imul    rax, SIZEOF FLUSH_JOB
    mov     rbx, [rdi].SSD_FLUSH_QUEUE.Jobs
    lea     rbx, [rbx + rax]

    ; Fill job
    mov     [rbx + FLUSH_JOB.BlockID], edx
    mov     [rbx + FLUSH_JOB.SrcPtr], r8
    mov     [rbx + FLUSH_JOB.DstOffset], r9
    mov     [rbx + FLUSH_JOB.ByteSize], eax

    ; Zero overlapped
    xor     eax, eax
    mov     [rbx + FLUSH_JOB.Ovlp.Internal], rax
    mov     [rbx + FLUSH_JOB.Ovlp.InternalHigh], rax
    mov     [rbx + FLUSH_JOB.Ovlp._Offset], eax
    mov     [rbx + FLUSH_JOB.Ovlp.OffsetHigh], eax
    mov     [rbx + FLUSH_JOB.Ovlp.hEvent], rax

    ; Advance head
    mov     [rdi].SSD_FLUSH_QUEUE.Head, ecx
    mov     DWORD PTR [rdi].SSD_FLUSH_QUEUE.SpinLock, 0

    ; Wake worker
    mov     rcx, [rdi].SSD_FLUSH_QUEUE.hNotify
    sub     rsp, 40
    call    SetEvent
    add     rsp, 40

    xor     eax, eax
    jmp     @eq_exit

@eq_full:
    mov     DWORD PTR [rdi].SSD_FLUSH_QUEUE.SpinLock, 0
    mov     eax, -1

@eq_exit:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
DRP_EnqueueSSDFlush ENDP

;=============================================================================
; DRP_TouchWeight
; Metadata-only hot path: records access without moving or loading weight.
; Uses direct-indexed lookup via BlockIndex when available; falls back to
; linear scan.  RCX = RESIDENCY_POOL*, RDX = BlockID, R8 = current_epoch
; Returns RAX = block pointer (NULL if not found)
; INVARIANT: MUST NOT change ResidencyState (Tier / DataPtr / State).
;=============================================================================
DRP_TouchWeight PROC FRAME
    push    rsi
    .pushreg rsi
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    .endprolog

    mov     r12, rcx                ; r12 = pool
    mov     ebx, edx                ; ebx = BlockID

    ; Fast path: direct-indexed lookup (BlockIndex[BlockID])
    mov     rsi, [r12].RESIDENCY_POOL.BlockIndex
    test    rsi, rsi
    jz      @touch_fallback

    mov     eax, ebx
    cmp     eax, [r12].RESIDENCY_POOL.TotalBlocks
    jae     @touch_fallback         ; BlockID out of dense range

    mov     rax, [rsi + rax*8]      ; rax = block pointer
    test    rax, rax
    jz      @touch_fallback         ; empty slot
    cmp     [rax + DYNAMIC_BLOCK.BlockID], ebx
    jne     @touch_fallback         ; index mismatch (stale)

    ; Fast path hit — same invariant as fallback
    mov     rsi, rax
    jmp     @touch_found

@touch_fallback:
    ; Fallback: linear scan of BlockTable
    mov     rsi, [r12].RESIDENCY_POOL.BlockTable
    mov     ecx, [r12].RESIDENCY_POOL.TotalBlocks

@touch_find:
    test    ecx, ecx
    jz      @touch_notfound
    cmp     [rsi + DYNAMIC_BLOCK.BlockID], ebx
    je      @touch_found
    add     rsi, SIZEOF DYNAMIC_BLOCK
    dec     ecx
    jmp     @touch_find

@touch_found:
    ; INVARIANT: TouchWeight MUST NOT change ResidencyState (Tier).
    ; It only marks metadata for the eviction scan to consume later.
    ; No SSD read, no RAM alloc, no VRAM alloc, no mapping, no dequant, no upload.
    mov     [rsi + DYNAMIC_BLOCK.LastAccess], r8
    mov     BYTE PTR [rsi + DYNAMIC_BLOCK.Referenced], 1
    mov     rax, rsi                ; return block pointer
    pop     r12
    pop     rbx
    pop     rsi
    ret

@touch_notfound:
    xor     eax, eax
    pop     r12
    pop     rbx
    pop     rsi
    ret
DRP_TouchWeight ENDP

END
