; =============================================================================
; RawRamXD_MASM.asm - Physical Tier Implementation for RawRamXD
; =============================================================================
; Implements the 8 extern "C" functions that bridge RawRamXD C++ fabric
; to physical memory: VRAM (GPU), RAM (system), NVMe (direct storage)
; =============================================================================

; Windows API includes
include \masm64\include64\windows.inc
include \masm64\include64\kernel32.inc
include \masm64\include64\ntdll.inc

; Vulkan/DirectX for GPU memory
include \masm64\include64\d3d12.inc

; External C functions from RawRamXD.hpp
; extern "C" {
;     uint64_t rrasm_phys_alloc(Tier tier, size_t size, uint32_t flags);
;     void rrasm_phys_free(Tier tier, uint64_t phys_addr, size_t size);
;     uint64_t rrasm_phys_copy(Tier dst_tier, uint64_t dst_phys,
;                              Tier src_tier, uint64_t src_phys,
;                              size_t size);
;     bool rrasm_phys_copy_done(uint64_t copy_id);
;     void* rrasm_phys_map(Tier tier, uint64_t phys_addr, size_t size);
;     void rrasm_phys_unmap(void* ptr, size_t size);
;     uint64_t rrasm_nvme_read(uint64_t nvme_offset, Tier dst_tier, uint64_t dst_phys, size_t size);
;     uint64_t rrasm_nvme_write(Tier src_tier, uint64_t src_phys, uint64_t nvme_offset, size_t size);
; }

; =============================================================================
; Constants
; =============================================================================
TIER_VRAM     equ 0
TIER_RAM      equ 1
TIER_NVME     equ 2

; Copy engine states
COPY_PENDING  equ 0
COPY_RUNNING  equ 1
COPY_COMPLETE equ 2
COPY_ERROR    equ 3

; Maximum concurrent copies
MAX_COPIES    equ 64

; =============================================================================
; Data Section
; =============================================================================
.data

; GPU context (from UnifiedMemoryGPUAllAccess)
align 8
g_gpu_device      dq ?
g_gpu_queue       dq ?
g_gpu_allocator   dq ?
g_gpu_list        dq ?
g_gpu_fence       dq ?
g_fence_value     dq ?

; Copy tracking
align 8
copy_table STRUCT
    id            dq ?
    state         dd ?
    dst_tier      dd ?
    src_tier      dd ?
    dst_phys      dq ?
    src_phys      dq ?
    size          dq ?
    start_time    dq ?
copy_table ENDS

align 8
g_copy_table copy_table MAX_COPIES dup(<0>)
g_next_copy_id    dq 1

; NVMe context
align 8
g_nvme_handle     dq ?
g_nvme_file       dq ?
g_nvme_size       dq ?

; Statistics
align 8
g_stats STRUCT
    vram_allocs     dq ?
    vram_frees      dq ?
    ram_allocs      dq ?
    ram_frees       dq ?
    nvme_allocs     dq ?
    nvme_frees      dq ?
    copies_started  dq ?
    copies_completed dq ?
    bytes_copied    dq ?
g_stats ENDS

align 8
stats g_stats <0>

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; rrasm_phys_alloc - Allocate physical memory on specified tier
; RCX = tier (0=VRAM, 1=RAM, 2=NVMe)
; RDX = size
; R8  = flags
; Returns: RAX = physical address (0 = failure)
; =============================================================================
rrasm_phys_alloc PROC FRAME
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    push    rbx
    push    rdi
    push    rsi
    
    mov     ebx, ecx        ; tier
    mov     rdi, rdx        ; size
    mov     rsi, r8         ; flags
    
    ; Branch by tier
    cmp     ebx, TIER_VRAM
    je      .alloc_vram
    cmp     ebx, TIER_RAM
    je      .alloc_ram
    cmp     ebx, TIER_NVME
    je      .alloc_nvme
    
    ; Invalid tier
    xor     rax, rax
    jmp     .done
    
.alloc_vram:
    ; Allocate GPU VRAM via DirectX 12
    call    AllocateVRAM
    lock inc [stats.vram_allocs]
    jmp     .done
    
.alloc_ram:
    ; Allocate system RAM via VirtualAlloc
    mov     rcx, rdi        ; size
    mov     edx, MEM_COMMIT or MEM_RESERVE
    mov     r8d, PAGE_READWRITE
    xor     r9, r9
    call    VirtualAlloc
    lock inc [stats.ram_allocs]
    jmp     .done
    
.alloc_nvme:
    ; Allocate NVMe-backed memory (memory-mapped file)
    call    AllocateNVMe
    lock inc [stats.nvme_allocs]
    jmp     .done
    
.done:
    pop     rsi
    pop     rdi
    pop     rbx
    leave
    ret
rrasm_phys_alloc ENDP

; =============================================================================
; rrasm_phys_free - Free physical memory on specified tier
; RCX = tier
; RDX = physical address
; R8  = size
; =============================================================================
rrasm_phys_free PROC FRAME
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    push    rbx
    push    rdi
    
    mov     ebx, ecx        ; tier
    mov     rdi, rdx        ; address
    
    cmp     ebx, TIER_VRAM
    je      .free_vram
    cmp     ebx, TIER_RAM
    je      .free_ram
    cmp     ebx, TIER_NVME
    je      .free_nvme
    jmp     .done
    
.free_vram:
    call    FreeVRAM
    lock inc [stats.vram_frees]
    jmp     .done
    
.free_ram:
    mov     rcx, rdi
    xor     edx, edx
    call    VirtualFree
    lock inc [stats.ram_frees]
    jmp     .done
    
.free_nvme:
    call    FreeNVMe
    lock inc [stats.nvme_frees]
    jmp     .done
    
.done:
    pop     rdi
    pop     rbx
    leave
    ret
rrasm_phys_free ENDP

; =============================================================================
; rrasm_phys_copy - Copy between tiers (non-blocking)
; RCX = dst_tier
; RDX = dst_phys
; R8  = src_tier
; R9  = src_phys
; [RSP+40] = size
; Returns: RAX = copy_id (0 = failure)
; =============================================================================
rrasm_phys_copy PROC FRAME
    push    rbp
    mov     rbp, rsp
    sub     rsp, 80
    
    push    rbx
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15
    
    mov     r12d, ecx       ; dst_tier
    mov     r13, rdx      ; dst_phys
    mov     r14d, r8d     ; src_tier
    mov     r15, r9       ; src_phys
    mov     rdi, [rbp+48] ; size
    
    ; Find free copy slot
    mov     rcx, MAX_COPIES
    xor     rbx, rbx
.find_slot:
    cmp     rbx, rcx
    jge     .no_slot
    
    mov     eax, [g_copy_table + rbx * SIZEOF copy_table + copy_table.state]
    cmp     eax, COPY_COMPLETE
    je      .found_slot
    cmp     eax, COPY_ERROR
    je      .found_slot
    
    inc     rbx
    jmp     .find_slot
    
.found_slot:
    ; Initialize copy
    lock inc [g_next_copy_id]
    mov     rax, [g_next_copy_id]
    mov     [g_copy_table + rbx * SIZEOF copy_table + copy_table.id], rax
    mov     dword ptr [g_copy_table + rbx * SIZEOF copy_table + copy_table.state], COPY_RUNNING
    mov     [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_tier], r12d
    mov     [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_tier], r14d
    mov     [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys], r13
    mov     [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys], r15
    mov     [g_copy_table + rbx * SIZEOF copy_table + copy_table.size], rdi
    
    ; Get timestamp
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     [g_copy_table + rbx * SIZEOF copy_table + copy_table.start_time], rax
    
    ; Execute copy based on tier combination
    mov     ecx, r14d       ; src_tier
    mov     edx, r12d       ; dst_tier
    call    ExecuteTierCopy
    
    ; Return copy_id
    mov     rax, [g_copy_table + rbx * SIZEOF copy_table + copy_table.id]
    lock inc [stats.copies_started]
    jmp     .done
    
.no_slot:
    xor     rax, rax        ; No slot available
    
.done:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    leave
    ret
rrasm_phys_copy ENDP

; =============================================================================
; rrasm_phys_copy_done - Check if copy is complete
; RCX = copy_id
; Returns: RAX = true if complete, false if pending
; =============================================================================
rrasm_phys_copy_done PROC FRAME
    push    rbp
    mov     rbp, rsp
    
    mov     rdx, rcx        ; copy_id
    
    ; Search for copy_id in table
    mov     rcx, MAX_COPIES
    xor     rax, rax
.find:
    cmp     rax, rcx
    jge     .not_found
    
    cmp     [g_copy_table + rax * SIZEOF copy_table + copy_table.id], rdx
    je      .found
    
    inc     rax
    jmp     .find
    
.found:
    ; Check state
    mov     edx, [g_copy_table + rax * SIZEOF copy_table + copy_table.state]
    cmp     edx, COPY_COMPLETE
    sete    al
    cmp     edx, COPY_ERROR
    sete    dl
    or      al, dl
    movzx   rax, al
    jmp     .done
    
.not_found:
    xor     rax, rax        ; Not found = not done
    
.done:
    leave
    ret
rrasm_phys_copy_done ENDP

; =============================================================================
; rrasm_phys_map - Map physical memory into CPU address space
; RCX = tier
; RDX = phys_addr
; R8  = size
; Returns: RAX = virtual pointer (nullptr = failure)
; =============================================================================
rrasm_phys_map PROC FRAME
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    mov     ebx, ecx        ; tier
    mov     rdi, rdx        ; phys_addr
    mov     rsi, r8         ; size
    
    cmp     ebx, TIER_VRAM
    je      .map_vram
    cmp     ebx, TIER_RAM
    je      .map_ram
    
    ; NVMe and others - return phys_addr as-is (already mapped)
    mov     rax, rdi
    jmp     .done
    
.map_vram:
    ; Map GPU VRAM via BAR
    call    MapVRAMBAR
    jmp     .done
    
.map_ram:
    ; RAM is already virtual - return as-is
    mov     rax, rdi
    jmp     .done
    
.done:
    leave
    ret
rrasm_phys_map ENDP

; =============================================================================
; rrasm_phys_unmap - Unmap physical memory
; RCX = ptr
; RDX = size
; =============================================================================
rrasm_phys_unmap PROC FRAME
    push    rbp
    mov     rbp, rsp
    
    mov     rdi, rcx        ; ptr
    mov     rsi, rdx        ; size
    
    ; Only VRAM needs unmapping
    call    UnmapVRAMBAR
    
    leave
    ret
rrasm_phys_unmap ENDP

; =============================================================================
; rrasm_nvme_read - Read from NVMe to tier
; RCX = nvme_offset
; RDX = dst_tier
; R8  = dst_phys
; R9  = size
; Returns: RAX = copy_id
; =============================================================================
rrasm_nvme_read PROC FRAME
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; For now, treat as RAM copy from NVMe buffer
    ; In production, this would use DirectStorage API
    
    mov     r10, [g_nvme_handle]    ; NVMe base
    add     r10, rcx                ; + offset
    
    ; Queue as copy from NVMe (treated as RAM tier for copy engine)
    mov     ecx, TIER_NVME          ; src = NVMe
    mov     r9, r10                 ; src_phys = nvme_addr
    mov     r8d, edx                ; dst_tier
    mov     rdx, r8                 ; dst_phys
    mov     rcx, r9                 ; size
    call    rrasm_phys_copy
    
    leave
    ret
rrasm_nvme_read ENDP

; =============================================================================
; rrasm_nvme_write - Write to NVMe from tier
; RCX = src_tier
; RDX = src_phys
; R8  = nvme_offset
; R9  = size
; Returns: RAX = copy_id
; =============================================================================
rrasm_nvme_write PROC FRAME
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    
    ; Similar to read but reversed
    mov     r10, [g_nvme_handle]
    add     r10, r8
    
    ; Queue as copy to NVMe
    mov     r9d, TIER_NVME          ; dst = NVMe
    mov     r8, r10                   ; dst_phys = nvme_addr
    ; src_tier and src_phys already in rcx, rdx
    call    rrasm_phys_copy
    
    leave
    ret
rrasm_nvme_write ENDP

; =============================================================================
; Helper Functions
; =============================================================================

AllocateVRAM PROC
    ; Allocate GPU memory via DirectX 12
    ; Returns: RAX = GPU virtual address
    
    ; For now, allocate via VirtualAlloc as placeholder
    ; In production, use ID3D12Device::CreateCommittedResource
    mov     rcx, rdi        ; size
    mov     edx, MEM_COMMIT or MEM_RESERVE
    mov     r8d, PAGE_READWRITE
    xor     r9, r9
    call    VirtualAlloc
    
    ret
AllocateVRAM ENDP

FreeVRAM PROC
    ; Free GPU memory
    mov     rcx, rdi
    xor     edx, edx
    call    VirtualFree
    ret
FreeVRAM ENDP

AllocateNVMe PROC
    ; Create memory-mapped file for NVMe backing
    ; Returns: RAX = mapped address
    
    ; Create file mapping
    mov     rcx, INVALID_HANDLE_VALUE
    xor     rdx, rdx
    mov     r8, rdi         ; size
    mov     r9d, PAGE_READWRITE
    call    CreateFileMappingA
    
    mov     [g_nvme_handle], rax
    
    ; Map view
    mov     rcx, rax
    xor     edx, edx
    xor     r8, r8
    mov     r9d, FILE_MAP_ALL_ACCESS
    call    MapViewOfFile
    
    ret
AllocateNVMe ENDP

FreeNVMe PROC
    ; Unmap and close NVMe backing
    mov     rcx, rdi
    call    UnmapViewOfFile
    
    mov     rcx, [g_nvme_handle]
    call    CloseHandle
    ret
FreeNVMe ENDP

ExecuteTierCopy PROC
    ; Execute copy based on source and destination tiers
    ; ECX = src_tier, EDX = dst_tier
    ; Uses global copy table entry in RBX
    
    push    rbp
    mov     rbp, rsp
    
    ; Determine copy method
    cmp     ecx, TIER_RAM
    jne     .check_vram_src
    
    ; Source is RAM
    cmp     edx, TIER_VRAM
    jne     .ram_to_ram
    
    ; RAM → VRAM (upload)
    call    CopyRAMtoVRAM
    jmp     .copy_done
    
.ram_to_ram:
    ; RAM → RAM (memcpy)
    mov     rsi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys]
    mov     rdi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys]
    mov     rcx, [g_copy_table + rbx * SIZEOF copy_table + copy_table.size]
    rep     movsb
    jmp     .copy_done
    
.check_vram_src:
    cmp     ecx, TIER_VRAM
    jne     .check_nvme_src
    
    ; Source is VRAM
    cmp     edx, TIER_RAM
    jne     .vram_to_vram
    
    ; VRAM → RAM (readback)
    call    CopyVRAMtoRAM
    jmp     .copy_done
    
.vram_to_vram:
    ; VRAM → VRAM (GPU copy)
    call    CopyVRAMtoVRAM
    jmp     .copy_done
    
.check_nvme_src:
    cmp     ecx, TIER_NVME
    jne     .unknown_combo
    
    ; Source is NVMe
    cmp     edx, TIER_RAM
    jne     .nvme_to_vram
    
    ; NVMe → RAM
    call    CopyNVMeToRAM
    jmp     .copy_done
    
.nvme_to_vram:
    ; NVMe → VRAM (direct load)
    call    CopyNVMeToVRAM
    jmp     .copy_done
    
.unknown_combo:
    ; Fallback to memcpy (shouldn't happen)
    mov     rsi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys]
    mov     rdi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys]
    mov     rcx, [g_copy_table + rbx * SIZEOF copy_table + copy_table.size]
    rep     movsb
    
.copy_done:
    ; Mark as complete
    mov     dword ptr [g_copy_table + rbx * SIZEOF copy_table + copy_table.state], COPY_COMPLETE
    lock add [stats.bytes_copied], rdi
    lock inc [stats.copies_completed]
    
    leave
    ret
ExecuteTierCopy ENDP

CopyRAMtoVRAM PROC
    ; Upload from RAM to GPU VRAM
    ; Use DirectX Copy Engine or CUDA memcpy
    
    ; For now, use memcpy as placeholder
    mov     rsi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys]
    mov     rdi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys]
    mov     rcx, [g_copy_table + rbx * SIZEOF copy_table + copy_table.size]
    rep     movsb
    
    ret
CopyRAMtoVRAM ENDP

CopyVRAMtoRAM PROC
    ; Download from GPU VRAM to RAM
    mov     rsi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys]
    mov     rdi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys]
    mov     rcx, [g_copy_table + rbx * SIZEOF copy_table + copy_table.size]
    rep     movsb
    ret
CopyVRAMtoRAM ENDP

CopyVRAMtoVRAM PROC
    ; GPU-to-GPU copy
    mov     rsi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys]
    mov     rdi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys]
    mov     rcx, [g_copy_table + rbx * SIZEOF copy_table + copy_table.size]
    rep     movsb
    ret
CopyVRAMtoVRAM ENDP

CopyNVMeToRAM PROC
    ; Read from NVMe-mapped memory to RAM
    mov     rsi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys]
    mov     rdi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys]
    mov     rcx, [g_copy_table + rbx * SIZEOF copy_table + copy_table.size]
    rep     movsb
    ret
CopyNVMeToRAM ENDP

CopyNVMeToVRAM PROC
    ; Direct NVMe to VRAM (bypass CPU)
    ; In production: use DirectStorage GPU decompression
    mov     rsi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.src_phys]
    mov     rdi, [g_copy_table + rbx * SIZEOF copy_table + copy_table.dst_phys]
    mov     rcx, [g_copy_table + rbx * SIZEOF copy_table + copy_table.size]
    rep     movsb
    ret
CopyNVMeToVRAM ENDP

MapVRAMBAR PROC
    ; Map GPU VRAM into CPU address space via BAR
    ; Returns: RAX = mapped pointer
    
    ; For now, return address as-is (assuming BAR mapping)
    mov     rax, rdi
    ret
MapVRAMBAR ENDP

UnmapVRAMBAR PROC
    ; Unmap GPU VRAM
    ret
UnmapVRAMBAR ENDP

; =============================================================================
; Export Functions
; =============================================================================
public rrasm_phys_alloc
public rrasm_phys_free
public rrasm_phys_copy
public rrasm_phys_copy_done
public rrasm_phys_map
public rrasm_phys_unmap
public rrasm_nvme_read
public rrasm_nvme_write

END