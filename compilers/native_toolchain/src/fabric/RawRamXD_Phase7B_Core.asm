; =============================================================================
; RawRamXD Phase 7B: Fabric Core (Minimum Invariant)
; 
; Two primitives:
;   1. Virtual address → tier → migrate → coherent state
;   2. Every byte has: owner + version + temperature
;
; Everything else (GPU federation, unified memory, MESI, workers, prefetch)
; expands from these two primitives.
; =============================================================================

; Page Table Entry (64 bytes) - the universal memory truth
; Every byte in the fabric has these three properties:
struc FabricPage
    .VirtualAddr    resq 1      ; 0x00: Global virtual address
    .PhysicalAddr   resq 1      ; 0x08: Physical address in owner tier
    .Size           resq 1      ; 0x10: Page size (4KB default)
    .OwnerTier      resd 1      ; 0x18: Current owner tier (0-3)
    .HomeTier       resd 1      ; 0x1C: Home tier (for writeback)
    .Version        resq 1      ; 0x20: Monotonic version counter
    .Temperature    resd 1      ; 0x28: Hot/cold score (0.0-1.0 as fixed point)
    .AccessCount    resd 1      ; 0x2C: Access frequency
    .LastAccess     resq 1      ; 0x30: Timestamp
    .State          resb 1       ; 0x38: Coherence state (MESI)
    .Dirty          resb 1       ; 0x39: Modified since sync
    .Migrating      resb 1       ; 0x3A: In-flight migration
    .Reserved       resb 5       ; 0x3B-3F: Padding
endstruc

; Coherence States (MESI-inspired)
STATE_INVALID   equ 0
STATE_SHARED    equ 1
STATE_EXCLUSIVE equ 2
STATE_MODIFIED  equ 3
STATE_PREFETCH  equ 4

; Memory Tiers
TIER_VRAM_FAST      equ 0   ; RX 7800 XT GDDR6 (600 GB/s)
TIER_UNIFIED        equ 1   ; APU shared DDR5 (100 GB/s)
TIER_SYSTEM         equ 2   ; CPU system RAM (50 GB/s)
TIER_NVME           equ 3   ; NVMe storage (7 GB/s)

; =============================================================================
; Primitive 1: ResolveTier
; Input:  RAX = virtual address
; Output: RCX = owner tier, RDX = coherence state
; =============================================================================
ResolveTier:
    ; Load page table entry
    mov rbx, [PageTableBase]
    
    ; Calculate index: (vaddr - base) / 4096
    sub rax, [VirtualBase]
    shr rax, 12                 ; Divide by 4096
    
    ; Load page entry
    imul rax, FabricPage_size
    add rbx, rax
    
    ; Return owner tier and state
    mov ecx, [rbx + FabricPage.OwnerTier]
    movzx edx, byte [rbx + FabricPage.State]
    
    ret

; =============================================================================
; Primitive 2: MigrateIfNeeded
; Input:  RAX = virtual address, RCX = desired tier
; Output: RAX = 0 (success) or -1 (failure)
; =============================================================================
MigrateIfNeeded:
    push rbx
    push rsi
    push rdi
    
    ; Get current page info
    call ResolveTier
    mov r8d, ecx                ; Current tier
    mov r9d, edx                ; Current state
    
    ; Already at desired tier?
    cmp r8d, ecx
    je .done_success
    
    ; Check if migration in progress
    mov rbx, [PageTableBase]
    sub rax, [VirtualBase]
    shr rax, 12
    imul rax, FabricPage_size
    add rbx, rax
    
    cmp byte [rbx + FabricPage.Migrating], 1
    je .done_wait               ; Already migrating, wait
    
    ; Mark as migrating
    mov byte [rbx + FabricPage.Migrating], 1
    
    ; Perform migration (simplified - real would be async DMA)
    call ExecuteMigration
    
    ; Update owner
    mov [rbx + FabricPage.OwnerTier], ecx
    
    ; Bump version
    inc qword [rbx + FabricPage.Version]
    
    ; Clear migrating flag
    mov byte [rbx + FabricPage.Migrating], 0
    
    ; Update state based on migration type
    cmp r8d, TIER_VRAM_FAST
    jne .to_slower
    
    ; Promoting to VRAM: EXCLUSIVE
    mov byte [rbx + FabricPage.State], STATE_EXCLUSIVE
    jmp .done_success
    
.to_slower:
    ; Demoting: SHARED (read-only in slower tier)
    mov byte [rbx + FabricPage.State], STATE_SHARED
    
.done_success:
    xor eax, eax
    pop rdi
    pop rsi
    pop rbx
    ret
    
.done_wait:
    mov eax, -2                 ; Migration in progress
    pop rdi
    pop rsi
    pop rbx
    ret

; =============================================================================
; Primitive 3: UpdateTemperature (hot/cold detection)
; Input:  RAX = virtual address, RCX = access type (0=read, 1=write)
; =============================================================================
UpdateTemperature:
    push rbx
    
    ; Get page entry
    mov rbx, [PageTableBase]
    sub rax, [VirtualBase]
    shr rax, 12
    imul rax, FabricPage_size
    add rbx, rax
    
    ; Increment access count
    inc dword [rbx + FabricPage.AccessCount]
    
    ; Update last access time
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [rbx + FabricPage.LastAccess], rax
    
    ; Calculate temperature (simplified EMA)
    ; temp = 0.7 * old_temp + 0.3 * new_access
    mov eax, [rbx + FabricPage.Temperature]
    imul eax, 7                   ; 0.7 * old (fixed point 0.1)
    mov ecx, 30                   ; 0.3 * 100 (new access boost)
    add eax, ecx
    xor edx, edx
    mov ecx, 10
    div ecx                       ; Divide by 10
    
    ; Clamp to 1.0 (100)
    cmp eax, 100
    jle .store_temp
    mov eax, 100
    
.store_temp:
    mov [rbx + FabricPage.Temperature], eax
    
    pop rbx
    ret

; =============================================================================
; Primitive 4: AcquireAccess (read/write with coherence)
; Input:  RAX = virtual address, RCX = tier, DL = access type (0=read, 1=write)
; Output: RAX = physical address or 0 (failure)
; =============================================================================
AcquireAccess:
    push rbx
    push rsi
    
    ; Update temperature
    push rdx
    call UpdateTemperature
    pop rdx
    
    ; Get page entry
    mov rbx, [PageTableBase]
    mov rsi, rax                ; Save vaddr
    sub rax, [VirtualBase]
    shr rax, 12
    imul rax, FabricPage_size
    add rbx, rax
    
    ; Check if we need to migrate
    mov r8d, [rbx + FabricPage.OwnerTier]
    cmp r8d, ecx
    je .check_state
    
    ; Migrate to requesting tier
    mov rax, rsi
    call MigrateIfNeeded
    test eax, eax
    jnz .fail
    
.check_state:
    ; Check coherence state
    movzx eax, byte [rbx + FabricPage.State]
    
    cmp dl, 0                   ; Read?
    je .handle_read
    
    ; Write path
    cmp al, STATE_EXCLUSIVE
    je .write_ok
    cmp al, STATE_MODIFIED
    je .write_ok
    
    ; Need to upgrade to EXCLUSIVE
    call InvalidateOthers
    mov byte [rbx + FabricPage.State], STATE_MODIFIED
    mov byte [rbx + FabricPage.Dirty], 1
    
.write_ok:
    ; Return physical address
    mov rax, [rbx + FabricPage.PhysicalAddr]
    pop rsi
    pop rbx
    ret
    
.handle_read:
    cmp al, STATE_INVALID
    je .need_sync
    
    ; Read OK from any valid state
    mov rax, [rbx + FabricPage.PhysicalAddr]
    pop rsi
    pop rbx
    ret
    
.need_sync:
    ; Sync from home tier
    call SyncFromHome
    mov byte [rbx + FabricPage.State], STATE_SHARED
    mov rax, [rbx + FabricPage.PhysicalAddr]
    pop rsi
    pop rbx
    ret
    
.fail:
    xor eax, eax
    pop rsi
    pop rbx
    ret

; =============================================================================
; Helper: Invalidate other copies (for write)
; Input: RBX = page entry pointer, RCX = except tier
; =============================================================================
InvalidateOthers:
    ; In real implementation: send invalidation messages to other tiers
    ; For now, just mark as needing sync
    ret

; =============================================================================
; Helper: Sync from home tier
; Input: RBX = page entry pointer
; =============================================================================
SyncFromHome:
    ; In real implementation: DMA copy from home tier
    ret

; =============================================================================
; Helper: Execute migration (simplified)
; Input: RBX = page entry, RCX = target tier
; =============================================================================
ExecuteMigration:
    ; Simulate migration delay
    ; In real implementation: queue DMA transfer
    ret

; =============================================================================
; Data Section
; =============================================================================
section .data
    PageTableBase   dq 0
    VirtualBase     dq 0x100000000  ; 4GB base
    
    ; Statistics
    TotalMigrations     dq 0
    TotalInvalidations  dq 0
    TotalSyncs          dq 0

; =============================================================================
; C API (for integration)
; =============================================================================
global Fabric_ResolveTier
global Fabric_Migrate
global Fabric_AcquireRead
global Fabric_AcquireWrite
global Fabric_UpdateTemp

Fabric_ResolveTier:
    mov rax, rcx
    call ResolveTier
    mov rax, rcx                ; Return tier
    ret

Fabric_Migrate:
    mov rax, rcx
    mov rcx, rdx
    call MigrateIfNeeded
    ret

Fabric_AcquireRead:
    mov rax, rcx
    mov rcx, rdx
    xor edx, edx                ; Read
    call AcquireAccess
    ret

Fabric_AcquireWrite:
    mov rax, rcx
    mov rcx, rdx
    mov edx, 1                  ; Write
    call AcquireAccess
    ret

Fabric_UpdateTemp:
    mov rax, rcx
    mov rcx, rdx
    call UpdateTemperature
    ret

; =============================================================================
; Test / Entry Point
; =============================================================================
global _start
_start:
    ; Initialize page table (simplified)
    ; In real implementation: allocate and initialize
    
    ; Test 1: Resolve tier for address
    mov rax, 0x100000000        ; First page
    call ResolveTier
    ; RCX = owner tier, RDX = state
    
    ; Test 2: Migrate to different tier
    mov rax, 0x100000000
    mov ecx, TIER_VRAM_FAST
    call MigrateIfNeeded
    
    ; Test 3: Acquire read access
    mov rax, 0x100000000
    mov ecx, TIER_VRAM_FAST
    xor edx, edx                ; Read
    call AcquireAccess
    
    ; Test 4: Update temperature
    mov rax, 0x100000000
    xor ecx, ecx                ; Read access
    call UpdateTemperature
    
    ; Exit
    xor ecx, ecx
    call ExitProcess

; Import
extern ExitProcess
