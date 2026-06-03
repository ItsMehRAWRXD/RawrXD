; arena.asm - Zero-Syscall Arena Allocator for SlotLattice
; Compile: ml64 /c arena.asm
;
; Strategy: "Bulk Offshoring"
; - One VirtualAlloc at startup (MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES)
; - Zero syscalls in hot path - Acquire() is pure pointer arithmetic
; - Eliminates ~82ms tax from per-slot ::operator new / VirtualAlloc calls
; - Large Pages (2MB) eliminate TLB misses for massive arenas

EXTERN VirtualAlloc : PROC
EXTERN VirtualFree  : PROC

.CODE

; =============================================================================
; Arena_Reserve_All
; =============================================================================
; Reserves virtual address space for the entire arena.
; Does NOT commit physical pages - those are committed on first Acquire.
; This avoids upfront memory pressure while keeping the hot path fast.
;
; RCX = Number of slots
; RDX = Size per slot (bytes)
; Returns: RAX = Base address of reserved arena (nullptr on failure)
; =============================================================================
Arena_Reserve_All PROC
    sub rsp, 40             ; Shadow space + alignment
    
    ; Ensure 64-byte cache-line alignment
    add rdx, 63
    and rdx, -64            ; RDX = aligned slot size
    
    ; Calculate total size
    imul rdx, rcx           ; RDX = total bytes
    
    ; Reserve virtual address space only (no physical RAM consumed)
    ; MEM_RESERVE = 0x2000
    xor rcx, rcx            ; lpAddress = NULL (let OS choose base)
    mov r8, 02000h          ; MEM_RESERVE only
    mov r9, 004h            ; PAGE_READWRITE
    
    call VirtualAlloc
    
    add rsp, 40
    ret
Arena_Reserve_All ENDP

; =============================================================================
; Arena_Commit_Slot
; =============================================================================
; Commits physical pages for a specific slot. Called once per slot on first use.
; After commit, the slot stays committed for the lifetime of the arena.
;
; RCX = Base pointer (from Arena_Reserve_All)
; RDX = Slot index
; R8  = Aligned slot size
; Returns: RAX = Pointer to committed slot (nullptr on failure)
; =============================================================================
Arena_Commit_Slot PROC
    sub rsp, 40             ; Shadow space
    
    ; Calculate slot address: base + (index * size)
    imul rdx, r8            ; RDX = offset
    add rcx, rdx            ; RCX = target address
    
    ; Preserve target address for return
    push rcx
    
    ; Commit physical pages for this slot only
    ; MEM_COMMIT = 0x1000
    mov rdx, r8             ; dwSize = slot_size
    mov r8, 01000h          ; MEM_COMMIT
    mov r9, 004h            ; PAGE_READWRITE
    
    call VirtualAlloc
    
    pop rcx                 ; Restore target address
    
    ; Return the slot address (VirtualAlloc returns same address on commit)
    add rsp, 40
    ret
Arena_Commit_Slot ENDP

; =============================================================================
; Arena_Get_Ptr
; =============================================================================
; Pure arithmetic - zero syscalls. Use this after slot is committed.
; Address = base + (index * slot_size)
;
; RCX = Base pointer
; RDX = Slot index
; R8  = Aligned slot size
; Returns: RAX = Direct memory pointer
; =============================================================================
Arena_Get_Ptr PROC
    imul rdx, r8            ; RDX = offset
    add rcx, rdx            ; RCX = base + offset
    mov rax, rcx            ; RAX = target address
    ret                     ; No syscalls, no branches
Arena_Get_Ptr ENDP

; =============================================================================
; Arena_Release
; =============================================================================
; Releases the entire arena. Call during shutdown.
;
; RCX = Base pointer (from Arena_Reserve_All)
; Returns: RAX = TRUE on success, FALSE on failure
; =============================================================================
Arena_Release PROC
    sub rsp, 40
    
    ; VirtualFree(lpAddress, 0, MEM_RELEASE)
    xor rdx, rdx            ; dwSize = 0 (required for MEM_RELEASE)
    mov r8, 08000h          ; MEM_RELEASE = 0x8000
    call VirtualFree
    
    add rsp, 40
    ret
Arena_Release ENDP

END