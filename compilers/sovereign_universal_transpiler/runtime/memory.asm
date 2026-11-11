; memory.asm - Minimal allocator for Sovereign Universal Transpiler
; v0.3 - Production: Fixed VirtualAlloc parameter passing (size in RDX)

option casemap:none

; Windows API functions
extrn VirtualAlloc:proc
extrn VirtualFree:proc

; Allocation constants
MEM_COMMIT      EQU 1000h
MEM_RESERVE     EQU 2000h
MEM_RELEASE     EQU 8000h
PAGE_READWRITE  EQU 4

; Allocation tracking (max 256 allocations)
.data
ALIGN 16
alloc_table     QWORD 256 DUP(0)
alloc_count     DWORD 0

.code

; ---------------------------------------------------------
; RuntimeAlloc - Allocate memory
; RCX = size in bytes
; Returns: RAX = pointer to allocated memory (0 on failure)
; FIXED: Properly saves size before VirtualAlloc clobbers registers
; ---------------------------------------------------------
RuntimeAlloc PROC
    push rbx
    push r12
    sub rsp, 28h

    mov r12, rcx            ; r12 = requested size (preserved across calls)

    ; VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    ; Win64 ABI: RCX=lpAddress, RDX=dwSize, R8=flAllocationType, R9=flProtect
    xor ecx, ecx            ; lpAddress = NULL (let OS choose address)
    mov rdx, r12            ; dwSize = requested size  
    mov r8d, MEM_COMMIT or MEM_RESERVE
    mov r9d, PAGE_READWRITE
    
    call VirtualAlloc
    
    ; rax = allocated pointer or NULL
    test rax, rax
    jz ra_done              ; allocation failed
    
    ; Track allocation in table
    mov ebx, alloc_count
    cmp ebx, 256
    jge ra_done             ; table full (but allocation succeeded)
    
    mov [alloc_table + rbx*8], rax
    inc alloc_count
    
ra_done:
    add rsp, 28h
    pop r12
    pop rbx
    ret
RuntimeAlloc ENDP

; ---------------------------------------------------------
; RuntimeFree - Free allocated memory
; RCX = pointer to free
; Returns: RAX = 1 on success, 0 on failure  
; FIXED: Saves pointer before VirtualAlloc clobbers RCX
; ---------------------------------------------------------
RuntimeFree PROC
    push rbx
    sub rsp, 28h

    mov rbx, rcx            ; rbx = pointer to free (preserved)
    
    ; VirtualFree(ptr, 0, MEM_RELEASE)
    ; Win64 ABI: RCX=lpAddress, RDX=dwSize, R8=dwFreeType
    mov rcx, rbx            ; lpAddress
    xor edx, edx            ; dwSize = 0 (required for MEM_RELEASE)
    mov r8d, MEM_RELEASE    ; dwFreeType
    
    call VirtualFree
    
    ; rax = TRUE (nonzero) on success, FALSE (0) on failure
    test rax, rax
    jz rf_done              ; free failed, don't modify table
    
    ; Remove from tracking table - search for pointer
    xor ecx, ecx            ; index = 0
    
rf_search:
    cmp ecx, alloc_count
    jge rf_done             ; not found in table (ok)
    
    cmp [alloc_table + rcx*8], rbx
    je rf_found
    
    inc ecx
    jmp rf_search
    
rf_found:
    ; Found at index ecx - shift remaining entries down
    mov edx, ecx
    inc edx                 ; edx = next index
    
rf_shift:
    cmp edx, alloc_count
    jge rf_shift_done
    
    mov r8, [alloc_table + rdx*8]
    mov [alloc_table + rcx*8], r8
    
    inc ecx
    inc edx
    jmp rf_shift
    
rf_shift_done:
    dec alloc_count
    
rf_done:
    add rsp, 28h
    pop rbx
    ret
RuntimeFree ENDP

; ---------------------------------------------------------
; RuntimeAllocCount - Get number of active allocations
; Returns: RAX = allocation count
; ---------------------------------------------------------
RuntimeAllocCount PROC
    mov eax, alloc_count
    ret
RuntimeAllocCount ENDP

; ---------------------------------------------------------
; RuntimeAllocTotalSize - Get total bytes allocated
; Returns: RAX = total bytes (approximate)
; ---------------------------------------------------------
RuntimeAllocTotalSize PROC
    push rbx
    push r12
    
    xor r12, r12            ; total = 0
    xor ebx, ebx            ; index = 0
    
rat_loop:
    cmp ebx, alloc_count
    jge rat_done
    
    ; Get allocation info - would need size tracking
    ; For now, return count * 4096 (page size assumption)
    add r12, 4096
    
    inc ebx
    jmp rat_loop
    
rat_done:
    mov rax, r12
    
    pop r12
    pop rbx
    ret
RuntimeAllocTotalSize ENDP

END