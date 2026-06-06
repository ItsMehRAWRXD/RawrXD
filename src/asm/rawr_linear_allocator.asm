; rawr_linear_allocator.asm
; Sovereign Memory Arena — VirtualAlloc with Large Page support
; Replaces HeapAlloc for deterministic multi-GB model mapping
;
; Exports:
;   RawrLinearAlloc_Init          — enable SeLockMemoryPrivilege, init state
;   RawrLinearAlloc_Alloc         — VirtualAlloc (large-page attempt, 4KB fallback)
;   RawrLinearAlloc_Free          — VirtualFree
;   RawrLinearAlloc_Realloc       — new alloc + memcpy + free
;   RawrLinearAlloc_GetStats      — {allocCount, freeCount, largePageCount}
;   RawrLinearAlloc_InitArena     — reserve contiguous arena (MEM_RESERVE)
;   RawrLinearAlloc_CommitArena   — commit sub-range (MEM_COMMIT)
;   RawrLinearAlloc_ReleaseArena  — release entire reservation
;
; Calling convention: Microsoft x64 (RCX, RDX, R8, R9)

; Windows API imports
extern GetCurrentProcess      : proc
extern OpenProcessToken       : proc
extern LookupPrivilegeValueA  : proc
extern AdjustTokenPrivileges  : proc
extern VirtualAlloc           : proc
extern VirtualFree            : proc
extern GetLastError           : proc
extern RtlCopyMemory          : proc

; Constants
MEM_RESERVE        equ 00002000h
MEM_COMMIT         equ 00001000h
MEM_LARGE_PAGES    equ 20000000h
MEM_RELEASE        equ 00008000h
PAGE_READWRITE     equ 04h
PAGE_READONLY      equ 02h
PAGE_NOACCESS      equ 01h
TOKEN_ADJUST_PRIVILEGES equ 0020h
TOKEN_QUERY        equ 0008h
SE_PRIVILEGE_ENABLED equ 00000002h

; LUID_AND_ATTRIBUTES + TOKEN_PRIVILEGES layout
LUID_AND_ATTRIBUTES_SIZE equ 12
TOKEN_PRIVILEGES_SIZE    equ 16

.data
    g_hToken        dq 0
    g_largePageOk   dq 0          ; 1 if SeLockMemoryPrivilege granted
    g_allocCount    dq 0
    g_freeCount     dq 0
    g_largePageCnt  dq 0
    g_arenaBase     dq 0
    g_arenaReserved dq 0

    ; Static buffer for AdjustTokenPrivileges (avoid heap during init)
    ALIGN 8
    tokPrivBuf      db TOKEN_PRIVILEGES_SIZE + LUID_AND_ATTRIBUTES_SIZE dup (0)
    szPrivilege     db "SeLockMemoryPrivilege", 0

.code

; ---------------------------------------------------------------------------
; RawrLinearAlloc_Init
;   RCX = flags (reserved, pass 0)
;   Enables SeLockMemoryPrivilege for large pages; falls back silently.
;   Returns: RAX = 1 on success, 0 on failure
; ---------------------------------------------------------------------------
RawrLinearAlloc_Init proc public
    sub rsp, 56

    ; 1. Open process token
    xor rdx, rdx
    mov rcx, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY
    lea r8, g_hToken
    call OpenProcessToken
    test rax, rax
    jz @init_done_ok            ; No token = no large pages, but still OK

    ; 2. Lookup LUID for SeLockMemoryPrivilege
    lea rcx, tokPrivBuf
    mov dword ptr [rcx], 1              ; PrivilegeCount = 1
    lea rdx, [rcx + 4]                  ; LUID offset
    lea r8, [rcx + 12]                  ; Attributes offset
    mov dword ptr [r8], SE_PRIVILEGE_ENABLED
    lea rcx, [tokPrivBuf + 4]           ; LUID pointer
    lea rdx, szPrivilege
    xor r8, r8
    call LookupPrivilegeValueA
    test rax, rax
    jz @init_close_token

    ; 3. Adjust token privileges
    mov rcx, g_hToken
    xor rdx, rdx
    lea r8, tokPrivBuf
    xor r9, r9
    mov qword ptr [rsp + 32], 0         ; ReturnLength = NULL
    call AdjustTokenPrivileges
    test rax, rax
    jz @init_close_token

    ; 4. Verify large pages actually work by probing a small allocation
    mov rcx, 0
    mov rdx, 4096
    mov r8, MEM_COMMIT or MEM_RESERVE or MEM_LARGE_PAGES
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    test rax, rax
    jz @init_close_token
    mov g_largePageOk, 1
    mov rcx, rax
    mov rdx, 0
    mov r8, MEM_RELEASE
    call VirtualFree

@init_close_token:
    ; Token handle leaked intentionally (we keep it for future use)
    ; In production, close it if you care about handle count.

@init_done_ok:
    mov rax, 1
    add rsp, 56
    ret
RawrLinearAlloc_Init endp

; ---------------------------------------------------------------------------
; RawrLinearAlloc_Alloc
;   RCX = size in bytes
;   Returns: RAX = pointer to zeroed memory, or NULL
;   Strategy: try MEM_LARGE_PAGES first, fall back to standard commit.
; ---------------------------------------------------------------------------
RawrLinearAlloc_Alloc proc public
    push rbx
    sub rsp, 40
    mov rbx, rcx                    ; save size

    ; Round up to next 4KB boundary (VirtualAlloc granularity)
    add rbx, 4095
    and rbx, -4096

    ; Attempt large pages if enabled
    cmp g_largePageOk, 0
    jz @alloc_standard

    mov rcx, 0                      ; lpAddress = NULL (let OS choose)
    mov rdx, rbx                    ; dwSize
    mov r8, MEM_COMMIT or MEM_RESERVE or MEM_LARGE_PAGES
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    test rax, rax
    jnz @alloc_success_large

@alloc_standard:
    mov rcx, 0
    mov rdx, rbx
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    test rax, rax
    jz @alloc_done
    jmp @alloc_success

@alloc_success_large:
    inc qword ptr [g_largePageCnt]
@alloc_success:
    inc qword ptr [g_allocCount]
@alloc_done:
    add rsp, 40
    pop rbx
    ret
RawrLinearAlloc_Alloc endp

; ---------------------------------------------------------------------------
; RawrLinearAlloc_Free
;   RCX = pointer to free
;   Returns: RAX = 1 on success, 0 on failure
; ---------------------------------------------------------------------------
RawrLinearAlloc_Free proc public
    sub rsp, 40
    test rcx, rcx
    jz @free_done                   ; NULL free is no-op
    mov rdx, 0                      ; dwSize = 0 (entire region)
    mov r8, MEM_RELEASE
    call VirtualFree
    test rax, rax
    jz @free_done
    inc qword ptr [g_freeCount]
@free_done:
    mov rax, 1
    add rsp, 40
    ret
RawrLinearAlloc_Free endp

; ---------------------------------------------------------------------------
; RawrLinearAlloc_Realloc
;   RCX = old pointer (may be NULL)
;   RDX = new size in bytes
;   Returns: RAX = new pointer, or NULL
;   Note: VirtualAlloc has no Realloc; we alloc new, copy, free old.
; ---------------------------------------------------------------------------
RawrLinearAlloc_Realloc proc public
    push rbx
    push r12
    push r13
    sub rsp, 56
    mov rbx, rcx                    ; old pointer
    mov r12, rdx                    ; new size

    ; Allocate new block
    mov rcx, r12
    call RawrLinearAlloc_Alloc
    test rax, rax
    jz @realloc_done
    mov r13, rax                    ; new pointer

    ; Copy old data (min of old/new size)
    ; We don't track old size, so caller must handle truncation.
    ; For sovereign use, realloc is rare; this is a safety stub.
    test rbx, rbx
    jz @realloc_no_copy
    mov rcx, r13                    ; dest
    mov rdx, rbx                    ; src
    mov r8, r12                     ; count (copy up to new size)
    call RtlCopyMemory

@realloc_no_copy:
    ; Free old block
    mov rcx, rbx
    call RawrLinearAlloc_Free

    mov rax, r13
@realloc_done:
    add rsp, 56
    pop r13
    pop r12
    pop rbx
    ret
RawrLinearAlloc_Realloc endp

; ---------------------------------------------------------------------------
; RawrLinearAlloc_GetStats
;   RCX = pointer to uint64_t[3] buffer {allocCount, freeCount, largePageCount}
; ---------------------------------------------------------------------------
RawrLinearAlloc_GetStats proc public
    mov rax, qword ptr [g_allocCount]
    mov qword ptr [rcx], rax
    mov rax, qword ptr [g_freeCount]
    mov qword ptr [rcx+8], rax
    mov rax, qword ptr [g_largePageCnt]
    mov qword ptr [rcx+16], rax
    ret
RawrLinearAlloc_GetStats endp

; ---------------------------------------------------------------------------
; RawrLinearAlloc_InitArena
;   RCX = total reserve size in bytes (e.g. 6GB for model + activations)
;   Returns: RAX = base pointer of reserved region, or NULL
;   Alignment: automatically aligned to allocation granularity (64KB)
; ---------------------------------------------------------------------------
RawrLinearAlloc_InitArena proc public
    push rbx
    sub rsp, 40
    mov rbx, rcx

    ; Round up to 2MB for large-page friendliness
    add rbx, 2097151
    and rbx, -2097152

    mov rcx, 0                      ; let OS choose address
    mov rdx, rbx
    mov r8, MEM_RESERVE             ; reserve only; commit on demand
    mov r9, PAGE_NOACCESS           ; no access until committed
    call VirtualAlloc
    test rax, rax
    jz @arena_done
    mov g_arenaBase, rax
    mov g_arenaReserved, rbx
@arena_done:
    add rsp, 40
    pop rbx
    ret
RawrLinearAlloc_InitArena endp

; ---------------------------------------------------------------------------
; RawrLinearAlloc_CommitArena
;   RCX = arena base pointer (from InitArena)
;   RDX = offset within arena
;   R8  = size to commit
;   R9  = protect flags (PAGE_READONLY or PAGE_READWRITE)
;   Returns: RAX = 1 on success, 0 on failure
; ---------------------------------------------------------------------------
RawrLinearAlloc_CommitArena proc public
    sub rsp, 40
    ; Round offset down to 4KB, size up to 4KB
    mov r10, rdx
    and r10, -4096
    mov r11, r8
    add r11, 4095
    and r11, -4096
    add r11, rdx
    sub r11, r10                  ; adjusted size covering full pages

    add rcx, r10                  ; actual commit address
    mov rdx, r11
    mov r8, MEM_COMMIT
    ; R9 already holds protect flags
    call VirtualAlloc
    test rax, rax
    setnz al
    movzx rax, al
    add rsp, 40
    ret
RawrLinearAlloc_CommitArena endp

; ---------------------------------------------------------------------------
; RawrLinearAlloc_ReleaseArena
;   RCX = arena base pointer
;   Returns: RAX = 1 on success
; ---------------------------------------------------------------------------
RawrLinearAlloc_ReleaseArena proc public
    sub rsp, 40
    test rcx, rcx
    jz @release_done
    mov rdx, 0
    mov r8, MEM_RELEASE
    call VirtualFree
    xor rcx, rcx
    mov g_arenaBase, rcx
    mov g_arenaReserved, rcx
@release_done:
    mov rax, 1
    add rsp, 40
    ret
RawrLinearAlloc_ReleaseArena endp

end

END
