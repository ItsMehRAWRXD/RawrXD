; =============================================================================
; Sovereign_Loader_MMAP.asm
; MASM x64 Implementation of Memory-Mapped File Loader
;
; Phase 14C: Zero-Copy Initialization via Windows MMAP
; Platform: Windows x64
; Assembler: ML64 (Microsoft Macro Assembler)
;
; Exports:
;   - Sovereign_MMAP_Init:      CreateFileMapping/MapViewOfFile
;   - Sovereign_MMAP_Cleanup:   UnmapViewOfFile/CloseHandle
;   - Sovereign_MMAP_Prefetch:  Touch pages for critical layers
;   - Sovereign_MMAP_GetPtr:    Get pointer to weight data
;
; ABI Compliance: Windows x64 calling convention
;   - RCX, RDX, R8, R9 for first 4 integer args
;   - XMM0-XMM3 for floating point
;   - RAX for return value
;   - Caller preserves: RBX, RBP, RDI, RSI, R12-R15
; =============================================================================

; External Windows API functions
EXTERN CreateFileA:PROC
EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetFileSizeEx:PROC
EXTERN GetLastError:PROC
EXTERN VirtualQuery:PROC
EXTERN PrefetchVirtualMemory:PROC

; External C runtime
EXTERN memset:PROC
EXTERN memcpy:PROC

; =============================================================================
; Data Section
; =============================================================================

.data

; Error messages
szErrorOpenFile       DB "[Sovereign_MMAP] Failed to open file", 0
szErrorCreateMapping  DB "[Sovereign_MMAP] Failed to create file mapping", 0
szErrorMapView        DB "[Sovereign_MMAP] Failed to map view", 0
szSuccessMMAP         DB "[Sovereign_MMAP] Successfully mapped %llu bytes", 0Dh, 0Ah, 0

; Constants
GENERIC_READ          EQU 80000000h
FILE_SHARE_READ       EQU 00000001h
OPEN_EXISTING         EQU 00000003h
FILE_ATTRIBUTE_NORMAL EQU 00000080h
FILE_FLAG_SEQUENTIAL_SCAN EQU 08000000h
PAGE_READONLY         EQU 00000002h
SEC_COMMIT            EQU 08000000h
FILE_MAP_READ         EQU 00000004h
INVALID_HANDLE_VALUE  EQU -1

; MMAP State Structure (64 bytes)
MMAP_STATE_SIZE       EQU 64
MMAP_STATE_hFile      EQU 0
MMAP_STATE_hMapping   EQU 8
MMAP_STATE_pView      EQU 16
MMAP_STATE_fileSize   EQU 24
MMAP_STATE_isValid    EQU 32
MMAP_STATE_reserved   EQU 36

; =============================================================================
; Code Section
; =============================================================================

.code

; =============================================================================
; Sovereign_MMAP_Init
; 
; Initializes memory-mapped file loading for a model.
;
; Input:
;   RCX = pointer to filepath (const char*)
;   RDX = pointer to MMAP_STATE structure (output)
;   R8  = prefetch flag (bool)
;
; Output:
;   RAX = 0 on success, error code on failure
;
; Clobbers: RAX, RCX, RDX, R8, R9, R10, R11
; =============================================================================

Sovereign_MMAP_Init PROC FRAME
    ; Save non-volatile registers
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
    
    ; Store parameters
    mov     r12, rcx        ; r12 = filepath
    mov     r13, rdx        ; r13 = MMAP_STATE pointer
    mov     r14, r8         ; r14 = prefetch flag
    
    ; Initialize MMAP_STATE to zero
    mov     rcx, r13
    xor     rdx, rdx
    mov     r8, MMAP_STATE_SIZE
    call    memset
    
    ; Step 1: CreateFileA
    ; RCX = filepath
    ; EDX = dwDesiredAccess = GENERIC_READ
    ; R8D = dwShareMode = FILE_SHARE_READ
    ; R9  = lpSecurityAttributes = NULL
    ; [RSP+0x28] = dwCreationDisposition = OPEN_EXISTING
    ; [RSP+0x30] = dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN
    ; [RSP+0x38] = hTemplateFile = NULL
    
    mov     rcx, r12                    ; filepath
    mov     edx, GENERIC_READ
    mov     r8d, FILE_SHARE_READ
    xor     r9, r9                      ; NULL
    
    sub     rsp, 40                     ; Shadow space + alignment
    mov     qword ptr [rsp+0x28], OPEN_EXISTING
    mov     rax, FILE_ATTRIBUTE_NORMAL
    or      rax, FILE_FLAG_SEQUENTIAL_SCAN
    mov     qword ptr [rsp+0x30], rax
    mov     qword ptr [rsp+0x38], 0
    
    call    CreateFileA
    add     rsp, 40
    
    cmp     rax, INVALID_HANDLE_VALUE
    je      MMAP_ERROR_FILE
    
    mov     [r13+MMAP_STATE_hFile], rax
    mov     r15, rax                    ; r15 = hFile
    
    ; Step 2: GetFileSizeEx
    ; RCX = hFile
    ; RDX = pointer to LARGE_INTEGER
    
    sub     rsp, 16                     ; Space for LARGE_INTEGER
    mov     rcx, r15
    mov     rdx, rsp
    call    GetFileSizeEx
    
    test    rax, rax
    jz      MMAP_ERROR_SIZE
    
    mov     rax, [rsp]                  ; Get file size (low 64 bits)
    add     rsp, 16
    mov     [r13+MMAP_STATE_fileSize], rax
    mov     r12, rax                    ; r12 = file size
    
    ; Step 3: CreateFileMappingA
    ; RCX = hFile
    ; RDX = lpFileMappingAttributes = NULL
    ; R8D = flProtect = PAGE_READONLY
    ; R9D = dwMaximumSizeHigh = 0 (use file size)
    ; [RSP+0x28] = dwMaximumSizeLow = 0 (use file size)
    ; [RSP+0x30] = lpName = NULL
    
    mov     rcx, r15
    xor     rdx, rdx
    mov     r8d, PAGE_READONLY
    xor     r9d, r9d
    
    sub     rsp, 40
    mov     qword ptr [rsp+0x28], 0
    mov     qword ptr [rsp+0x30], 0
    
    call    CreateFileMappingA
    add     rsp, 40
    
    test    rax, rax
    jz      MMAP_ERROR_MAPPING
    
    mov     [r13+MMAP_STATE_hMapping], rax
    mov     r15, rax                    ; r15 = hMapping
    
    ; Step 4: MapViewOfFile
    ; RCX = hFileMappingObject
    ; RDX = dwDesiredAccess = FILE_MAP_READ
    ; R8D = dwFileOffsetHigh = 0
    ; R9D = dwFileOffsetLow = 0
    ; [RSP+0x28] = dwNumberOfBytesToMap = 0 (map entire file)
    
    mov     rcx, r15
    mov     edx, FILE_MAP_READ
    xor     r8d, r8d
    xor     r9d, r9d
    
    sub     rsp, 40
    mov     qword ptr [rsp+0x28], 0
    
    call    MapViewOfFile
    add     rsp, 40
    
    test    rax, rax
    jz      MMAP_ERROR_VIEW
    
    mov     [r13+MMAP_STATE_pView], rax
    mov     dword ptr [r13+MMAP_STATE_isValid], 1
    
    ; Step 5: Prefetch critical layers if requested
    test    r14, r14
    jz      MMAP_SUCCESS
    
    ; Prefetch first 10% of file or 512MB, whichever is smaller
    mov     rcx, r12                    ; file size
    shr     rcx, 3                      ; / 8 = 12.5%
    mov     rdx, 512 * 1024 * 1024      ; 512MB
    cmp     rcx, rdx
    cmova   rcx, rdx                    ; RCX = min(12.5%, 512MB)
    
    mov     rdx, [r13+MMAP_STATE_pView] ; base pointer
    call    Sovereign_MMAP_Prefetch_Internal
    
MMAP_SUCCESS:
    xor     rax, rax                    ; Return 0 (success)
    jmp     MMAP_EXIT
    
MMAP_ERROR_FILE:
    mov     rax, 1                      ; Error code 1: File open failed
    jmp     MMAP_EXIT
    
MMAP_ERROR_SIZE:
    mov     rcx, [r13+MMAP_STATE_hFile]
    call    CloseHandle
    mov     rax, 2                      ; Error code 2: GetFileSize failed
    jmp     MMAP_EXIT
    
MMAP_ERROR_MAPPING:
    mov     rcx, [r13+MMAP_STATE_hFile]
    call    CloseHandle
    mov     rax, 3                      ; Error code 3: CreateFileMapping failed
    jmp     MMAP_EXIT
    
MMAP_ERROR_VIEW:
    mov     rcx, [r13+MMAP_STATE_hMapping]
    call    CloseHandle
    mov     rcx, [r13+MMAP_STATE_hFile]
    call    CloseHandle
    mov     rax, 4                      ; Error code 4: MapViewOfFile failed
    
MMAP_EXIT:
    ; Restore non-volatile registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
Sovereign_MMAP_Init ENDP

; =============================================================================
; Sovereign_MMAP_Cleanup
;
; Cleans up memory-mapped file resources.
;
; Input:
;   RCX = pointer to MMAP_STATE structure
;
; Output:
;   None
; =============================================================================

Sovereign_MMAP_Cleanup PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog
    
    mov     rbx, rcx                    ; RBX = MMAP_STATE pointer
    
    ; Check if valid
    cmp     dword ptr [rbx+MMAP_STATE_isValid], 0
    je      CLEANUP_EXIT
    
    ; UnmapViewOfFile
    mov     rcx, [rbx+MMAP_STATE_pView]
    test    rcx, rcx
    jz      SKIP_UNMAP
    call    UnmapViewOfFile
    
SKIP_UNMAP:
    ; Close mapping handle
    mov     rcx, [rbx+MMAP_STATE_hMapping]
    test    rcx, rcx
    jz      SKIP_CLOSE_MAPPING
    call    CloseHandle
    
SKIP_CLOSE_MAPPING:
    ; Close file handle
    mov     rcx, [rbx+MMAP_STATE_hFile]
    cmp     rcx, INVALID_HANDLE_VALUE
    je      SKIP_CLOSE_FILE
    call    CloseHandle
    
SKIP_CLOSE_FILE:
    ; Clear state
    mov     dword ptr [rbx+MMAP_STATE_isValid], 0
    
CLEANUP_EXIT:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
Sovereign_MMAP_Cleanup ENDP

; =============================================================================
; Sovereign_MMAP_Prefetch_Internal
;
; Prefetches pages by touching them (causing page faults).
;
; Input:
;   RCX = size to prefetch
;   RDX = base pointer
;
; Output:
;   None
; =============================================================================

Sovereign_MMAP_Prefetch_Internal PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog
    
    mov     rbx, rcx                    ; RBX = size
    mov     rsi, rdx                    ; RSI = base pointer
    
    ; Touch every 4KB page
    xor     rdi, rdi                    ; RDI = offset
    
PREFETCH_LOOP:
    cmp     rdi, rbx
    jae     PREFETCH_DONE
    
    ; Touch page at offset
    mov     al, byte ptr [rsi+rdi]
    
    ; Advance by page size (4096)
    add     rdi, 4096
    jmp     PREFETCH_LOOP
    
PREFETCH_DONE:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
Sovereign_MMAP_Prefetch_Internal ENDP

; =============================================================================
; Sovereign_MMAP_GetPtr
;
; Gets pointer to data at specified offset.
;
; Input:
;   RCX = pointer to MMAP_STATE
;   RDX = offset
;
; Output:
;   RAX = pointer to data, or NULL if invalid
; =============================================================================

Sovereign_MMAP_GetPtr PROC FRAME
    mov     r8, rcx                     ; R8 = MMAP_STATE
    
    ; Check if valid
    cmp     dword ptr [r8+MMAP_STATE_isValid], 0
    je      GETPTR_NULL
    
    ; Check offset bounds
    mov     rax, [r8+MMAP_STATE_fileSize]
    cmp     rdx, rax
    jae     GETPTR_NULL
    
    ; Calculate pointer
    mov     rax, [r8+MMAP_STATE_pView]
    add     rax, rdx
    ret
    
GETPTR_NULL:
    xor     rax, rax
    ret
    
Sovereign_MMAP_GetPtr ENDP

; =============================================================================
; Sovereign_MMAP_GetSize
;
; Gets the size of the mapped file.
;
; Input:
;   RCX = pointer to MMAP_STATE
;
; Output:
;   RAX = file size in bytes
; =============================================================================

Sovereign_MMAP_GetSize PROC FRAME
    mov     rax, [rcx+MMAP_STATE_fileSize]
    ret
Sovereign_MMAP_GetSize ENDP

; =============================================================================
; Sovereign_MMAP_IsResident
;
; Checks if a page is resident in RAM.
;
; Input:
;   RCX = pointer to MMAP_STATE
;   RDX = offset to check
;
; Output:
;   RAX = 1 if resident, 0 if not
; =============================================================================

Sovereign_MMAP_IsResident PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 64                     ; Space for MEMORY_BASIC_INFORMATION
    .allocstack 64
    .endprolog
    
    mov     rbx, rcx                    ; RBX = MMAP_STATE
    mov     rsi, rdx                    ; RSI = offset
    
    ; Check if valid
    cmp     dword ptr [rbx+MMAP_STATE_isValid], 0
    je      NOT_RESIDENT
    
    ; Get pointer
    mov     rcx, [rbx+MMAP_STATE_pView]
    add     rcx, rsi                    ; RCX = address to query
    
    ; VirtualQuery
    mov     rdx, rsp                    ; RDX = buffer for info
    mov     r8d, 48                     ; R8 = sizeof(MEMORY_BASIC_INFORMATION)
    call    VirtualQuery
    
    test    rax, rax
    jz      NOT_RESIDENT
    
    ; Check State field (offset 0x10 in MEMORY_BASIC_INFORMATION)
    mov     eax, dword ptr [rsp+0x10]   ; State
    cmp     eax, 1000h                  ; MEM_COMMIT = 0x1000
    jne     NOT_RESIDENT
    
    mov     rax, 1                      ; Resident
    jmp     IS_RESIDENT_EXIT
    
NOT_RESIDENT:
    xor     rax, rax                    ; Not resident
    
IS_RESIDENT_EXIT:
    add     rsp, 64
    pop     rsi
    pop     rbx
    ret
    
Sovereign_MMAP_IsResident ENDP

; =============================================================================
; Export Table
; =============================================================================

PUBLIC Sovereign_MMAP_Init
PUBLIC Sovereign_MMAP_Cleanup
PUBLIC Sovereign_MMAP_GetPtr
PUBLIC Sovereign_MMAP_GetSize
PUBLIC Sovereign_MMAP_IsResident

END
