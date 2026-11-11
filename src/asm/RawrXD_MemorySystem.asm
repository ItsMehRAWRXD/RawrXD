; =============================================================================
; RawrXD_MemorySystem.asm - Three-Layer Persistent Memory Architecture
; Based on Claude Code's MEMORY.md + Topic Files + Transcript Index
; MASM64 Compatible - Windows x64 ABI
; =============================================================================

OPTION CASEMAP:NONE

include masm64_compat.inc

; External Windows API functions
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN CreateMutexW:PROC
EXTERN CreateEventW:PROC
EXTERN CloseHandle:PROC
EXTERN WaitForSingleObject:PROC
EXTERN ReleaseMutex:PROC
EXTERN SetEvent:PROC
EXTERN GetLastError:PROC

INCLUDELIB kernel32.lib

; Constants
MEMORY_LAYER_INDEX      EQU 1
MEMORY_LAYER_TOPICS     EQU 2
MEMORY_LAYER_TRANSCRIPT EQU 3

MEM_TYPE_CONTEXT        EQU 1
MEM_TYPE_DECISION       EQU 2
MEM_TYPE_PATTERN        EQU 3

MAX_TOPICS              EQU 256
HASH_TABLE_SIZE         EQU 1024
MEMORY_MAGIC            EQU 0544D5852h  ; 'RXMT'

; Structures
MEMORY_INDEX_ENTRY STRUCT
    entryType       DWORD ?
    priority        DWORD ?
    topicHash       DWORD ?
    lastAccessed    QWORD ?
    accessCount     DWORD ?
    title           BYTE 128 DUP(?)
    summary         BYTE 512 DUP(?)
MEMORY_INDEX_ENTRY ENDS

MEMORY_SYSTEM_CONTEXT STRUCT
    indexEntries    QWORD ?
    indexCount      DWORD ?
    indexCapacity   DWORD ?
    indexModified   BYTE ?
    topicCache      QWORD ?
    topicCacheSize  DWORD ?
    topicHashTable  QWORD ?
    hMutex          QWORD ?
    hIndexEvent     QWORD ?
    basePath        BYTE 260 DUP(?)
    indexPath       BYTE 260 DUP(?)
    autoSaveInterval DWORD ?
MEMORY_SYSTEM_CONTEXT ENDS

; Structure field offsets for MASM64 compatibility
MEMORY_SYSTEM_CONTEXT_basePath        EQU 0
MEMORY_SYSTEM_CONTEXT_indexPath       EQU 260
MEMORY_SYSTEM_CONTEXT_indexEntries    EQU 520
MEMORY_SYSTEM_CONTEXT_indexCount      EQU 528
MEMORY_SYSTEM_CONTEXT_indexCapacity   EQU 532
MEMORY_SYSTEM_CONTEXT_indexModified   EQU 536
MEMORY_SYSTEM_CONTEXT_topicCache      EQU 544
MEMORY_SYSTEM_CONTEXT_topicCacheSize  EQU 552
MEMORY_SYSTEM_CONTEXT_topicHashTable  EQU 560
MEMORY_SYSTEM_CONTEXT_hMutex          EQU 568
MEMORY_SYSTEM_CONTEXT_hIndexEvent     EQU 576
MEMORY_SYSTEM_CONTEXT_autoSaveInterval EQU 584

.DATA
g_szMemorySubdir    BYTE "memory", 0
g_szIndexFile       BYTE "MEMORY.md", 0
g_szTopicsDir       BYTE "topics", 0
g_szIndexHeader     BYTE "# RawrXD Memory Index", 13, 10, 0

.CODE

; =============================================================================
; MemorySystem_Initialize - Initialize the three-layer memory system
; Windows x64 ABI: RCX = HWND (placeholder), RDX = Project path, R8 = Context
; =============================================================================
MemorySystem_Initialize PROC FRAME
    ; Save non-volatile registers
    push rbx
    .pushframe
    push rsi
    push rdi
    push r12
    push r13
    push r14
    .pushframe
    .endprolog
    
    mov r12, rcx                    ; HWND (placeholder use)
    mov r13, rdx                    ; Project path
    mov r14, r8                     ; Context
    
    ; Get process heap handle
    sub rsp, 28h                    ; Shadow space for GetProcessHeap
    call GetProcessHeap
    add rsp, 28h
    mov rbx, rax                    ; Save heap handle in rbx
    
    ; Setup paths - copy basePath from project path
    lea rdi, [r14 + MEMORY_SYSTEM_CONTEXT_basePath]
    mov rsi, r13
@@copy_base:
    lodsb
    stosb
    test al, al
    jnz @@copy_base
    
    ; Create index path - copy from basePath
    lea rdi, [r14 + MEMORY_SYSTEM_CONTEXT_indexPath]
    lea rsi, [r14 + MEMORY_SYSTEM_CONTEXT_basePath]
@@copy_index:
    lodsb
    stosb
    test al, al
    jnz @@copy_index
    
    ; Allocate Layer 1 Index
    ; HeapAlloc(hHeap, dwFlags, dwBytes)
    ; RCX = hHeap, RDX = dwFlags, R8 = dwBytes
    mov rcx, rbx                    ; hHeap
    xor rdx, rdx                    ; dwFlags = 0 (default)
    mov r8, MAX_TOPICS * SIZEOF MEMORY_INDEX_ENTRY
    sub rsp, 28h
    call HeapAlloc
    add rsp, 28h
    
    ; Store allocated pointer
    mov [r14 + MEMORY_SYSTEM_CONTEXT_indexEntries], rax
    
    ; Set initial capacity
    mov dword ptr [r14 + MEMORY_SYSTEM_CONTEXT_indexCapacity], MAX_TOPICS
    
    ; Create mutex for thread safety
    ; CreateMutexW(lpMutexAttributes, bInitialOwner, lpName)
    ; RCX = lpMutexAttributes, RDX = bInitialOwner, R8 = lpName
    xor rcx, rcx                    ; NULL attributes
    xor rdx, rdx                    ; FALSE initial owner
    xor r8, r8                      ; NULL name
    sub rsp, 28h
    call CreateMutexW
    add rsp, 28h
    mov [r14 + MEMORY_SYSTEM_CONTEXT_hMutex], rax
    
    ; Create event for index synchronization
    ; CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName)
    ; RCX = lpEventAttributes, RDX = bManualReset, R8 = bInitialState, R9 = lpName
    xor rcx, rcx                    ; NULL attributes
    mov rdx, 1                      ; TRUE manual reset
    xor r8, r8                      ; FALSE initial state
    xor r9, r9                      ; NULL name
    sub rsp, 28h
    call CreateEventW
    add rsp, 28h
    mov [r14 + MEMORY_SYSTEM_CONTEXT_hIndexEvent], rax
    
    ; Return TRUE
    mov rax, 1
    
    ; Restore non-volatile registers
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
MemorySystem_Initialize ENDP

PUBLIC MemorySystem_Initialize

; =============================================================================
; MemorySystem_AddEntry - Add a memory entry to the index
; Windows x64 ABI: RCX = Context, RDX = Entry pointer
; Returns: RAX = TRUE on success, FALSE on failure
; =============================================================================
MemorySystem_AddEntry PROC FRAME
    ; Save non-volatile registers
    push rbx
    .pushframe
    push rsi
    push rdi
    push r12
    .pushframe
    .endprolog
    
    mov r12, rcx                    ; Context pointer
    mov r13, rdx                    ; Entry pointer
    
    ; Validate parameters
    test r12, r12
    jz @@fail
    test r13, r13
    jz @@fail
    
    ; Check if index entries allocated
    mov rax, [r12 + MEMORY_SYSTEM_CONTEXT_indexEntries]
    test rax, rax
    jz @@fail
    
    ; Get current count and check capacity
    mov eax, [r12 + MEMORY_SYSTEM_CONTEXT_indexCount]
    mov ecx, [r12 + MEMORY_SYSTEM_CONTEXT_indexCapacity]
    cmp eax, ecx
    jae @@fail                      ; At capacity
    
    ; Calculate destination address
    ; dest = indexEntries + (indexCount * SIZEOF MEMORY_INDEX_ENTRY)
    mov rcx, SIZEOF MEMORY_INDEX_ENTRY
    mul rcx                         ; RAX = indexCount * size
    mov rbx, [r12 + MEMORY_SYSTEM_CONTEXT_indexEntries]
    add rbx, rax                    ; RBX = destination address
    
    ; Copy entry to index
    mov rsi, r13                    ; Source
    mov rdi, rbx                    ; Destination
    mov rcx, SIZEOF MEMORY_INDEX_ENTRY
    rep movsb
    
    ; Increment count
    inc dword ptr [r12 + MEMORY_SYSTEM_CONTEXT_indexCount]
    
    ; Mark as modified
    mov byte ptr [r12 + MEMORY_SYSTEM_CONTEXT_indexModified], 1
    
    ; Return TRUE
    mov rax, 1
    jmp @@done
    
@@fail:
    xor rax, rax                    ; Return FALSE
    
@@done:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
MemorySystem_AddEntry ENDP

PUBLIC MemorySystem_AddEntry

; =============================================================================
; MemorySystem_Shutdown - Clean up memory system resources
; Windows x64 ABI: RCX = Context
; =============================================================================
MemorySystem_Shutdown PROC FRAME
    push rbx
    .pushframe
    push rsi
    .pushframe
    .endprolog
    
    mov rbx, rcx                    ; Context pointer
    
    test rbx, rbx
    jz @@done
    
    ; Free index entries if allocated
    mov rcx, [rbx + MEMORY_SYSTEM_CONTEXT_indexEntries]
    test rcx, rcx
    jz @@free_handles
    
    ; Get process heap for HeapFree
    sub rsp, 28h
    call GetProcessHeap
    add rsp, 28h
    mov rsi, rax                    ; Save heap handle
    
    ; HeapFree(hHeap, dwFlags, lpMem)
    mov rcx, rsi                    ; hHeap
    xor rdx, rdx                    ; dwFlags = 0
    mov r8, [rbx + MEMORY_SYSTEM_CONTEXT_indexEntries]
    sub rsp, 28h
    call HeapFree
    add rsp, 28h
    
@@free_handles:
    ; Close mutex handle
    mov rcx, [rbx + MEMORY_SYSTEM_CONTEXT_hMutex]
    test rcx, rcx
    jz @@close_event
    sub rsp, 28h
    call CloseHandle
    add rsp, 28h
    
@@close_event:
    ; Close event handle
    mov rcx, [rbx + MEMORY_SYSTEM_CONTEXT_hIndexEvent]
    test rcx, rcx
    jz @@done
    sub rsp, 28h
    call CloseHandle
    add rsp, 28h
    
@@done:
    pop rsi
    pop rbx
    ret
MemorySystem_Shutdown ENDP

PUBLIC MemorySystem_Shutdown

END


