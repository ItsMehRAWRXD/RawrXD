; Sovereign_Stream_Ingest.asm - GGUF File Ingestion
; ABI: Zero-CRT, Win64
; Maps GGUF tensor blob via OS-chosen VA (no forced base)

include Sovereign_Common.inc

extern g_ApiTable : SOVEREIGN_API_TABLE

.DATA
    align 8
    TensorFileName  DW 'D',':','\','r','a','w','r','x','d','\','p','h','i','3','-','m','i','n','i','-','Q','2','_','K','.','g','g','u','f',0
    szLockPriv      DW 'S','e','L','o','c','k','M','e','m','o','r','y','P','r','i','v','i','l','e','g','e',0

PUBLIC g_IngestStatus
PUBLIC g_MappedBase
PUBLIC g_MappedSize
PUBLIC g_ManifestBase
PUBLIC g_TensorBase
PUBLIC g_LastIngestError

g_IngestStatus      dd 0
g_MappedBase        dq 0
g_MappedSize        dq 0
g_ManifestBase      dq 0
g_TensorBase        dq 0
g_LastIngestError   dq 0

.CODE

; ============================================================
; XR_Acquire_LargePage_Privilege - Enables SeLockMemoryPrivilege
; ============================================================
PUBLIC XR_Acquire_LargePage_Privilege
XR_Acquire_LargePage_Privilege PROC
    push rbx
    sub rsp, 80                         ; Shadow(32) + locals(48)

    ; OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hTok)
    mov rcx, -1                        ; hProcess (GetCurrentProcess() pseudo-handle)
    mov edx, 28h                        ; TOKEN_ADJUST_PRIVILEGES(20h) | TOKEN_QUERY(8h)
    lea     r8, [rsp+64]                ; &hTok
    call    [g_ApiTable.pOpenProcessToken]
    test    eax, eax
    jz      priv_fail

    ; LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &luid)
    xor     ecx, ecx
    lea     rdx, [szLockPriv]
    lea     r8, [rsp+48]                ; &luid (8 bytes)
    call    [g_ApiTable.pLookupPrivilegeValueW]
    test    eax, eax
    jz      priv_fail

    ; Build TOKEN_PRIVILEGES at [rsp+56]: count(4) + luid(8) + attrs(4)
    mov     dword ptr [rsp+56], 1       ; PrivilegeCount = 1
    mov     rax, [rsp+48]               ; LUID
    mov     qword ptr [rsp+60], rax     ; Privileges[0].Luid
    mov     dword ptr [rsp+68], 2       ; SE_PRIVILEGE_ENABLED

    mov     rcx, [rsp+64]               ; hTok
    xor     edx, edx                    ; DisableAllPrivileges = FALSE
    lea     r8, [rsp+56]                ; NewState
    mov     r9d, 16                     ; BufferLength
    mov     qword ptr [rsp+32], 0       ; PreviousState = NULL
    mov     qword ptr [rsp+40], 0       ; ReturnLength  = NULL
    call    [g_ApiTable.pAdjustTokenPrivileges]

    mov     rcx, [rsp+64]
    call    [g_ApiTable.pCloseHandle]

priv_fail:
    add rsp, 80
    pop rbx
    ret
XR_Acquire_LargePage_Privilege ENDP


; ============================================================
; XR_Dispatch_Ingest - Maps GGUF file into memory
; Returns:  RAX = mapped base (success), 0=fail, 2=CreateFile fail,
;           3=CreateFileMapping fail, 4=MapViewOfFile fail
; ============================================================
PUBLIC XR_Dispatch_Ingest
XR_Dispatch_Ingest PROC
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 72                         ; Shadow(32) + locals(40), 16-byte aligned

    ; ---- 1. CreateFileW ----
    lea rcx, [TensorFileName]
    mov edx, 80000000h                  ; GENERIC_READ
    mov r8d, 1                          ; FILE_SHARE_READ
    xor r9, r9                          ; lpSecurityAttributes = NULL
    mov qword ptr [rsp+32], 3           ; OPEN_EXISTING
    mov qword ptr [rsp+40], 080h        ; FILE_ATTRIBUTE_NORMAL (no NO_BUFFERING, mapping incompatible)
    mov qword ptr [rsp+48], 0           ; hTemplateFile = NULL
    call    [g_ApiTable.pCreateFileW]
    mov r12, rax                        ; hFile
    cmp rax, -1
    je fail_file

    ; ---- 2. GetFileSize ----
    mov rcx, r12
    lea rdx, [rsp+56]                   ; lpFileSizeHigh
    call    [g_ApiTable.pGetFileSize]
    cmp eax, -1                         ; INVALID_FILE_SIZE
    jne size_ok
    cmp dword ptr [rsp+56], 0
    je fail_close_file
size_ok:
    mov r13d, eax                       ; size low
    mov r14d, dword ptr [rsp+56]        ; size high
    mov rax, r14
    shl rax, 32
    or rax, r13
    mov [g_MappedSize], rax

    ; ---- 3. CreateFileMappingW(hFile, NULL, PAGE_READONLY, sizeHigh, sizeLow, NULL) ----
    mov rcx, r12                        ; hFile
    xor edx, edx                        ; lpAttributes = NULL
    mov r8d, 2                          ; PAGE_READONLY
    mov r9d, r14d                       ; dwMaximumSizeHigh
    mov dword ptr [rsp+32], r13d         ; dwMaximumSizeLow
    mov qword ptr [rsp+40], 0           ; lpName = NULL
    call    [g_ApiTable.pCreateFileMappingW]
    mov rbx, rax                        ; hMap
    test rax, rax
    jz fail_close_file

    ; ---- 4. MapViewOfFileEx(hMap, FILE_MAP_READ, 0, 0, 0, NULL) ----
    mov rcx, rbx                        ; hMap
    mov edx, 4                          ; FILE_MAP_READ
    xor r8, r8                          ; dwFileOffsetHigh = 0
    xor r9, r9                          ; dwFileOffsetLow  = 0
    mov qword ptr [rsp+32], 0           ; dwNumberOfBytesToMap = 0 (entire file)
    mov qword ptr [rsp+40], 0           ; lpBaseAddress = NULL (OS chooses)
    call    [g_ApiTable.pMapViewOfFileEx]
    test rax, rax
    jz fail_close_map

    ; ---- Success ----
    mov [g_MappedBase], rax
    mov dword ptr [g_IngestStatus], 1

    ; Close handles (mapping persists while view is open)
    mov rcx, rbx
    call [g_ApiTable.pCloseHandle]
    mov rcx, r12
    call [g_ApiTable.pCloseHandle]

    mov rax, [g_MappedBase]
    jmp dispatch_done

fail_close_map:
    call [g_ApiTable.pGetLastError]
    mov [g_LastIngestError], rax
    mov rcx, rbx
    call [g_ApiTable.pCloseHandle]
    mov rcx, r12
    call [g_ApiTable.pCloseHandle]
    mov rax, 4                          ; MapViewOfFileEx failed
    jmp dispatch_done

fail_close_file:
    call [g_ApiTable.pGetLastError]
    mov [g_LastIngestError], rax
    mov rcx, r12
    call [g_ApiTable.pCloseHandle]
    mov rax, 3                          ; CreateFileMappingW failed
    jmp dispatch_done

fail_file:
    call [g_ApiTable.pGetLastError]
    mov [g_LastIngestError], rax
    mov rax, 2                          ; CreateFileW failed

dispatch_done:
    add rsp, 72
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
XR_Dispatch_Ingest ENDP


; ============================================================
; Sovereign_Stream_Release - Unmaps GGUF view
; ============================================================
PUBLIC Sovereign_Stream_Release
Sovereign_Stream_Release PROC
    sub rsp, 40
    mov rcx, [g_MappedBase]
    test rcx, rcx
    jz release_done
    call    [g_ApiTable.pUnmapViewOfFile]
    mov qword ptr [g_MappedBase], 0
release_done:
    add rsp, 40
    ret
Sovereign_Stream_Release ENDP


; Backwards compatibility stub
PUBLIC Sovereign_Stream_Ingest
Sovereign_Stream_Ingest PROC
    jmp XR_Dispatch_Ingest
Sovereign_Stream_Ingest ENDP

END
