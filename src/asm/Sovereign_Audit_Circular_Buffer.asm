; ==============================================================================
; Sovereign_Audit_Circular_Buffer.asm
; Logic: High-Performance Lock-Free SPSC Circular Audit Sink
; Purpose: Offloads telemetry writes to shared memory to eliminate I/O blocking.
; ==============================================================================

.DATA
    align 16
    AUDIT_CAPACITY     EQU 4096 ; Number of 64-byte entries (256KB total)
    AUDIT_ENTRY_SIZE   EQU 64   ; One cache line per entry
    
    g_AuditHead        dq 0     ; WRITER index (Engine)
    g_AuditTail        dq 0     ; READER index (Host/Watchdog)
    
    ; Shared Buffer Reference
    g_SharedBufferName db "Global\\SovereignAuditRing", 0
    g_hAuditMapping    dq 0
    g_pAuditBase       dq 0

    align 16
    g_AuditBuffer      db AUDIT_CAPACITY * AUDIT_ENTRY_SIZE dup(0)

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Audit_Init
; Logic: Creates the named shared memory region for the Watchdog.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Audit_Init
Sovereign_Audit_Init PROC
    push rbp
    mov rbp, rsp
    sub rsp, 48

    ; 1. Create named file mapping in pagefile
    ; CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, Size, Name)
    mov rcx, -1                 ; INVALID_HANDLE_VALUE
    xor rdx, rdx                ; lpAttributes = NULL
    mov r8, 4                   ; flProtect = PAGE_READWRITE
    xor r9, r9                  ; dwMaximumSizeHigh
    mov qword ptr [rsp+32], AUDIT_CAPACITY * AUDIT_ENTRY_SIZE ; dwMaximumSizeLow
    lea rax, g_SharedBufferName
    mov qword ptr [rsp+40], rax ; lpName
    call CreateFileMappingW
    
    test rax, rax
    jz @@Error
    mov [g_hAuditMapping], rax

    ; 2. Map the view
    ; MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0)
    mov rcx, rax
    mov rdx, 000F001Fh         ; FILE_MAP_ALL_ACCESS (Specific to Win64)
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call MapViewOfFile
    
    test rax, rax
    jz @@Error
    mov [g_pAuditBase], rax

    mov rax, 1
    jmp @@Done

@@Error:
    xor rax, rax

@@Done:
    add rsp, 48
    pop rbp
    ret
Sovereign_Audit_Init ENDP

; ------------------------------------------------------------------------------
; EXTERN CALLS
; ------------------------------------------------------------------------------
EXTERN CreateFileMappingW : PROC
EXTERN MapViewOfFile       : PROC

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Audit_Log
; Input: RCX = OpCode (8 bytes), RDX = Data (8 bytes), R8 = Timestamp (8 bytes)
; Logic: Appends to the circular buffer if space is available.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Audit_Log
Sovereign_Audit_Log PROC
    push rbx
    
    mov r11, [g_AuditHead]
    mov r10, [g_AuditTail]
    
    ; Check for Overflow: (Head + 1) % Capacity == Tail?
    mov rax, r11
    inc rax
    and rax, (AUDIT_CAPACITY - 1) ; Power of 2 mask
    
    cmp rax, r10
    je @@BufferFull
    
    ; Calculate offset: Head * EntrySize
    ; EntrySize 64 is (1 << 6)
    mov r9, r11
    shl r9, 6
    lea rbx, g_AuditBuffer
    add rbx, r9
    
    ; Store Data (Simplified 3-QWORD log)
    mov [rbx], rcx       ; OpCode
    mov [rbx + 8], rdx   ; Data
    mov [rbx + 16], r8   ; Timestamp / Cycle
    
    ; Update Head (Store-Release semantics)
    ; In x64, stores are already released relative to other stores.
    mov [g_AuditHead], rax
    
    mov rax, 1
    jmp @@Done

@@BufferFull:
    xor rax, rax

@@Done:
    pop rbx
    ret
Sovereign_Audit_Log ENDP

END
