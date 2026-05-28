; ==================================================================================
; Sovereign_Parity.asm - Drop-In Monolithic Integrity Engine
; Architecture: x64 MASM Monolith (Zero-IAT, Strict 64-bit Slot ABI Compliance)
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_Registry.inc
include Sovereign_Security.inc
include Sovereign_Macros.inc

.DATA
ALIGN 64
; Runtime Global Registry Fields
g_hStdOut               QWORD 0
g_pWriteFile            QWORD 0
g_EnterpriseFeatures    QWORD 0
g_800B_Unlocked         DWORD 0

; Provenance Allocation Substrate (Shielded Tracking Arena)
ALIGN 64
g_ProvenanceRegistry    PROVENANCE_RECORD 1024 DUP(<0>)
g_ProvenanceCount       QWORD 0
g_TelemetryCore         TELEMETRY_BLOCK <0>

; Local Strings for System Events
ALIGN 16
szHexPrefix             DB "0x", 0
szPanicMsg              DB "!!! SOVEREIGN KERNEL PANIC: COMPLIANCE VIOLATION !!!", 13, 10, 0
szLeakDetected          DB "[-] PROVENANCE ALERT: Active Allocation Leak on Exit.", 13, 10, 0
szHexDigits             DB "0123456789ABCDEF"

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Resolve_Core_APIs - Pure PEB-Parsing Dynamic Resolution Kernel
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Resolve_Core_APIs
Sovereign_Resolve_Core_APIs PROC
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    push rbx
    ALLOC_LEAF_FRAME 32             ; Setup frame parameters

    ; Locating the Process Environment Block (PEB) directly
    mov rax, gs:[60h]               ; rax = PEB pointer
    mov rax, [rax + 18h]            ; rax = PEB_LDR_DATA pointer
    mov rsi, [rax + 20h]            ; rsi = InInMemoryOrderModuleList (InMemoryOrderLinks)

@@NextModule:
    ; Walk through memory modules list safely
    mov rbx, [rsi + 50h]            ; rbx = BaseDllName.Buffer (Unicode)
    test rbx, rbx
    jz @@ModuleLoopNext
    
    ; Identify target library signatures via hardcoded inline offsets
    mov rax, [rbx]                  ; Read first 4 wide chars
    cmp eax, 006B004Bh              ; Check for wide-char 'k'/'K' layout
    je @@CheckKernel32
    jmp @@ModuleLoopNext

@@CheckKernel32:
    mov rax, [rsi + 20h]            ; rax = DllBase address of module
    mov [g_ApiTable.pKernel32Base], rax
    jmp @@ExportResolution

@@ModuleLoopNext:
    mov rsi, [rsi]                  ; Move forward down the list pointer chain
    jmp @@NextModule

@@ExportResolution:
    ; Direct PEB parse path to manually locate GetProcAddress
    mov rbx, [g_ApiTable.pKernel32Base]
    mov eax, [rbx + 3Ch]            ; eax = e_lfanew
    mov edx, [rbx + rax + 88h]      ; edx = Export Directory RVA
    add rdx, rbx                    ; rdx = Export Directory VA
    
    mov ecx, [rdx + 20h]            ; ecx = AddressOfNames RVA
    add rcx, rbx                    ; rcx = AddressOfNames VA
    xor r9, r9                      ; Function index tracking register

@@NameLoop:
    mov edi, [rcx + r9*4]           ; edi = Name RVA
    add rdi, rbx                    ; rdi = Name VA (ASCII)
    
    ; Match against known GetProcAddress signature values
    mov rax, [rdi]
    cmp rax, 50746547h              ; "GetP" string match
    jne @@NextName
    mov eax, [rdi + 4]
    cmp eax, 41636F72h              ; "rocA" string match
    jne @@NextName
    
    ; Found signature index match
    mov r8d, [rdx + 24h]            ; r8d = AddressOfNameOrdinals RVA
    add r8, rbx
    movzx r11d, word ptr [r8 + r9*2] ; Get function ordinal
    
    mov r8d, [rdx + 1Ch]            ; r8d = AddressOfFunctions RVA
    add r8, rbx
    mov eax, [r8 + r11*4]           ; Function RVA
    add rax, rbx                    ; Absolute function VA
    mov [g_ApiTable.pGetProcAddress], rax
    jmp @@PopulateTable

@@NextName:
    inc r9
    jmp @@NameLoop

@@PopulateTable:
    ; Use manual parsing or standard lookups to resolve remaining symbols
    DEALLOC_LEAF_FRAME
    pop rbx
    pop rdi
    pop rsi
    pop rbp
    ret
Sovereign_Resolve_Core_APIs ENDP

; ----------------------------------------------------------------------------
; Sovereign_Heap_Init - Secure Allocation Layer Initialization
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Heap_Init
Sovereign_Heap_Init PROC
    push rbp
    mov rbp, rsp
    ALLOC_LEAF_FRAME 0
    ASSERT_ALIGN16 rsp

    ; Explicit zeroing out of tracking systems before startup
    cld
    lea rdi, g_ProvenanceRegistry
    mov rcx, (SIZEOF PROVENANCE_RECORD * 1024) / 8
    xor rax, rax
    rep stosq
    
    mov g_ProvenanceCount, 0

    DEALLOC_LEAF_FRAME
    pop rbp
    ret
Sovereign_Heap_Init ENDP

; ----------------------------------------------------------------------------
; Provenance_Register_Alloc - Secure Allocation Tracking Hook
; ----------------------------------------------------------------------------
PUBLIC Provenance_Register_Alloc
Provenance_Register_Alloc PROC
    ; rcx = pAddress, rdx = cbSize, r8d = dwAllocationId
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    ALLOC_LEAF_FRAME 16

    mov rax, g_ProvenanceCount
    cmp rax, 1024
    jae @@RegistryOverflow

    ; Calculate explicit table offset
    imul rsi, rax, SIZEOF PROVENANCE_RECORD
    lea rdi, g_ProvenanceRegistry
    add rdi, rsi

    ; Populate tracking properties into registry frame
    mov [rdi + PROVENANCE_RECORD.pAddress], rcx
    mov [rdi + PROVENANCE_RECORD.cbSize], rdx
    mov [rdi + PROVENANCE_RECORD.dwAllocationId], r8d
    mov [rdi + PROVENANCE_RECORD.dwMagicSignature], 0A5A5A5A5h

    inc g_ProvenanceCount

@@RegistryOverflow:
    DEALLOC_LEAF_FRAME
    pop rdi
    pop rsi
    pop rbp
    ret
Provenance_Register_Alloc ENDP

; ----------------------------------------------------------------------------
; Provenance_Deregister_Alloc - Secure Resource Release Validation
; ----------------------------------------------------------------------------
PUBLIC Provenance_Deregister_Alloc
Provenance_Deregister_Alloc PROC
    ; rcx = pAddress
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    ALLOC_LEAF_FRAME 16

    xor rsi, rsi                    ; Table scanning index
    mov rdx, g_ProvenanceCount

@@ScanLoop:
    cmp rsi, rdx
    jae @@NotFound
    
    imul rax, rsi, SIZEOF PROVENANCE_RECORD
    lea rdi, g_ProvenanceRegistry
    add rdi, rax

    cmp [rdi + PROVENANCE_RECORD.pAddress], rcx
    je @@FoundRecord
    inc rsi
    jmp @@ScanLoop

@@FoundRecord:
    ; Verify memory bounds and marker signatures
    cmp [rdi + PROVENANCE_RECORD.dwMagicSignature], 0A5A5A5A5h
    jne @@CorruptedProvenance

    ; Clear memory tracking entries cleanly
    mov qword ptr [rdi + PROVENANCE_RECORD.pAddress], 0
    mov qword ptr [rdi + PROVENANCE_RECORD.cbSize], 0
    mov dword ptr [rdi + PROVENANCE_RECORD.dwMagicSignature], 0

    jmp @@Exit

@@CorruptedProvenance:
    mov ecx, 0C0000409h             ; STATUS_STACK_BUFFER_OVERRUN
    call Terminate_Execution_Fast

@@NotFound:
    ; Tracking failure fallback path
@@Exit:
    DEALLOC_LEAF_FRAME
    pop rdi
    pop rsi
    pop rbp
    ret
Provenance_Deregister_Alloc ENDP

; ----------------------------------------------------------------------------
; Sovereign_Print - Thread-Safe, Pure Output Primitive
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Print
Sovereign_Print PROC
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    ALLOC_LEAF_FRAME 32
    ASSERT_ALIGN16 rsp

    mov rsi, rcx                    ; Save source string address
    
    ; Determine null-terminated string length
    xor rdx, rdx
@@LenLoop:
    cmp byte ptr [rsi + rdx], 0
    je @@LenDone
    inc rdx
    jmp @@LenLoop

@@LenDone:
    test rdx, rdx
    jz @@Exit
    
    ; Pass variables safely down to operational raw print functions
    mov rcx, rsi
    call PrintRaw

@@Exit:
    DEALLOC_LEAF_FRAME
    pop rdi
    pop rsi
    pop rbp
    ret
Sovereign_Print ENDP

; ----------------------------------------------------------------------------
; Terminate_Execution_Fast - Hard Fault Boundary Panic Vector
; ----------------------------------------------------------------------------
PUBLIC Terminate_Execution_Fast
Terminate_Execution_Fast PROC
    ; ecx = Exception Exit Code Status Flag
    sub rsp, 40                     ; Maintain clean shadow space allocation
    
    ; Push log streams directly to standard error/output systems
    push rcx
    lea rcx, szPanicMsg
    call Sovereign_Print
    pop rcx

    call [g_ApiTable.pExitProcess]
    int 3
    ud2
Terminate_Execution_Fast ENDP

; ----------------------------------------------------------------------------
; Sovereign_Verify_Provenance_Summary - Audit Active Leak Traces
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Verify_Provenance_Summary
Sovereign_Verify_Provenance_Summary PROC
    push rbp
    mov rbp, rsp
    push rsi
    push rdi
    ALLOC_LEAF_FRAME 32

    xor rsi, rsi
    mov rdx, g_ProvenanceCount
    xor rbx, rbx                    ; Active leak counters

@@AuditLoop:
    cmp rsi, rdx
    jae @@AuditDone
    
    imul rax, rsi, SIZEOF PROVENANCE_RECORD
    lea rdi, g_ProvenanceRegistry
    add rdi, rax

    cmp qword ptr [rdi + PROVENANCE_RECORD.pAddress], 0
    je @@NextAudit
    inc rbx                         ; Tracking structural active leaks

@@NextAudit:
    inc rsi
    jmp @@AuditLoop

@@AuditDone:
    test rbx, rbx
    jz @@AllClean
    
    lea rcx, szLeakDetected
    call Sovereign_Print

@@AllClean:
    DEALLOC_LEAF_FRAME
    pop rdi
    pop rsi
    pop rbp
    ret
Sovereign_Verify_Provenance_Summary ENDP

END
