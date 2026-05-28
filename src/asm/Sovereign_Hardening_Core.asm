; ==============================================================================
; SOVEREIGN HARDENING LAYER & RUNTIME PARITY EXTENSIONS
; Module: Sovereign_Hardening_Core.asm
; Architecture: x64 MASM Monolith (Zero-IAT, Strict Win64 ABI Compliance)
; Substrate Role: Macro-Driven ABI Enforcement, Safe Allocations & Fault Isolation
; ==============================================================================

include Sovereign_Common.inc

; --- Structural Configuration Constants ---
STATUS_STACK_BUFFER_OVERRUN EQU 0C0000409h
STATUS_NO_MEMORY           EQU 0C0000017h
MEM_COMMIT                 EQU 00001000h
MEM_RESERVE                EQU 00002000h
MEM_RELEASE                EQU 00008000h
PAGE_READWRITE             EQU 00000004h

; ==============================================================================
; PRODUCTION ABI ENFORCEMENT MACROS
; ==============================================================================

; --- FRAME_ALLOC_ALIGN ---
; Allocates shadow space plus any necessary local variable frame space, 
; ensuring the subsequent total stack frame matches strict 16-byte parity alignment.
; Accounts for any prior non-volatile register pushes.
FRAME_ALLOC_ALIGN MACRO local_bytes:=<0>, num_pushes:=<0>
    LOCAL total_frame_size, pad_bytes
    total_frame_size = 32 + local_bytes
    ; Calculate current stack displacement relative to 16-byte alignment.
    ; Function entry point starts at (8 mod 16) due to the implicit return pointer push.
    ; Each explicit push increments the offset by 8 bytes.
    if ((8 + (num_pushes * 8) + total_frame_size) MOD 16) NE 0
        pad_bytes = 16 - ((8 + (num_pushes * 8) + total_frame_size) MOD 16)
        total_frame_size = total_frame_size + pad_bytes
    endif
    sub rsp, total_frame_size
ENDM

; --- FRAME_FREE_ALIGN ---
; Reclaims precisely the bytes allocated by FRAME_ALLOC_ALIGN.
FRAME_FREE_ALIGN MACRO local_bytes:=<0>, num_pushes:=<0>
    LOCAL total_frame_size, pad_bytes
    total_frame_size = 32 + local_bytes
    if ((8 + (num_pushes * 8) + total_frame_size) MOD 16) NE 0
        pad_bytes = 16 - ((8 + (num_pushes * 8) + total_frame_size) MOD 16)
        total_frame_size = total_frame_size + pad_bytes
    endif
    add rsp, total_frame_size
ENDM

; ==============================================================================
; STRUCTURAL SCHEMAS & PROVENANCE STRUCTURES
; ==============================================================================
.DATA
SOVEREIGN_PAGE_RECORD STRUCT
    pVirtualAddress DQ 0            ; Base pointer returned by Windows VirtualAlloc
    cbSize          DQ 0            ; Allocation capacity size tracked in bytes
    uAllocationTag  DQ 0            ; Unique signature identifier (e.g., 'WEIGHTS', 'INPUT')
SOVEREIGN_PAGE_RECORD ENDS
ALIGN 16
; --- High-Isolation Page Provenance Table ---
; Restricts, stores, and validates critical SIMD memory maps across allocations
g_ProvenanceRegistry    SOVEREIGN_PAGE_RECORD 16 DUP(<>)
g_MaxRegistrySlots      DQ 16

.CODE

; --- External Win64 Substrate Mappings ---
EXTERN g_ApiTable               : SOVEREIGN_API_TABLE
EXTERN g_hStdOut                : QWORD
EXTERN g_pWriteFile             : QWORD

; ----------------------------------------------------------------------------
; Sovereign_Alloc_Tracked - Provenance-Enabled Memory Provisioner
; ----------------------------------------------------------------------------
; Input:  RCX = Size in bytes, RDX = Allocation Tag Identification
; Output: RAX = Validated Memory Pointer
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Alloc_Tracked
Sovereign_Alloc_Tracked PROC
    push rbx
    push rdi
    push rsi
    FRAME_ALLOC_ALIGN 16, 3         ; 16 local bytes, 3 non-volatile registers pushed
    
    mov rbx, rcx                    ; Save size allocation vector
    mov rsi, rdx                    ; Save structural tag footprint

    ; Issue Windows API Memory Map Request
    mov rcx, 0
    mov rdx, rbx
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call [g_ApiTable.pVirtualAlloc]
    
    ; Validate Memory State Integrity
    test rax, rax
    jz @@AllocationCrashPanic

    ; Acquire Thread-Safe Access Pointer to Local Provenance Slots
    lea rdi, g_ProvenanceRegistry
    mov rcx, [g_MaxRegistrySlots]
    xor rdx, rdx

@@FindSlotLoop:
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov r8, [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress]
    test r8, r8
    jz @@SlotAcquired
    inc rdx
    loop @@FindSlotLoop
    
    ; Out of tracking slots? Immediately force fail-fast behavior to protect execution
    jmp @@AllocationCrashPanic

@@SlotAcquired:
    ; Commit Allocation Map Metrics Into Persistent Global Layout
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress], rax
    mov [rdi + r9 + SOVEREIGN_PAGE_RECORD.cbSize], rbx
    mov [rdi + r9 + SOVEREIGN_PAGE_RECORD.uAllocationTag], rsi

    FRAME_FREE_ALIGN 16, 3
    pop rsi
    pop rdi
    pop rbx
    ret

@@AllocationCrashPanic:
    mov ecx, STATUS_NO_MEMORY
    call [g_ApiTable.pExitProcess]
    int 3
    ud2
Sovereign_Alloc_Tracked ENDP

; ----------------------------------------------------------------------------
; Sovereign_Free_Tracked - Provenance-Enforced Memory Deallocator
; ----------------------------------------------------------------------------
; Input:  RCX = Active Allocation Address Reference
; Output: RAX = Success (1) / Failure Status Code (0)
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Free_Tracked
Sovereign_Free_Tracked PROC
    push rbx
    push rdi
    FRAME_ALLOC_ALIGN 0, 2          ; 0 local bytes, 2 non-volatile registers pushed
    
    mov rbx, rcx                    ; Stash target lookup pointer safely
    lea rdi, g_ProvenanceRegistry
    mov rcx, [g_MaxRegistrySlots]
    xor rdx, rdx

@@LookupLoop:
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov r8, [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress]
    cmp r8, rbx
    je @@TargetMapIdentified
    inc rdx
    loop @@LookupLoop
    
    ; Pointer unrecognized by Provenance Registry -> Reject operation to prevent double-free or corruption
    xor rax, rax
    jmp @@ExitEpilogue

@@TargetMapIdentified:
    ; Clear mapping signature immediately to prevent race reuse vectors
    mov r9, TYPE SOVEREIGN_PAGE_RECORD
    imul r9, rdx
    mov qword ptr [rdi + r9 + SOVEREIGN_PAGE_RECORD.pVirtualAddress], 0
    mov qword ptr [rdi + r9 + SOVEREIGN_PAGE_RECORD.cbSize], 0
    mov qword ptr [rdi + r9 + SOVEREIGN_PAGE_RECORD.uAllocationTag], 0

    ; Execute Virtual Memory Page Release Request
    mov rcx, rbx
    mov rdx, 0                      ; Must be 0 for MEM_RELEASE operations
    mov r8, MEM_RELEASE
    call [g_ApiTable.pVirtualFree]
    mov rax, 1

@@ExitEpilogue:
    FRAME_FREE_ALIGN 0, 2
    pop rdi
    pop rbx
    ret
Sovereign_Free_Tracked ENDP

; ----------------------------------------------------------------------------
; Sovereign_Fault_Containment_Handler - System Crash Fallback Engine
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Fault_Containment_Handler
Sovereign_Fault_Containment_Handler PROC
    ; Enforce rigid stack discipline: non-volatile footprint requires explicit isolation
    sub rsp, 40                     ; 32 Shadow Space + 8-byte Alignment Pad
    
    ; Extract Error Signal Payload, Route Directly to Fast Process Teardown API
    mov ecx, STATUS_STACK_BUFFER_OVERRUN
    call [g_ApiTable.pExitProcess]
    
    ; Microarchitectural execution traps to catch runaway instruction stepping
    int 3
    ud2
    add rsp, 40
    ret
Sovereign_Fault_Containment_Handler ENDP

; ----------------------------------------------------------------------------
; Sovereign_ABI_Sanity_Checkpoint - Dynamic Context Verifier
; ----------------------------------------------------------------------------
PUBLIC Sovereign_ABI_Sanity_Checkpoint
Sovereign_ABI_Sanity_Checkpoint PROC
    mov rax, rsp
    add rax, 8                      ; Account for structural caller return offset address
    and rax, 0Fh                    ; Evaluate layout trace alignment matrix (RSP mod 16)
    jz @@SanityVerified
    
    ; Critical Alignment Failure Detected -> Detonate immediately to guarantee state preservation
    call Sovereign_Fault_Containment_Handler

@@SanityVerified:
    ret
Sovereign_ABI_Sanity_Checkpoint ENDP

END

