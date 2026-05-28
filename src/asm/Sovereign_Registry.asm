; ==================================================================================
; SOVEREIGN REGISTRY
; File: Sovereign_Registry.asm
; Role: O(1) Tensor Lookup (Hash Map)
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

.DATA
ALIGN 64
REGISTRY_SIZE EQU 1024
g_Registry    QWORD REGISTRY_SIZE DUP(0) ; Stores pointers to TensorMetadata structs

.CODE

; ==================================================================================
; Sovereign_Registry_Insert
; RCX = Hash, RDX = MetadataPtr
; ==================================================================================
PUBLIC Sovereign_Registry_Insert
Sovereign_Registry_Insert PROC
    ENTER_FRAME

    mov rax, rcx
@@FindSlot:
    and rax, REGISTRY_SIZE - 1
    mov r8, rax
    shl r8, 3
    
    ; Linear probe collision safety
    cmp qword ptr [g_Registry + r8], 0
    je @@Insert
    inc rax
    jmp @@FindSlot

@@Insert:
    mov [g_Registry + r8], rdx

    EXIT_FRAME
Sovereign_Registry_Insert ENDP

; ==================================================================================
; Sovereign_Registry_Lookup
; RCX = Hash
; Returns RAX = MetadataPtr
; ==================================================================================
PUBLIC Sovereign_Registry_Lookup
Sovereign_Registry_Lookup PROC
    ENTER_FRAME

    mov rax, rcx
    and rax, REGISTRY_SIZE - 1
    shl rax, 3
    mov rax, [g_Registry + rax]

    EXIT_FRAME
Sovereign_Registry_Lookup ENDP

END
