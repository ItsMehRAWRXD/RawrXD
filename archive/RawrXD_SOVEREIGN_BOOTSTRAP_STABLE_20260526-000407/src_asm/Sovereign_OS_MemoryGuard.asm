; =============================================================================
; Sovereign_OS_MemoryGuard.asm
; Hardware-Accelerated Protection Boundary for Sovereign OS Log Sealing
; Purpose: Atomic transition of KV-Cache and Log pages to Read-Only/Guard state
; =============================================================================

.CODE

EXTERN XR_FaultHandler_Resolve : PROC
EXTERN XR_Append_Log_Atomic : PROC

; XR_Apply_MemoryGuard: Hardens the log segment post-commit
; Maps directly to NtProtectVirtualMemory or VirtualProtect
PUBLIC XR_Apply_MemoryGuard
XR_Apply_MemoryGuard PROC
    sub rsp, 40                 ; Shadow space
    
    ; 1. Prepare Win32/NT call parameters
    ; RCX: BaseAddress, RDX: RegionSize, R8: NewProtect
    ; R9: Pointer to receive old protection
    mov r10, rcx                ; Save Base
    
    ; 2. Invoke memory protection transition
    ; We use the pre-resolved pVirtualProtect stub established during PEB bootstrap
    mov rax, qword ptr [g_pVirtualProtect] 
    call rax                    ; Execute hardening
    
    ; 3. Verify success
    test eax, eax
    jz fault_event             ; If return is 0, protection failed
    
    add rsp, 40
    ret

fault_event:
    ; Trigger log-tampering alert or kernel-panic-restart
    mov ecx, 0C0000005h         ; Access Violation status
    call XR_FaultHandler_Resolve
    add rsp, 40
    ret
XR_Apply_MemoryGuard ENDP

; XR_Commit_And_Seal: Atomic log append + hash + lock
; RCX=KV_Base, RDX=DataPtr, R8=Size
PUBLIC XR_Commit_And_Seal
XR_Commit_And_Seal PROC
    sub rsp, 56                 ; Shadow space + register preservation
    
    ; 1. Hardware-accelerated hash commit
    call XR_Append_Log_Atomic  ; Append new entry to the chain
    
    ; 2. Transition memory to Read-Only (0x02) to seal the log
    ; Set up for VirtualProtect syscall
    mov rcx, rcx                ; Log Page Base
    mov rdx, qword ptr [g_PageSize] ; Page-aligned size
    mov r8, 02h                 ; PAGE_READONLY equivalent
    lea r9, [rsp + 48]          ; Dummy for old protection
    call XR_Apply_MemoryGuard
    
    add rsp, 56
    ret
XR_Commit_And_Seal ENDP

.DATA
PUBLIC g_pVirtualProtect
PUBLIC g_PageSize
align 8
g_pVirtualProtect dq 0
g_PageSize        dq 4096
END
