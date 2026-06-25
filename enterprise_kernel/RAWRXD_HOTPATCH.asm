;=============================================================================
; RAWRXD HOTPATCHER v10.0
; Pure MASM x64 - Live Binary Mutation with Safe Rollback
;=============================================================================
; Features:
;   - In-memory code modification
;   - Instruction patching (byte-level)
;   - Function detour switching
;   - Rollback-safe patch commits
;   - Verification before activation
;=============================================================================

OPTION WIN64:6
OPTION CASEMAP:NONE

;=============================================================================
; EXTERNAL IMPORTS
;=============================================================================
EXTERN VirtualProtect:PROC
EXTERN WriteProcessMemory:PROC
EXTERN FlushInstructionCache:PROC
EXTERN GetCurrentProcess:PROC
EXTERN GetLastError:PROC
EXTERN Sleep:PROC
EXTERN Smoke_Run:PROC
EXTERN CI_Evaluate:PROC

;=============================================================================
; DATA SECTION
;=============================================================================
.data

;-----------------------------------------------------------------------------
; Patch Types
;-----------------------------------------------------------------------------
PATCH_NOP           equ 1
PATCH_JUMP          equ 2
PATCH_RETURN        equ 3
PATCH_CALL          equ 4

;-----------------------------------------------------------------------------
; Patch Descriptor Structure
;-----------------------------------------------------------------------------
PatchDescriptor STRUCT
    targetAddress   dq ?
    patchBytes      dq ?
    patchSize       dq ?
    patchType       dd ?
    backupBytes     db 16 dup(?)
    backupSize      dq ?
    oldProtect      dd ?
PatchDescriptor ENDS

;-----------------------------------------------------------------------------
; Patch Registry (max 64 patches)
;-----------------------------------------------------------------------------
MAX_PATCHES         equ 64
patchRegistry       PatchDescriptor MAX_PATCHES dup(<>)
patchCount          dq 0
activePatchCount    dq 0

;-----------------------------------------------------------------------------
; Patch Status
;-----------------------------------------------------------------------------
PATCH_STATUS_IDLE   equ 0
PATCH_STATUS_APPLIED equ 1
PATCH_STATUS_ROLLEDBACK equ 2
PATCH_STATUS_FAILED equ 3

;-----------------------------------------------------------------------------
; Instruction Bytes
;-----------------------------------------------------------------------------
NOP_OPCODE          db 0x90
RET_OPCODE          db 0xC3
JMP_REL_OPCODE      db 0xE9
CALL_REL_OPCODE     db 0xE8

;-----------------------------------------------------------------------------
; Patch Event Log
;-----------------------------------------------------------------------------
PATCH_EVENT_APPLY   db "HOTPATCH_APPLY",0
PATCH_EVENT_ROLLBACK db "HOTPATCH_ROLLBACK",0
PATCH_EVENT_VERIFY  db "HOTPATCH_VERIFY",0

;=============================================================================
; CODE SECTION
;=============================================================================
.code

;=============================================================================
; Hotpatch_Init - Initialize hotpatch system
;=============================================================================
Hotpatch_Init PROC
    push rbx
    
    ; Clear patch registry
    mov patchCount, 0
    mov activePatchCount, 0
    
    xor eax, eax
    mov ecx, MAX_PATCHES * SIZEOF PatchDescriptor
    lea rdi, patchRegistry
    rep stosb
    
    pop rbx
    ret
Hotpatch_Init ENDP

;=============================================================================
; Hotpatch_Register - Register a patch for later application
;=============================================================================
Hotpatch_Register PROC
    ; RCX = target address
    ; RDX = patch bytes pointer
    ; R8  = patch size
    ; R9D = patch type
    
    push rbx
    push rsi
    push rdi
    
    ; Check if registry is full
    mov rax, patchCount
    cmp rax, MAX_PATCHES
    jae registerFail
    
    ; Get next descriptor slot
    mov rbx, rax
    imul rbx, SIZEOF PatchDescriptor
    lea rdi, patchRegistry
    add rdi, rbx
    
    ; Fill descriptor
    mov [rdi].PatchDescriptor.targetAddress, rcx
    mov [rdi].PatchDescriptor.patchBytes, rdx
    mov [rdi].PatchDescriptor.patchSize, r8
    mov [rdi].PatchDescriptor.patchType, r9d
    mov [rdi].PatchDescriptor.backupSize, r8
    
    ; Backup original bytes
    mov rsi, rcx            ; source = target address
    lea rdx, [rdi].PatchDescriptor.backupBytes
    mov rcx, r8             ; size
    
    ; Copy backup
    push rdi
    mov rdi, rdx
    rep movsb
    pop rdi
    
    ; Increment patch count
    inc patchCount
    
    mov eax, 1
    jmp registerDone
    
registerFail:
    xor eax, eax
    
registerDone:
    pop rdi
    pop rsi
    pop rbx
    ret
Hotpatch_Register ENDP

;=============================================================================
; Hotpatch_Backup - Backup original bytes before patching
;=============================================================================
Hotpatch_Backup PROC
    ; RCX = target address
    ; RDX = backup buffer
    ; R8  = size
    
    push rsi
    push rdi
    
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    
    rep movsb
    
    pop rdi
    pop rsi
    ret
Hotpatch_Backup ENDP

;=============================================================================
; Hotpatch_Apply - Apply a registered patch
;=============================================================================
Hotpatch_Apply PROC
    ; RCX = patch index
    
    push rbx
    push rsi
    push rdi
    push r12
    
    mov r12, rcx            ; Save patch index
    
    ; Get descriptor
    imul rcx, SIZEOF PatchDescriptor
    lea rbx, patchRegistry
    add rbx, rcx
    
    ; Check if already applied
    cmp dword ptr [rbx].PatchDescriptor.patchType, PATCH_STATUS_APPLIED
    je applyFail
    
    ; Step 1: Change memory protection
    mov rcx, [rbx].PatchDescriptor.targetAddress
    mov rdx, [rbx].PatchDescriptor.patchSize
    mov r8d, 40h            ; PAGE_EXECUTE_READWRITE
    lea r9, [rbx].PatchDescriptor.oldProtect
    
    sub rsp, 28h
    call VirtualProtect
    add rsp, 28h
    
    test eax, eax
    jz applyFail
    
    ; Step 2: Write patch bytes
    call GetCurrentProcess
    mov rcx, rax
    mov rdx, [rbx].PatchDescriptor.targetAddress
    mov r8, [rbx].PatchDescriptor.patchBytes
    mov r9, [rbx].PatchDescriptor.patchSize
    mov qword ptr [rsp+28h], 0
    
    sub rsp, 30h
    call WriteProcessMemory
    add rsp, 30h
    
    test eax, eax
    jz applyFail
    
    ; Step 3: Flush instruction cache
    call GetCurrentProcess
    mov rcx, rax
    mov rdx, [rbx].PatchDescriptor.targetAddress
    mov r8, [rbx].PatchDescriptor.patchSize
    
    sub rsp, 20h
    call FlushInstructionCache
    add rsp, 20h
    
    ; Mark as applied
    mov dword ptr [rbx].PatchDescriptor.patchType, PATCH_STATUS_APPLIED
    inc activePatchCount
    
    mov eax, 1
    jmp applyDone
    
applyFail:
    xor eax, eax
    
applyDone:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Hotpatch_Apply ENDP

;=============================================================================
; Hotpatch_Rollback - Restore original bytes
;=============================================================================
Hotpatch_Rollback PROC
    ; RCX = patch index
    
    push rbx
    push rsi
    push rdi
    push r12
    
    mov r12, rcx
    
    ; Get descriptor
    imul rcx, SIZEOF PatchDescriptor
    lea rbx, patchRegistry
    add rbx, rcx
    
    ; Check if applied
    cmp dword ptr [rbx].PatchDescriptor.patchType, PATCH_STATUS_APPLIED
    jne rollbackFail
    
    ; Restore original protection
    mov rcx, [rbx].PatchDescriptor.targetAddress
    mov rdx, [rbx].PatchDescriptor.patchSize
    mov r8d, [rbx].PatchDescriptor.oldProtect
    lea r9, [rsp+28h]
    
    sub rsp, 30h
    call VirtualProtect
    add rsp, 30h
    
    ; Restore original bytes
    call GetCurrentProcess
    mov rcx, rax
    mov rdx, [rbx].PatchDescriptor.targetAddress
    lea r8, [rbx].PatchDescriptor.backupBytes
    mov r9, [rbx].PatchDescriptor.backupSize
    mov qword ptr [rsp+28h], 0
    
    sub rsp, 30h
    call WriteProcessMemory
    add rsp, 30h
    
    ; Flush cache
    call GetCurrentProcess
    mov rcx, rax
    mov rdx, [rbx].PatchDescriptor.targetAddress
    mov r8, [rbx].PatchDescriptor.backupSize
    
    sub rsp, 20h
    call FlushInstructionCache
    add rsp, 20h
    
    ; Mark as rolled back
    mov dword ptr [rbx].PatchDescriptor.patchType, PATCH_STATUS_ROLLEDBACK
    dec activePatchCount
    
    mov eax, 1
    jmp rollbackDone
    
rollbackFail:
    xor eax, eax
    
rollbackDone:
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Hotpatch_Rollback ENDP

;=============================================================================
; Hotpatch_Validate - Verify patch with smoke test
;=============================================================================
Hotpatch_Validate PROC
    push rbx
    
    ; Run smoke test
    call Smoke_Run
    test eax, eax
    jz validateFail
    
    ; Run CI evaluation
    call CI_Evaluate
    test eax, eax
    jz validateFail
    
    mov eax, 1
    jmp validateDone
    
validateFail:
    xor eax, eax
    
validateDone:
    pop rbx
    ret
Hotpatch_Validate ENDP

;=============================================================================
; Hotpatch_ApplyWithValidation - Full patch pipeline
;=============================================================================
Hotpatch_ApplyWithValidation PROC
    ; RCX = patch index
    
    push rbx
    mov rbx, rcx
    
    ; Apply patch
    mov rcx, rbx
    call Hotpatch_Apply
    test eax, eax
    jz applyValidateFail
    
    ; Validate
    call Hotpatch_Validate
    test eax, eax
    jnz applyValidateSuccess
    
    ; Validation failed, rollback
    mov rcx, rbx
    call Hotpatch_Rollback
    xor eax, eax
    jmp applyValidateDone
    
applyValidateSuccess:
    mov eax, 1
    jmp applyValidateDone
    
applyValidateFail:
    xor eax, eax
    
applyValidateDone:
    pop rbx
    ret
Hotpatch_ApplyWithValidation ENDP

;=============================================================================
; Hotpatch_CreateNOPPatch - Create NOP patch
;=============================================================================
Hotpatch_CreateNOPPatch PROC
    ; RCX = target address
    ; RDX = size
    
    push rbx
    push rsi
    push rdi
    
    ; Allocate patch buffer
    sub rsp, 32
    mov rdi, rsp
    
    ; Fill with NOPs
    mov rcx, rdx
    mov al, 0x90
    rep stosb
    
    ; Register patch
    mov rcx, rcx            ; target
    mov rdx, rsp            ; patch bytes
    mov r8, rdx             ; size
    mov r9d, PATCH_NOP      ; type
    call Hotpatch_Register
    
    add rsp, 32
    
    pop rdi
    pop rsi
    pop rbx
    ret
Hotpatch_CreateNOPPatch ENDP

;=============================================================================
; Hotpatch_CreateJumpPatch - Create JMP redirect patch
;=============================================================================
Hotpatch_CreateJumpPatch PROC
    ; RCX = target address
    ; RDX = destination address
    
    push rbx
    push rsi
    push rdi
    
    ; Calculate relative offset
    mov r8, rdx
    sub r8, rcx
    sub r8, 5             ; JMP instruction is 5 bytes
    
    ; Create patch buffer
    sub rsp, 8
    mov byte ptr [rsp], 0xE9    ; JMP opcode
    mov dword ptr [rsp+1], r8d  ; relative offset
    
    ; Register patch
    mov r8, 5             ; size
    mov r9d, PATCH_JUMP   ; type
    call Hotpatch_Register
    
    add rsp, 8
    
    pop rdi
    pop rsi
    pop rbx
    ret
Hotpatch_CreateJumpPatch ENDP

;=============================================================================
; Hotpatch_GetStatus - Get patch status
;=============================================================================
Hotpatch_GetStatus PROC
    ; RCX = patch index
    ; Returns status in EAX
    
    imul rcx, SIZEOF PatchDescriptor
    lea rax, patchRegistry
    add rax, rcx
    mov eax, [rax].PatchDescriptor.patchType
    ret
Hotpatch_GetStatus ENDP

;=============================================================================
; Hotpatch_GetActiveCount - Get number of active patches
;=============================================================================
Hotpatch_GetActiveCount PROC
    mov rax, activePatchCount
    ret
Hotpatch_GetActiveCount ENDP

;=============================================================================
; END OF FILE
;=============================================================================
END
