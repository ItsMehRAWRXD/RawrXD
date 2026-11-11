; spe.asm - Sovereign Process Enforcer (x64)
; ABI: QWORD SpawnRestricted(QWORD manifestPtr)
;   manifestPtr -> RestrictedManifest:
;     QWORD PathPtr
;     QWORD CapsMask
; Returns:
;   0 = Spawn succeeded (process handle in RAX)
;   1 = Invalid manifest
;   2 = Spawn rejected by capability policy

option casemap:none

.data
align 8
; Capability constants (must match capabilities.ts)
CAP_READ_WORKSPACE    equ 0000000000000001h
CAP_WRITE_WORKSPACE   equ 0000000000000002h
CAP_EXECUTE_INTERNAL  equ 0000000000000004h
CAP_NETWORK_PROXY     equ 0000000000000008h
CAP_TELEMETRY_EMIT    equ 0000000000000010h

.code

SpawnRestricted proc
    ; RCX = manifest pointer
    test rcx, rcx
    jz invalid_manifest

    mov r8, rcx                         ; r8 -> manifest base

    ; Load PathPtr (offset 0)
    mov r9, [r8]                        ; r9 = PathPtr
    test r9, r9
    jz invalid_manifest

    ; Load CapsMask (offset 8)
    mov r10, [r8+8]                     ; r10 = CapsMask

    ; Validate CapsMask: reject if ADMIN_ACCESS bits set
    ; (upper 32 bits must be zero for valid extension masks)
    shr r10, 32
    test r10, r10
    jnz spawn_rejected

    ; For MVP: return success (0) without actual CreateProcess
    ; In production, this path calls CreateRestrictedToken,
    ; CreateJobObject, CreateProcessW, AssignProcessToJobObject,
    ; ResumeThread, and returns the process handle.
    xor rax, rax
    ret

invalid_manifest:
    mov rax, 1
    ret

spawn_rejected:
    mov rax, 2
    ret

SpawnRestricted endp
end
