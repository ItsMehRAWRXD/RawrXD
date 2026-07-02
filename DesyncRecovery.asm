OPTION CASEMAP:NONE

EXTERN Snapshot_Serialize   : PROC
EXTERN Snapshot_Deserialize : PROC

PUBLIC DesyncRecovery_Configure
PUBLIC SaveState
PUBLIC RestoreState

MAX_RECOVERY_ENTITIES EQU 4096
MIN_VALID_PTR         EQU 10000h

.data
ALIGN 16
EntityCount          dq 0

EntityXPtr           dq 0
EntityYPtr           dq 0
EntityVXPtr          dq 0
EntityVYPtr          dq 0
EntityFlagsPtr       dq 0

.code

; RCX = entity count
; RDX = EntityX pointer
; R8  = EntityY pointer
; R9  = EntityVX pointer
; [rsp+28h] = EntityVY pointer
; [rsp+30h] = EntityFlags pointer
; Returns EAX=1 on success, 0 on invalid args
DesyncRecovery_Configure PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    test rcx, rcx
    jz cfg_fail
    cmp rcx, MAX_RECOVERY_ENTITIES
    ja cfg_fail

    test rdx, rdx
    jz cfg_fail
    cmp rdx, MIN_VALID_PTR
    jb cfg_fail
    test r8, r8
    jz cfg_fail
    cmp r8, MIN_VALID_PTR
    jb cfg_fail
    test r9, r9
    jz cfg_fail
    cmp r9, MIN_VALID_PTR
    jb cfg_fail

    mov r10, qword ptr [rsp + 50h]
    mov r11, qword ptr [rsp + 58h]
    test r10, r10
    jz cfg_fail
    cmp r10, MIN_VALID_PTR
    jb cfg_fail
    test r11, r11
    jz cfg_fail
    cmp r11, MIN_VALID_PTR
    jb cfg_fail

    mov qword ptr [EntityCount], rcx
    mov qword ptr [EntityXPtr], rdx
    mov qword ptr [EntityYPtr], r8
    mov qword ptr [EntityVXPtr], r9
    mov qword ptr [EntityVYPtr], r10
    mov qword ptr [EntityFlagsPtr], r11

    mov eax, 1
    add rsp, 28h
    ret

cfg_fail:
    xor eax, eax
    add rsp, 28h
    ret
DesyncRecovery_Configure ENDP

; Save configured world state into snapshot buffers
; Returns EAX=1 on success, 0 if not configured
SaveState PROC
    mov rdx, qword ptr [EntityCount]
    test rdx, rdx
    jz save_fail

    mov r8, qword ptr [EntityXPtr]
    test r8, r8
    jz save_fail
    cmp r8, MIN_VALID_PTR
    jb save_fail

    mov r9, qword ptr [EntityYPtr]
    test r9, r9
    jz save_fail
    cmp r9, MIN_VALID_PTR
    jb save_fail

    mov r10, qword ptr [EntityVXPtr]
    test r10, r10
    jz save_fail
    cmp r10, MIN_VALID_PTR
    jb save_fail

    mov r11, qword ptr [EntityVYPtr]
    test r11, r11
    jz save_fail
    cmp r11, MIN_VALID_PTR
    jb save_fail

    mov rax, qword ptr [EntityFlagsPtr]
    test rax, rax
    jz save_fail
    cmp rax, MIN_VALID_PTR
    jb save_fail

    sub rsp, 40h
    xor rcx, rcx
    mov qword ptr [rsp + 20h], r10
    mov qword ptr [rsp + 28h], r11
    mov qword ptr [rsp + 30h], rax
    call Snapshot_Serialize
    add rsp, 40h

    test rax, rax
    jz save_fail

    mov eax, 1
    ret

save_fail:
    xor eax, eax
    ret
SaveState ENDP

; Restore world state from snapshot buffers
; Returns EAX=1 on success, 0 if not configured
RestoreState PROC
    mov rcx, qword ptr [EntityCount]
    test rcx, rcx
    jz restore_fail

    mov rdx, qword ptr [EntityXPtr]
    test rdx, rdx
    jz restore_fail
    cmp rdx, MIN_VALID_PTR
    jb restore_fail

    mov r8, qword ptr [EntityYPtr]
    test r8, r8
    jz restore_fail
    cmp r8, MIN_VALID_PTR
    jb restore_fail

    mov r9, qword ptr [EntityVXPtr]
    test r9, r9
    jz restore_fail
    cmp r9, MIN_VALID_PTR
    jb restore_fail

    mov r10, qword ptr [EntityVYPtr]
    test r10, r10
    jz restore_fail
    cmp r10, MIN_VALID_PTR
    jb restore_fail

    mov r11, qword ptr [EntityFlagsPtr]
    test r11, r11
    jz restore_fail
    cmp r11, MIN_VALID_PTR
    jb restore_fail

    sub rsp, 40h
    xor rcx, rcx
    mov qword ptr [rsp + 20h], r10
    mov qword ptr [rsp + 28h], r11
    mov rax, qword ptr [EntityCount]
    mov qword ptr [rsp + 30h], rax
    call Snapshot_Deserialize
    add rsp, 40h

    test eax, eax
    jz restore_fail

    mov eax, 1
    ret

restore_fail:
    xor eax, eax
    ret
RestoreState ENDP

END
