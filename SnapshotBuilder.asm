OPTION CASEMAP:NONE

PUBLIC Snapshot_Serialize
PUBLIC Snapshot_Deserialize
PUBLIC Snapshot_GetBuffer
PUBLIC Snapshot_GetSize

MAX_SNAPSHOT_ENTITIES EQU 4096
SNAPSHOT_VERSION      EQU 0100h
SNAPSHOT_FLAGS_QWORD  EQU 1
SNAPSHOT_HEADER_BYTES EQU 16
SNAPSHOT_RECORD_BYTES EQU 40
SNAPSHOT_MAX_BYTES    EQU (SNAPSHOT_HEADER_BYTES + (MAX_SNAPSHOT_ENTITIES * SNAPSHOT_RECORD_BYTES))
MIN_VALID_PTR         EQU 10000h

.data
ALIGN 16
SnapshotBuffer        db SNAPSHOT_MAX_BYTES dup(0)
SnapshotSize          dq 0

.code

; RCX = destination buffer (0 => internal SnapshotBuffer)
; RDX = entity count
; R8  = EntityX pointer (qword lanes)
; R9  = EntityY pointer (qword lanes)
; [rsp+28h] = EntityVX pointer
; [rsp+30h] = EntityVY pointer
; [rsp+38h] = EntityFlags pointer
; Returns RAX = bytes written (0 on failure)
Snapshot_Serialize PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    test rdx, rdx
    jz ss_fail
    cmp rdx, MAX_SNAPSHOT_ENTITIES
    ja ss_fail

    test r8, r8
    jz ss_fail
    cmp r8, MIN_VALID_PTR
    jb ss_fail
    test r9, r9
    jz ss_fail
    cmp r9, MIN_VALID_PTR
    jb ss_fail

    mov r12, qword ptr [rsp + 60h]
    mov r13, qword ptr [rsp + 68h]
    mov r14, qword ptr [rsp + 70h]

    test r12, r12
    jz ss_fail
    cmp r12, MIN_VALID_PTR
    jb ss_fail
    test r13, r13
    jz ss_fail
    cmp r13, MIN_VALID_PTR
    jb ss_fail
    test r14, r14
    jz ss_fail
    cmp r14, MIN_VALID_PTR
    jb ss_fail

    test rcx, rcx
    jnz ss_have_dest
    lea rcx, SnapshotBuffer

ss_have_dest:
    mov r15, rcx

    mov word ptr [rcx + 0], SNAPSHOT_VERSION
    mov word ptr [rcx + 2], 0
    mov dword ptr [rcx + 4], SNAPSHOT_FLAGS_QWORD
    mov qword ptr [rcx + 8], rdx

    lea rdi, [rcx + SNAPSHOT_HEADER_BYTES]
    xor rbx, rbx

ss_loop:
    cmp rbx, rdx
    jae ss_done

    mov rax, qword ptr [r8 + rbx*8]
    mov qword ptr [rdi + 0], rax

    mov rax, qword ptr [r9 + rbx*8]
    mov qword ptr [rdi + 8], rax

    mov rax, qword ptr [r12 + rbx*8]
    mov qword ptr [rdi + 16], rax

    mov rax, qword ptr [r13 + rbx*8]
    mov qword ptr [rdi + 24], rax

    mov rax, qword ptr [r14 + rbx*8]
    mov qword ptr [rdi + 32], rax

    add rdi, SNAPSHOT_RECORD_BYTES
    inc rbx
    jmp ss_loop

ss_done:
    mov rax, rdi
    sub rax, r15
    mov qword ptr [SnapshotSize], rax
    jmp ss_exit

ss_fail:
    xor eax, eax

ss_exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Snapshot_Serialize ENDP

; RCX = source buffer (0 => internal SnapshotBuffer)
; RDX = EntityX pointer (qword lanes)
; R8  = EntityY pointer (qword lanes)
; R9  = EntityVX pointer (qword lanes)
; [rsp+28h] = EntityVY pointer
; [rsp+30h] = EntityFlags pointer
; [rsp+38h] = max entity capacity
; Returns EAX = 1 success, 0 failure
Snapshot_Deserialize PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    test rcx, rcx
    jnz sd_have_src
    lea rcx, SnapshotBuffer

sd_have_src:
    cmp rcx, MIN_VALID_PTR
    jb sd_fail

    test rdx, rdx
    jz sd_fail
    cmp rdx, MIN_VALID_PTR
    jb sd_fail
    test r8, r8
    jz sd_fail
    cmp r8, MIN_VALID_PTR
    jb sd_fail
    test r9, r9
    jz sd_fail
    cmp r9, MIN_VALID_PTR
    jb sd_fail

    mov r12, qword ptr [rsp + 60h]
    mov r13, qword ptr [rsp + 68h]
    mov r14, qword ptr [rsp + 70h]

    test r12, r12
    jz sd_fail
    cmp r12, MIN_VALID_PTR
    jb sd_fail
    test r13, r13
    jz sd_fail
    cmp r13, MIN_VALID_PTR
    jb sd_fail
    test r14, r14
    jz sd_fail

    movzx eax, word ptr [rcx + 0]
    cmp eax, SNAPSHOT_VERSION
    jne sd_fail

    mov r15, qword ptr [rcx + 8]
    test r15, r15
    jz sd_fail
    cmp r15, r14
    ja sd_fail

    lea rsi, [rcx + SNAPSHOT_HEADER_BYTES]
    xor rbx, rbx

sd_loop:
    cmp rbx, r15
    jae sd_done

    mov rax, qword ptr [rsi + 0]
    mov qword ptr [rdx + rbx*8], rax

    mov rax, qword ptr [rsi + 8]
    mov qword ptr [r8 + rbx*8], rax

    mov rax, qword ptr [rsi + 16]
    mov qword ptr [r9 + rbx*8], rax

    mov rax, qword ptr [rsi + 24]
    mov qword ptr [r12 + rbx*8], rax

    mov rax, qword ptr [rsi + 32]
    mov qword ptr [r13 + rbx*8], rax

    add rsi, SNAPSHOT_RECORD_BYTES
    inc rbx
    jmp sd_loop

sd_done:
    mov eax, 1
    jmp sd_exit

sd_fail:
    xor eax, eax

sd_exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Snapshot_Deserialize ENDP

Snapshot_GetBuffer PROC
    lea rax, SnapshotBuffer
    ret
Snapshot_GetBuffer ENDP

Snapshot_GetSize PROC
    mov rax, qword ptr [SnapshotSize]
    ret
Snapshot_GetSize ENDP

END
