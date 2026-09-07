; Deep2OuterEvidence.asm — GATE_STATUS.txt, ignore mkdir races
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN CreateDirectoryA:PROC
EXTERN CreateFileA:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
PUBLIC Deep2Outer_WriteEvidence

.data
ev_dir1 db "G:\~dev\rawrxd\evidence",0
ev_dir2 db "G:\~dev\rawrxd\evidence\DEEP2_OUTER_RUNTIME_001",0
ev_file db "G:\~dev\rawrxd\evidence\DEEP2_OUTER_RUNTIME_001\GATE_STATUS.txt",0
ev_note db "GENERATION_CLAIMED=0",13,10,0

.code
Deep2Outer_WriteEvidence PROC PUBLIC
    push rbx
    push rsi
    sub rsp, 48h
    mov rsi, rcx
    lea rcx, ev_dir1
    xor edx, edx
    call CreateDirectoryA
    lea rcx, ev_dir2
    xor edx, edx
    call CreateDirectoryA
    lea rcx, ev_file
    mov edx, GENERIC_WRITE
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+20h], CREATE_ALWAYS
    mov qword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0
    call CreateFileA
    cmp rax, INVALID_HANDLE_VALUE
    je EV_Fail
    mov rbx, rax
    lea rdx, ev_note
    mov rcx, rbx
    mov r8d, 22
    lea r9, [rsp+40h]
    mov qword ptr [rsp+20h], 0
    call WriteFile
    mov rcx, rbx
    call CloseHandle
    mov eax, 1
    jmp EV_Done
EV_Fail:
    xor eax, eax
EV_Done:
    add rsp, 48h
    pop rsi
    pop rbx
    ret
Deep2Outer_WriteEvidence ENDP
END
