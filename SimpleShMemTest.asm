; SimpleShMemTest.asm - Test shared memory access

OPTION CASEMAP:NONE
option prologue:none
option epilogue:none

EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN OpenFileMappingA:PROC
EXTERN GetLastError:PROC
EXTERN FormatMessageA:PROC
EXTERN LocalFree:PROC

STD_OUTPUT_HANDLE EQU -11
FILE_MAP_ALL_ACCESS EQU 0F001Fh

.DATA
ALIGN 16

msg_trying      DB "Trying to open SOVEREIGN_BEACON_V1...",13,10,0
msg_success     DB "SUCCESS! Shared memory opened.",13,10,0
msg_failed      DB "FAILED! Error code: ",0
msg_newline     DB 13,10,0
shmem_name      DB "SOVEREIGN_BEACON_V1",0

error_buffer    DB 256 DUP(0)
written         DD 0
hShMem          DQ 0

.CODE

PrintString PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 40
    
    mov rsi, rcx
    mov rdi, rcx
    mov rcx, -1
    xor eax, eax
    repne scasb
    not rcx
    dec rcx
    jz print_done
    
    mov r12, rcx
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    
    mov rcx, rax
    mov rdx, rsi
    mov r8, r12
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    
print_done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
PrintString ENDP

main PROC
    sub rsp, 56
    
    ; Print trying message
    lea rcx, msg_trying
    call PrintString
    
    ; Try to open shared memory
    mov ecx, FILE_MAP_ALL_ACCESS
    xor edx, edx
    lea r8, shmem_name
    call OpenFileMappingA
    mov hShMem, rax
    
    test rax, rax
    jnz success
    
    ; Failed - print error code
    lea rcx, msg_failed
    call PrintString
    
    call GetLastError
    ; Convert to string and print (simplified - just show we got here)
    
    lea rcx, msg_newline
    call PrintString
    
    mov ecx, 1
    call ExitProcess
    
success:
    lea rcx, msg_success
    call PrintString
    
    ; Cleanup
    mov rcx, hShMem
    mov qword ptr [hShMem], 0
    
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 56
    ret
main ENDP

END
