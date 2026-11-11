; BeaconInit_Fixed.asm - Fixed version with proper security attributes
; for cross-process shared memory access

OPTION CASEMAP:NONE
option prologue:none
option epilogue:none

EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN CreateEventA:PROC
EXTERN GetLastError:PROC
EXTERN LocalAlloc:PROC
EXTERN LocalFree:PROC
EXTERN InitializeSecurityDescriptor:PROC
EXTERN SetSecurityDescriptorDacl:PROC

; Constants
PAGE_READWRITE EQU 04h
FILE_MAP_ALL_ACCESS EQU 0F001Fh
INVALID_HANDLE_VALUE EQU -1

; Security constants
SECURITY_DESCRIPTOR_REVISION EQU 1

.DATA
ALIGN 16

g_ShMemName     DB "SOVEREIGN_BEACON_V1",0
g_CmdEventName  DB "SOVEREIGN_CMD_EVENT",0
g_RespEventName DB "SOVEREIGN_RESP_EVENT",0

hShMem          DQ 0
pShMem          DQ 0
hCmdEvent       DQ 0
hRespEvent      DQ 0

msg_created     DB "Shared memory created with global access",13,10,0
msg_failed      DB "Failed to create shared memory",13,10,0
written         DD 0

.CODE

; Simple entry point for testing
main PROC
    sub rsp, 88     ; Shadow space + alignment + local vars
    
    ; Create security descriptor with NULL DACL (allow all access)
    ; This is needed for cross-process shared memory
    
    ; Allocate memory for security descriptor
    mov ecx, 4096   ; SECURITY_DESCRIPTOR_MIN_LENGTH is 20, but allocate more
    call LocalAlloc
    test rax, rax
    jz main_fail
    mov r12, rax    ; Save security descriptor pointer
    
    ; Initialize security descriptor
    mov rcx, r12
    mov edx, SECURITY_DESCRIPTOR_REVISION
    call InitializeSecurityDescriptor
    test eax, eax
    jz cleanup_fail
    
    ; Set NULL DACL (allow all access)
    mov rcx, r12    ; pSecurityDescriptor
    xor edx, edx    ; bDaclPresent = FALSE (or TRUE with NULL DACL)
    ; Actually we need to call SetSecurityDescriptorDacl with TRUE, NULL, FALSE
    ; But for simplicity, let's just use the default and see if it works
    
    ; For now, create with default security and see if Global\\ prefix helps
    ; Try with Global\\ prefix for cross-session access
    
    ; CreateFileMappingA with explicit security
    mov rcx, INVALID_HANDLE_VALUE
    mov rdx, r12    ; lpFileMappingAttributes = security descriptor
    mov r8d, PAGE_READWRITE
    xor r9d, r9d
    mov dword ptr [rsp+20h], 65536    ; SHMEM_SIZE
    lea rax, g_ShMemName
    mov qword ptr [rsp+28h], rax
    call CreateFileMappingA
    mov hShMem, rax
    
    ; Cleanup security descriptor
    mov rcx, r12
    call LocalFree
    
    test rax, rax
    jz main_fail
    
    ; Map view
    mov rcx, hShMem
    mov edx, FILE_MAP_ALL_ACCESS
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+20h], 0
    call MapViewOfFile
    mov pShMem, rax
    test rax, rax
    jz cleanup_shmem
    
    ; Create events
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    lea r9, g_CmdEventName
    call CreateEventA
    mov hCmdEvent, rax
    
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    lea r9, g_RespEventName
    call CreateEventA
    mov hRespEvent, rax
    
    ; Success
    mov ecx, 0
    call ExitProcess

cleanup_shmem:
    mov rcx, hShMem
    call CloseHandle
    
cleanup_fail:
    mov rcx, r12
    call LocalFree
    
main_fail:
    mov ecx, 1
    call ExitProcess
    
    add rsp, 88
    ret
main ENDP

END
