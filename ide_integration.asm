; ============================================================================
; ide_integration.asm — IDE GPU Integration
; ============================================================================
; Integrates Vulkan backend into both CLI and GUI IDE versions
; ============================================================================

EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF CreateProcessA:PROC
EXTERNDEF WaitForSingleObject:PROC
EXTERNDEF GetExitCodeProcess:PROC
EXTERNDEF CloseHandle:PROC

.const
STD_OUTPUT_HANDLE equ -11
INFINITE equ 0FFFFFFFFh

.data
align 8
hStdOut dq 0
bytesWritten dq 0
processInfo dq 0, 0, 0, 0, 0, 0, 0
startupInfo db 104 dup(0)
exitCode dd 0

msgHeader db "RawrXD IDE - GPU Backend Integration", 13, 10
msgHeaderLen equ $ - msgHeader

msgInit db "  Initializing IDE...", 13, 10
msgInitLen equ $ - msgInit

msgLoading db "  Loading Vulkan backend...", 13, 10
msgLoadingLen equ $ - msgLoading

msgRunning db "  Executing GPU backend...", 13, 10
msgRunningLen equ $ - msgRunning

msgSuccess db 13, 10, "IDE GPU Integration: SUCCESS", 13, 10
msgSuccessLen equ $ - msgSuccess

msgFail db 13, 10, "IDE GPU Integration: FAILED", 13, 10
msgFailLen equ $ - msgFail

msgCreateFail db "  CreateProcess failed", 13, 10
msgCreateFailLen equ $ - msgCreateFail

gpuBackendPath db "vulkan_backend.exe", 0

crlf db 13, 10
crlfLen equ $ - crlf

.code

Print PROC
    push rbp
    mov rbp, rsp
    sub rsp, 40
    mov r8, rdx
    mov rdx, rcx
    mov rcx, hStdOut
    lea r9, bytesWritten
    mov qword ptr [rsp+32], 0
    call WriteFile
    add rsp, 40
    pop rbp
    ret
Print ENDP

PrintNum PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rax, rcx
    lea rdi, [rsp+48]
    mov byte ptr [rdi], 0
    mov rbx, 10
nextDigit:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz nextDigit
    lea rax, [rsp+48]
    sub rax, rdi
    mov rcx, rdi
    mov rdx, rax
    call Print
    add rsp, 64
    pop rbp
    ret
PrintNum ENDP

main PROC
    push rbp
    mov rbp, rsp
    sub rsp, 256
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    lea rcx, msgHeader
    mov rdx, msgHeaderLen
    call Print
    
    lea rcx, msgInit
    mov rdx, msgInitLen
    call Print
    
    lea rcx, msgLoading
    mov rdx, msgLoadingLen
    call Print
    
    ; Setup startup info
    mov dword ptr [startupInfo], 104
    
    ; Create process for GPU backend
    lea rcx, msgRunning
    mov rdx, msgRunningLen
    call Print
    
    xor ecx, ecx
    lea rdx, gpuBackendPath
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+32], 0
    mov qword ptr [rsp+40], 0
    mov qword ptr [rsp+48], 0
    lea rax, startupInfo
    mov qword ptr [rsp+56], rax
    lea rax, processInfo
    mov qword ptr [rsp+64], rax
    call CreateProcessA
    test eax, eax
    jnz createOk
    ; CreateProcess failed
    lea rcx, msgCreateFail
    mov rdx, msgCreateFailLen
    call Print
    jmp fail
createOk:
    
    ; Wait for process to complete
    mov rcx, [processInfo]
    mov edx, INFINITE
    call WaitForSingleObject
    
    ; Get exit code
    mov rcx, [processInfo]
    lea rdx, exitCode
    call GetExitCodeProcess
    
    ; Close handles
    mov rcx, [processInfo]
    call CloseHandle
    mov rcx, [processInfo+8]
    call CloseHandle
    
    ; Check exit code - exitCode is a DWORD (32-bit)
    mov eax, exitCode
    test eax, eax
    jnz fail
    
    lea rcx, msgSuccess
    mov rdx, msgSuccessLen
    call Print
    
    xor ecx, ecx
    call ExitProcess
    
fail:
    lea rcx, msgFail
    mov rdx, msgFailLen
    call Print
    ; Print the actual exit code for debugging
    mov ecx, exitCode
    call PrintNum
    lea rcx, crlf
    mov rdx, crlfLen
    call Print
    mov ecx, 1
    call ExitProcess
    
    add rsp, 256
    pop rbp
    ret
main ENDP

END
