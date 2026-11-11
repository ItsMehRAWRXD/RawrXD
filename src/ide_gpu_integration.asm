; ============================================================================
; ide_gpu_integration.asm — IDE GPU Integration Test
; ============================================================================
; This executable simulates the IDE calling the GPU backend
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

msgHeader db "RawrXD IDE - GPU Integration Test", 13, 10
msgHeaderLen equ $ - msgHeader

msgInit db "  Initializing IDE...", 13, 10
msgInitLen equ $ - msgInit

msgLoading db "  Loading GPU backend...", 13, 10
msgLoadingLen equ $ - msgLoading

msgRunning db "  Executing GPU backend...", 13, 10
msgRunningLen equ $ - msgRunning

msgSuccess db 13, 10, "IDE GPU Integration: SUCCESS", 13, 10
msgSuccessLen equ $ - msgSuccess

msgFail db 13, 10, "IDE GPU Integration: FAILED", 13, 10
msgFailLen equ $ - msgFail

gpuBackendPath db "..\gpu_backend.exe", 0

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
    mov dword ptr [startupInfo], 104  ; cb
    
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
    jz fail
    
    ; Wait for process to complete
    mov rcx, [processInfo]  ; hProcess
    mov edx, INFINITE
    call WaitForSingleObject
    
    ; Get exit code
    mov rcx, [processInfo]  ; hProcess
    lea rdx, exitCode
    call GetExitCodeProcess
    
    ; Close handles
    mov rcx, [processInfo]  ; hProcess
    call CloseHandle
    mov rcx, [processInfo+8]  ; hThread
    call CloseHandle
    
    ; Check exit code
    cmp exitCode, 0
    jne fail
    
    lea rcx, msgSuccess
    mov rdx, msgSuccessLen
    call Print
    
    xor ecx, ecx
    call ExitProcess
    
fail:
    lea rcx, msgFail
    mov rdx, msgFailLen
    call Print
    mov ecx, 1
    call ExitProcess
    
    add rsp, 256
    pop rbp
    ret
main ENDP

END
