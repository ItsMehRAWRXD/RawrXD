; ============================================================================
; hip_test.asm — Working HIP/ROCm Test in x64 MASM
; ============================================================================
; Assemble: ml64.exe /c /W3 /nologo /Fo hip_test.obj hip_test.asm
; Link: link.exe /SUBSYSTEM:CONSOLE /ENTRY:main /OUT:hip_test.exe hip_test.obj kernel32.lib
; ============================================================================

EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF ExitProcess:PROC
EXTERNDEF LoadLibraryA:PROC
EXTERNDEF GetProcAddress:PROC
EXTERNDEF FreeLibrary:PROC

.const
STD_OUTPUT_HANDLE equ -11
HIP_SUCCESS equ 0

.data
align 8
hStdOut dq 0
bytesWritten dq 0
hipDll dq 0

; Function pointers
hipInitPtr dq 0
hipGetDeviceCountPtr dq 0
hipSetDevicePtr dq 0

; Messages
msgInit db "[HIP] Loading HIP/ROCm runtime...", 13, 10
msgInitLen equ $ - msgInit

msgLoaded db "[HIP] DLL loaded successfully", 13, 10
msgLoadedLen equ $ - msgLoaded

msgFuncs db "[HIP] Function pointers resolved", 13, 10
msgFuncsLen equ $ - msgFuncs

msgInitSuccess db "[HIP] hipInit: SUCCESS", 13, 10
msgInitSuccessLen equ $ - msgInitSuccess

msgDevices db "[HIP] Device count: "
msgDevicesLen equ $ - msgDevices

msgComplete db "[HIP] Initialization complete", 13, 10
msgCompleteLen equ $ - msgComplete

msgSuccess db 13, 10, "=== HIP TEST PASSED ===", 13, 10
msgSuccessLen equ $ - msgSuccess

msgFail db 13, 10, "=== HIP TEST FAILED ===", 13, 10
msgFailLen equ $ - msgFail

crlf db 13, 10
crlfLen equ $ - crlf

msgNoRocm db "[HIP] ROCm not installed (optional)", 13, 10
msgNoRocmLen equ $ - msgNoRocm

; DLL names
dllName db "amdhip64.dll", 0

; Function names
funcInit db "hipInit", 0
funcGetDeviceCount db "hipGetDeviceCount", 0
funcSetDevice db "hipSetDevice", 0

; Device count
deviceCount dd 0

.code

; Print string to stdout
PrintString PROC
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
PrintString ENDP

; Print number as ASCII
PrintNumber PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rax, rcx
    lea rdi, [rsp+48]
    mov byte ptr [rdi], 0
    mov rbx, 10
convertLoop:
    xor rdx, rdx
    div rbx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz convertLoop
    lea rax, [rsp+48]
    sub rax, rdi
    mov rcx, rdi
    mov rdx, rax
    call PrintString
    add rsp, 64
    pop rbp
    ret
PrintNumber ENDP

; Initialize HIP
InitHIP PROC
    push rbp
    mov rbp, rsp
    sub rsp, 256
    
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    lea rcx, msgInit
    mov rdx, msgInitLen
    call PrintString
    
    ; Load HIP DLL
    lea rcx, dllName
    call LoadLibraryA
    mov hipDll, rax
    test rax, rax
    jz noRocm
    
    lea rcx, msgLoaded
    mov rdx, msgLoadedLen
    call PrintString
    
    ; Get function pointers
    mov rcx, hipDll
    lea rdx, funcInit
    call GetProcAddress
    mov hipInitPtr, rax
    
    mov rcx, hipDll
    lea rdx, funcGetDeviceCount
    call GetProcAddress
    mov hipGetDeviceCountPtr, rax
    
    mov rcx, hipDll
    lea rdx, funcSetDevice
    call GetProcAddress
    mov hipSetDevicePtr, rax
    
    lea rcx, msgFuncs
    mov rdx, msgFuncsLen
    call PrintString
    
    ; Call hipInit
    mov rcx, hipInitPtr
    test rcx, rcx
    jz initFail
    xor ecx, ecx
    call hipInitPtr
    test eax, eax
    jnz initFail
    
    lea rcx, msgInitSuccess
    mov rdx, msgInitSuccessLen
    call PrintString
    
    ; Get device count
    mov rcx, hipGetDeviceCountPtr
    test rcx, rcx
    jz initFail
    lea rcx, deviceCount
    call hipGetDeviceCountPtr
    test eax, eax
    jnz initFail
    
    lea rcx, msgDevices
    mov rdx, msgDevicesLen
    call PrintString
    mov ecx, deviceCount
    call PrintNumber
    lea rcx, crlf
    mov rdx, crlfLen
    call PrintString
    
    lea rcx, msgComplete
    mov rdx, msgCompleteLen
    call PrintString
    
    mov rax, 1
    jmp initDone
    
noRocm:
    lea rcx, msgNoRocm
    mov rdx, msgNoRocmLen
    call PrintString
    mov rax, 1  ; Not a failure, just not installed
    jmp initDone
    
initFail:
    xor rax, rax
    
initDone:
    add rsp, 256
    pop rbp
    ret
InitHIP ENDP

; Cleanup HIP
CleanupHIP PROC
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov rcx, hipDll
    test rcx, rcx
    jz cleanupDone
    call FreeLibrary
cleanupDone:
    add rsp, 32
    pop rbp
    ret
CleanupHIP ENDP

; Main entry point
main PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    call InitHIP
    test rax, rax
    jz mainFail
    call CleanupHIP
    lea rcx, msgSuccess
    mov rdx, msgSuccessLen
    call PrintString
    xor ecx, ecx
    call ExitProcess
mainFail:
    lea rcx, msgFail
    mov rdx, msgFailLen
    call PrintString
    mov ecx, 1
    call ExitProcess
    add rsp, 64
    pop rbp
    ret
main ENDP

END
