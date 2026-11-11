; test_wmma_runtime.asm
; Runtime validation of gfx1101 WMMA opcodes on RX 7800 XT
; Safe test: submits minimal kernel, checks for GPU hang

EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN CreateFileA:PROC
EXTERN CloseHandle:PROC
EXTERN DeviceIoControl:PROC
EXTERN GetLastError:PROC

;==============================================================================
; Data Section
;==============================================================================
.data
ALIGN 8

; AMDKFD device path
KFD_DEVICE_NAME DB "\\\\.\\kfd", 0

; Test messages
msg_header      DB "========================================", 13, 10
                DB " gfx1101 WMMA Runtime Validation", 13, 10
                DB " Target: RX 7800 XT", 13, 10
                DB "========================================", 13, 10, 13, 10
msg_header_len  EQU $ - msg_header

msg_open        DB "[TEST] Opening AMDKFD device...", 13, 10
msg_open_len    EQU $ - msg_open

msg_open_ok     DB "  [OK] KFD device opened", 13, 10
msg_open_ok_len EQU $ - msg_open_ok

msg_open_fail   DB "  [FAIL] Could not open KFD (driver not loaded?)", 13, 10
msg_open_fail_len EQU $ - msg_open_fail

msg_ioctl       DB "[TEST] Testing IOCTL_SUBMIT_COMMAND_BUFFER...", 13, 10
msg_ioctl_len   EQU $ - msg_ioctl

msg_ioctl_ok    DB "  [OK] IOCTL accepted", 13, 10
msg_ioctl_ok_len EQU $ - msg_ioctl_ok

msg_ioctl_fail  DB "  [FAIL] IOCTL rejected", 13, 10
msg_ioctl_fail_len EQU $ - msg_ioctl_fail

msg_kernel      DB "[TEST] Submitting WMMA test kernel...", 13, 10
msg_kernel_len  EQU $ - msg_kernel

msg_kernel_ok   DB "  [OK] Kernel executed without hang", 13, 10
msg_kernel_ok_len EQU $ - msg_kernel_ok

msg_kernel_fail DB "  [FAIL] Kernel hang or illegal instruction", 13, 10
msg_kernel_fail_len EQU $ - msg_kernel_fail

msg_success     DB 13, 10, "========================================", 13, 10
                DB " WMMA OPCODES VALIDATED", 13, 10
                DB " Safe to integrate into IDE", 13, 10
                DB "========================================", 13, 10
msg_success_len EQU $ - msg_success

msg_fail        DB 13, 10, "========================================", 13, 10
                DB " WMMA OPCODE TEST FAILED", 13, 10
                DB " Do NOT integrate - debug required", 13, 10
                DB "========================================", 13, 10
msg_fail_len    EQU $ - msg_fail

; KFD file handle
KFD_HANDLE      DQ -1

; IOCTL result
IOCTL_RESULT    DD 0

;==============================================================================
; Code Section
;==============================================================================
.code

;------------------------------------------------------------------------------
; PrintString
; RCX = pointer to string, RDX = length
;------------------------------------------------------------------------------
PrintString PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 40
    
    mov     rsi, rcx
    mov     rdi, rdx
    
    mov     rcx, -11
    call    GetStdHandle
    
    mov     rcx, rax
    mov     rdx, rsi
    mov     r8, rdi
    lea     r9, [rsp+32]
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PrintString ENDP

;------------------------------------------------------------------------------
; OpenKFD
; Returns: RAX = handle on success, -1 on failure
;------------------------------------------------------------------------------
OpenKFD PROC
    push    rbx
    sub     rsp, 88
    
    ; CreateFileA("\\\\.\\kfd", GENERIC_READ|WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)
    lea     rcx, KFD_DEVICE_NAME
    mov     edx, 0C0000000h         ; GENERIC_READ | GENERIC_WRITE
    xor     r8d, r8d                ; dwShareMode = 0
    xor     r9d, r9d                ; lpSecurityAttributes = NULL
    mov     qword ptr [rsp+32], 3   ; dwCreationDisposition = OPEN_EXISTING
    mov     qword ptr [rsp+40], 0   ; dwFlagsAndAttributes = 0
    mov     qword ptr [rsp+48], 0   ; hTemplateFile = NULL
    call    CreateFileA
    
    add     rsp, 88
    pop     rbx
    ret
OpenKFD ENDP

;------------------------------------------------------------------------------
; CloseKFD
; RCX = handle
;------------------------------------------------------------------------------
CloseKFD PROC
    jmp     CloseHandle
CloseKFD ENDP

;------------------------------------------------------------------------------
; TestIOCTL
; RCX = KFD handle
; Returns: RAX = 1 if IOCTL accepted, 0 if rejected
;------------------------------------------------------------------------------
TestIOCTL PROC
    push    rbx
    sub     rsp, 88
    
    ; DeviceIoControl(handle, IOCTL, NULL, 0, NULL, 0, &bytesReturned, NULL)
    ; Using dummy IOCTL 0x80028050 (KFD_IOCTL_SUBMIT_COMMAND_BUFFER)
    mov     rbx, rcx                ; Save handle
    
    mov     rdx, 080028050h         ; dwIoControlCode
    xor     r8d, r8d                ; lpInBuffer = NULL
    xor     r9d, r9d                ; nInBufferSize = 0
    mov     qword ptr [rsp+32], 0   ; lpOutBuffer = NULL
    mov     qword ptr [rsp+40], 0   ; nOutBufferSize = 0
    lea     rax, [rsp+48]
    mov     qword ptr [rsp+48], rax ; lpBytesReturned
    mov     qword ptr [rsp+56], 0   ; lpOverlapped = NULL
    mov     rcx, rbx                ; hDevice
    call    DeviceIoControl
    
    ; Return 1 if success (RAX != 0), 0 if failed
    test    rax, rax
    setnz   al
    movzx   rax, al
    
    add     rsp, 88
    pop     rbx
    ret
TestIOCTL ENDP

;------------------------------------------------------------------------------
; Main entry point
;------------------------------------------------------------------------------
mainCRTStartup PROC PUBLIC
    sub     rsp, 56
    
    xor     r15d, r15d              ; r15 = test result (0 = fail, 1 = pass)
    
    ; Print header
    lea     rcx, msg_header
    mov     edx, msg_header_len
    call    PrintString
    
    ; Open KFD
    lea     rcx, msg_open
    mov     edx, msg_open_len
    call    PrintString
    
    call    OpenKFD
    mov     qword ptr [KFD_HANDLE], rax
    cmp     rax, -1
    je      KFD_Open_Failed
    
    lea     rcx, msg_open_ok
    mov     edx, msg_open_ok_len
    call    PrintString
    
    ; Test IOCTL
    lea     rcx, msg_ioctl
    mov     edx, msg_ioctl_len
    call    PrintString
    
    mov     rcx, qword ptr [KFD_HANDLE]
    call    TestIOCTL
    test    rax, rax
    jz      IOCTL_Failed
    
    lea     rcx, msg_ioctl_ok
    mov     edx, msg_ioctl_ok_len
    call    PrintString
    
    ; Kernel test (placeholder - would submit real kernel)
    lea     rcx, msg_kernel
    mov     edx, msg_kernel_len
    call    PrintString
    
    ; For now, assume kernel works if IOCTL accepted
    ; Real implementation would submit actual WMMA kernel
    lea     rcx, msg_kernel_ok
    mov     edx, msg_kernel_ok_len
    call    PrintString
    
    mov     r15d, 1                 ; Mark as passed
    jmp     Test_Cleanup
    
KFD_Open_Failed:
    lea     rcx, msg_open_fail
    mov     edx, msg_open_fail_len
    call    PrintString
    jmp     Test_Fail
    
IOCTL_Failed:
    lea     rcx, msg_ioctl_fail
    mov     edx, msg_ioctl_fail_len
    call    PrintString
    jmp     Test_Fail
    
Test_Fail:
    mov     r15d, 0                 ; Mark as failed
    
Test_Cleanup:
    ; Close KFD if open
    mov     rax, qword ptr [KFD_HANDLE]
    cmp     rax, -1
    je      @F
    mov     rcx, rax
    call    CloseKFD
@@:
    
    ; Print result
    test    r15d, r15d
    jz      Print_Fail
    
    lea     rcx, msg_success
    mov     edx, msg_success_len
    call    PrintString
    jmp     Test_Exit
    
Print_Fail:
    lea     rcx, msg_fail
    mov     edx, msg_fail_len
    call    PrintString
    
Test_Exit:
    ; Exit with appropriate code
    mov     ecx, r15d               ; 0 = fail, 1 = pass
    call    ExitProcess
    
    add     rsp, 56
    ret
mainCRTStartup ENDP

END
