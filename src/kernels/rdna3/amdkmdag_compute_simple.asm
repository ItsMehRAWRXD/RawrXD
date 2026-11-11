; amdkmdag_compute_simple.asm — WDDM KMD GPU Compute Dispatcher (Win32 API Version)
; Target: RX 7800 XT (gfx1101, Navi 32) on Windows 11
; Uses standard Win32 DeviceIoControl API instead of NT native API

OPTION CASEMAP:NONE

; ============================================================================
; WIN32 API DECLARATIONS
; ============================================================================
EXTERN DeviceIoControl:PROC
EXTERN CreateFileA:PROC
EXTERN CloseHandle:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN Sleep:PROC
EXTERN GetLastError:PROC

; ============================================================================
; CONSTANTS
; ============================================================================
GENERIC_READ            EQU 080000000h
GENERIC_WRITE           EQU 040000000h
OPEN_EXISTING           EQU 3
FILE_ATTRIBUTE_NORMAL   EQU 080h
FILE_SHARE_READ         EQU 1
FILE_SHARE_WRITE        EQU 2
INVALID_HANDLE_VALUE    EQU -1
MEM_COMMIT              EQU 01000h
MEM_RESERVE             EQU 02000h
MEM_RELEASE             EQU 08000h
PAGE_READWRITE          EQU 4
STD_OUTPUT_HANDLE       EQU -11

; IOCTL codes (estimated from ROCm/amdgpu headers)
; These are reverse-engineered from amdkmdag.sys
IOCTL_AMDGPU_CTX_ALLOC  EQU 08000200Bh
IOCTL_AMDGPU_CTX_FREE   EQU 08000200Ch
IOCTL_AMDGPU_BO_ALLOC   EQU 08000200Dh
IOCTL_AMDGPU_BO_FREE    EQU 08000200Eh
IOCTL_AMDGPU_CS_SUBMIT  EQU 080002011h
IOCTL_AMDGPU_CS_QUERYFence EQU 080002012h

; PM4 Packet constants
PM4_TYPE3               EQU 0C0000000h
PM4_SET_SH_REG          EQU 037h
PM4_DISPATCH_DIRECT     EQU 015h

; Compute registers (SH space)
COMPUTE_PGM_ADDR_LO     EQU 02E98h
COMPUTE_PGM_ADDR_HI     EQU 02E9Ch
COMPUTE_DISPATCH_INITIATOR EQU 02E80h

; ============================================================================
; DATA SECTION
; ============================================================================
.DATA

szDevicePath    DB "\\\\.\\amdkmdag", 0
msgHeader       DB "========================================", 13, 10
                DB " WDDM KMD GPU Compute Dispatcher", 13, 10
                DB " Target: RX 7800 XT (gfx1101)", 13, 10
                DB "========================================", 13, 10, 13, 10, 0
msgOpen         DB "[+] Opening amdkmdag device...", 13, 10, 0
msgOpenFail     DB "[-] Failed to open device", 13, 10, 0
msgOpenOk       DB "[+] Device opened successfully", 13, 10, 0
msgIoctl        DB "[+] Testing IOCTL...", 13, 10, 0
msgIoctlFail    DB "[-] IOCTL failed", 13, 10, 0
msgIoctlOk      DB "[+] IOCTL succeeded", 13, 10, 0
msgDone         DB "[+] Test complete", 13, 10, 0
msgExit         DB "[+] Exiting...", 13, 10, 0

; ============================================================================
; BSS SECTION
; ============================================================================
.data?

hDevice         DQ ?
ctxHandle       DQ ?
boHandle        DQ ?
dwReturned      DD ?

; ============================================================================
; CODE SECTION
; ============================================================================
.CODE

; ----------------------------------------------------------------------------
; PrintString - Output null-terminated string to console
; Input: RCX = string pointer
; ----------------------------------------------------------------------------
PrintString PROC FRAME
    push    rbp
    .pushreg rbp
    push    rdi
    .pushreg rdi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rdi, rcx

    ; Calculate length
    xor     eax, eax
    mov     rcx, rdi
    dec     rcx
lenLoop:
    inc     rcx
    cmp     byte ptr [rcx], 0
    jne     lenLoop
    sub     rcx, rdi

    ; Get stdout handle
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle

    ; Write to console
    mov     rcx, rax                    ; hConsoleOutput
    mov     rdx, rdi                    ; lpBuffer
    mov     r8, rax                     ; nNumberOfCharsToWrite (reuse length)
    sub     r8, rdi
    lea     r9, [dwReturned]            ; lpNumberOfCharsWritten
    mov     qword ptr [rsp+32], 0       ; lpReserved
    call    WriteConsoleA

    add     rsp, 40
    pop     rdi
    pop     rbp
    ret
PrintString ENDP

; ----------------------------------------------------------------------------
; OpenDevice - Open amdkmdag device
; Output: RAX = handle or 0 on failure
; ----------------------------------------------------------------------------
OpenDevice PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; CreateFileA("\\\\.\\amdkmdag", GENERIC_READ|GENERIC_WRITE, ...)
    lea     rcx, szDevicePath
    mov     edx, GENERIC_READ OR GENERIC_WRITE
    xor     r8d, r8d                    ; dwShareMode (exclusive)
    xor     r9d, r9d                    ; lpSecurityAttributes
    mov     qword ptr [rsp+32], OPEN_EXISTING
    mov     qword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+48], 0      ; hTemplateFile
    call    CreateFileA

    cmp     rax, INVALID_HANDLE_VALUE
    je      openFail
    jmp     openDone

openFail:
    xor     rax, rax

openDone:
    add     rsp, 40
    pop     rbp
    ret
OpenDevice ENDP

; ----------------------------------------------------------------------------
; TestIoctl - Test a simple IOCTL to verify communication
; Input: RCX = device handle
; Output: RAX = 0 on success, non-zero on failure
; ----------------------------------------------------------------------------
TestIoctl PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    sub     rsp, 56
    .allocstack 56
    .endprolog

    mov     rbx, rcx                    ; Save device handle

    ; Allocate input/output buffers
    mov     rcx, 256                    ; Size
    mov     edx, MEM_COMMIT OR MEM_RESERVE
    mov     r8d, PAGE_READWRITE
    xor     r9d, r9d                    ; No allocation type extension
    mov     qword ptr [rsp+32], 0       ; hFile (ignored)
    mov     qword ptr [rsp+40], 0       ; dwMaximumSizeHigh (ignored)
    call    VirtualAlloc

    test    rax, rax
    jz      ioctlFail

    mov     r8, rax                     ; R8 = lpInBuffer

    ; Try IOCTL_AMDGPU_CTX_ALLOC
    ; This is a test - the actual structure is unknown
    mov     rcx, rbx                    ; hDevice
    mov     edx, IOCTL_AMDGPU_CTX_ALLOC ; dwIoControlCode
    mov     r9, r8                      ; lpOutBuffer (same as input)
    mov     qword ptr [rsp+32], 256     ; nInBufferSize
    mov     qword ptr [rsp+40], 256     ; nOutBufferSize
    lea     rax, [dwReturned]
    mov     qword ptr [rsp+48], rax     ; lpBytesReturned
    mov     qword ptr [rsp+56], 0       ; lpOverlapped
    call    DeviceIoControl

    test    al, al
    jz      ioctlFailCleanup

    ; Success
    xor     eax, eax
    jmp     ioctlDone

ioctlFailCleanup:
    mov     rcx, r8                     ; Buffer
    xor     edx, edx                    ; dwSize (0 = release all)
    mov     r8d, MEM_RELEASE
    call    VirtualFree

ioctlFail:
    mov     eax, 1

ioctlDone:
    add     rsp, 56
    pop     rbx
    pop     rbp
    ret
TestIoctl ENDP

; ----------------------------------------------------------------------------
; mainCRTStartup - Entry point
; ----------------------------------------------------------------------------
mainCRTStartup PROC FRAME
    push    rbp
    .pushreg rbp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; Print header
    lea     rcx, msgHeader
    call    PrintString

    ; Print opening message
    lea     rcx, msgOpen
    call    PrintString

    ; Open device
    call    OpenDevice
    mov     [hDevice], rax
    test    rax, rax
    jz      mainOpenFail

    lea     rcx, msgOpenOk
    call    PrintString

    ; Test IOCTL
    lea     rcx, msgIoctl
    call    PrintString

    mov     rcx, [hDevice]
    call    TestIoctl
    test    eax, eax
    jnz     mainIoctlFail

    lea     rcx, msgIoctlOk
    call    PrintString

    ; Close device
    mov     rcx, [hDevice]
    call    CloseHandle

    lea     rcx, msgDone
    call    PrintString
    jmp     mainExit

mainOpenFail:
    lea     rcx, msgOpenFail
    call    PrintString
    jmp     mainExit

mainIoctlFail:
    lea     rcx, msgIoctlFail
    call    PrintString
    mov     rcx, [hDevice]
    call    CloseHandle
    jmp     mainExit

mainExit:
    lea     rcx, msgExit
    call    PrintString

    xor     ecx, ecx
    call    ExitProcess

mainCRTStartup ENDP

END
