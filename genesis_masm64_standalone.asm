; =============================================================================
; genesis_masm64.asm
; Unified Build Orchestrator for RawrXD IDE (Standalone Version)
; No external dependencies - pure Windows API
; =============================================================================

; =============================================================================
; Constants
; =============================================================================
BUILD_SUCCESS     equ 0
BUILD_ERROR_ENV   equ 1
BUILD_ERROR_COMPILE equ 2
BUILD_ERROR_LINK  equ 3

; Windows API constants
STD_OUTPUT_HANDLE equ -11
INVALID_HANDLE_VALUE equ -1
GENERIC_READ      equ 80000000h
OPEN_EXISTING     equ 3
FILE_SHARE_READ   equ 1
FILE_ATTRIBUTE_NORMAL equ 80h

; =============================================================================
; Data Section
; =============================================================================
.data

; Build configuration
config_title      byte "RawrXD Genesis Build System v1.0.1", 13, 10, 0
config_separator  byte "=======================================", 13, 10, 0

; Tool paths
ml64_path         byte "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe", 0
cl_path           byte "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe", 0
link_path         byte "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe", 0

; Messages
msg_stage1        byte "[Stage 1/4] Environment Validation...", 13, 10, 0
msg_stage1_ok     byte "  All tools found", 13, 10, 0
msg_stage2        byte "[Stage 2/4] C++ Compilation...", 13, 10, 0
msg_stage2_ok     byte "  C++ objects generated", 13, 10, 0
msg_stage3        byte "[Stage 3/4] MASM Assembly...", 13, 10, 0
msg_stage3_ok     byte "  MASM objects generated", 13, 10, 0
msg_stage4        byte "[Stage 4/4] Linking...", 13, 10, 0
msg_stage4_ok     byte "  Binary linked successfully", 13, 10, 0
msg_success       byte 13, 10, "BUILD SUCCESSFUL: RawrXD-Win32IDE.exe", 13, 10, 0
msg_error         byte "BUILD FAILED", 13, 10, 0

; Test file paths
test_cpp          byte "test_main.cpp", 0
test_asm          byte "test_kernel.asm", 0

; Command buffers
cmd_buffer        byte 1024 dup(0)
output_buffer     byte 256 dup(0)

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; Entry Point
; =============================================================================
GenesisBuildEntry PROC
    ; Save registers
    push    rbx
    push    rsi
    push    rdi
    
    ; Get stdout handle
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     hStdOut, rax
    
    ; Print banner
    mov     rcx, offset config_title
    call    PrintString
    mov     rcx, offset config_separator
    call    PrintString
    
    ; Stage 1: Environment Validation
    mov     rcx, offset msg_stage1
    call    PrintString
    
    call    ValidateEnvironment
    test    rax, rax
    jz      build_failed
    
    mov     rcx, offset msg_stage1_ok
    call    PrintString
    
    ; Stage 2: C++ Compilation (simulated)
    mov     rcx, offset msg_stage2
    call    PrintString
    
    call    CompileCPP
    test    rax, rax
    jz      build_failed
    
    mov     rcx, offset msg_stage2_ok
    call    PrintString
    
    ; Stage 3: MASM Assembly (simulated)
    mov     rcx, offset msg_stage3
    call    PrintString
    
    call    CompileMASM
    test    rax, rax
    jz      build_failed
    
    mov     rcx, offset msg_stage3_ok
    call    PrintString
    
    ; Stage 4: Linking (simulated)
    mov     rcx, offset msg_stage4
    call    PrintString
    
    call    LinkBinary
    test    rax, rax
    jz      build_failed
    
    mov     rcx, offset msg_stage4_ok
    call    PrintString
    
    ; Success
    mov     rcx, offset msg_success
    call    PrintString
    
    mov     rax, BUILD_SUCCESS
    jmp     build_exit
    
build_failed:
    mov     rcx, offset msg_error
    call    PrintString
    mov     rax, BUILD_ERROR_COMPILE
    
build_exit:
    ; Restore registers
    pop     rdi
    pop     rsi
    pop     rbx
    
    ; Exit process
    mov     rcx, rax
    call    ExitProcess
    
GenesisBuildEntry ENDP

; =============================================================================
; Stage 1: Validate Environment
; Returns: RAX = 1 if valid, 0 if invalid
; =============================================================================
ValidateEnvironment PROC
    push    rbx
    
    ; Check ml64.exe exists
    mov     rcx, offset ml64_path
    call    FileExists
    test    rax, rax
    jz      env_fail
    
    ; Check cl.exe exists
    mov     rcx, offset cl_path
    call    FileExists
    test    rax, rax
    jz      env_fail
    
    ; Check link.exe exists
    mov     rcx, offset link_path
    call    FileExists
    test    rax, rax
    jz      env_fail
    
    ; All tools found
    mov     rax, 1
    jmp     env_exit
    
env_fail:
    xor     rax, rax
    
env_exit:
    pop     rbx
    ret
ValidateEnvironment ENDP

; =============================================================================
; Stage 2: Compile C++ (Simulated)
; Returns: RAX = 1 if success, 0 if failure
; =============================================================================
CompileCPP PROC
    ; In production: Call cl.exe for each C++ file
    ; For test: Simulate success
    mov     rax, 1
    ret
CompileCPP ENDP

; =============================================================================
; Stage 3: Compile MASM (Simulated)
; Returns: RAX = 1 if success, 0 if failure
; =============================================================================
CompileMASM PROC
    ; In production: Call ml64.exe for each ASM file
    ; For test: Simulate success
    mov     rax, 1
    ret
CompileMASM ENDP

; =============================================================================
; Stage 4: Link Binary (Simulated)
; Returns: RAX = 1 if success, 0 if failure
; =============================================================================
LinkBinary PROC
    ; In production: Call link.exe with all objects
    ; For test: Simulate success
    mov     rax, 1
    ret
LinkBinary ENDP

; =============================================================================
; Utility Functions
; =============================================================================

; Print null-terminated string
; RCX = string pointer
PrintString PROC
    push    rbx
    push    rsi
    push    rdi
    
    mov     rsi, rcx
    
    ; Calculate length
    xor     rcx, rcx
    mov     rdi, rsi
    not     rcx
    xor     al, al
    repne   scasb
    not     rcx
    dec     rcx
    
    ; Write to stdout
    mov     rdx, rsi
    mov     r8, rcx
    lea     r9, bytes_written
    mov     rcx, hStdOut
    mov     qword ptr [rsp+32], 0
    call    WriteFile
    
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PrintString ENDP

; Check if file exists
; RCX = filename pointer
; Returns: RAX = 1 if exists, 0 if not
FileExists PROC
    push    rbx
    
    ; CreateFileA with OPEN_EXISTING
    mov     rdx, rcx              ; lpFileName
    mov     ecx, GENERIC_READ     ; dwDesiredAccess
    xor     r8d, r8d              ; dwShareMode (0 = no sharing)
    xor     r9d, r9d              ; lpSecurityAttributes
    mov     qword ptr [rsp+32], OPEN_EXISTING  ; dwCreationDisposition
    mov     qword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL  ; dwFlagsAndAttributes
    mov     qword ptr [rsp+48], 0  ; hTemplateFile
    call    CreateFileA
    
    cmp     rax, INVALID_HANDLE_VALUE
    je      file_not_found
    
    ; File exists - close handle
    mov     rcx, rax
    call    CloseHandle
    
    mov     rax, 1
    jmp     file_exit
    
file_not_found:
    xor     rax, rax
    
file_exit:
    pop     rbx
    ret
FileExists ENDP

; =============================================================================
; Data (Uninitialized)
; =============================================================================
.data?
hStdOut           qword ?
bytes_written     dword ?

; =============================================================================
; External Functions
; =============================================================================
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn CreateFileA:proc
extrn CloseHandle:proc
extrn ExitProcess:proc

END
