; =============================================================================
; RawrXDMain.asm — Pure Native Entrypoint for RawrXD
; PE entry, process init, stack setup, subsystem startup, shutdown
; =============================================================================

OPTION CASEMAP:NONE
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

; ---------------------------------------------------------------------------
; External declarations
; ---------------------------------------------------------------------------
EXTERNDEF InitializeRuntime:PROC
EXTERNDEF InitializeEngine:PROC
EXTERNDEF CreateMainWindow:PROC
EXTERNDEF RunMessageLoop:PROC
EXTERNDEF ShutdownRuntime:PROC

; Windows API
EXTERNDEF GetModuleHandleA:PROC
EXTERNDEF GetCommandLineA:PROC
EXTERNDEF ExitProcess:PROC

; ---------------------------------------------------------------------------
; .data
; ---------------------------------------------------------------------------
.DATA
ALIGN 8

g_hInstance     DQ 0
g_hPrevInstance DQ 0
g_lpCmdLine     DQ 0
g_nCmdShow      DD 0

szClassName     DB "RawrXDMainWindow", 0
szAppTitle      DB "RawrXD Sovereign Runtime", 0

; ---------------------------------------------------------------------------
; .code
; ---------------------------------------------------------------------------
.CODE

; =============================================================================
; WinMain — Native PE entrypoint
; =============================================================================
WinMain PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 64
    .allocstack 64
    .endprolog

    ; Save parameters
    mov     g_hInstance, rcx
    mov     g_hPrevInstance, rdx
    mov     g_lpCmdLine, r8
    mov     g_nCmdShow, r9d

    ; Phase 1: Initialize runtime core
    call    InitializeRuntime
    test    eax, eax
    jz      @@shutdown

    ; Phase 2: Initialize Deep2 engine
    call    InitializeEngine
    test    eax, eax
    jz      @@shutdown

    ; Phase 3: Create main window
    mov     rcx, g_hInstance
    call    CreateMainWindow
    test    rax, rax
    jz      @@shutdown

    ; Phase 4: Run message loop
    call    RunMessageLoop

@@shutdown:
    call    ShutdownRuntime

    ; Exit process
    xor     ecx, ecx
    call    ExitProcess

    ; Should never reach here
    xor     eax, eax
    mov     rsp, rbp
    pop     rbp
    ret
WinMain ENDP

; =============================================================================
; Standard C main entry (calls WinMain)
; =============================================================================
main PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog

    ; Get module handle
    xor     ecx, ecx
    call    GetModuleHandleA
    mov     rcx, rax

    ; Get command line
    call    GetCommandLineA
    mov     r8, rax

    ; Show window normally
    mov     r9d, 1      ; SW_SHOWNORMAL
    xor     edx, edx    ; hPrevInstance = NULL

    call    WinMain

    xor     eax, eax
    mov     rsp, rbp
    pop     rbp
    ret
main ENDP

END
