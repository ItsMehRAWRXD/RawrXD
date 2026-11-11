; =============================================================================
; test_syntax_harness.asm - Test Harness for Syntax Highlighter
; =============================================================================
; Demonstrates the VTable pattern for testing syntax_highlight.asm in isolation.
; This is a minimal EXE that loads syntax_pipeline.dll and tests the scanner.
;
; Build:
;   ml64 /c test_syntax_harness.asm
;   link /SUBSYSTEM:CONSOLE test_syntax_harness.obj kernel32.lib user32.lib
;
; Run:
;   test_syntax_harness.exe
;
; Version: 1.0
; Date: 2026-06-18
; =============================================================================

option casemap:none

; Include interface definitions
include plugin_iface.inc

; =============================================================================
; External Functions
; =============================================================================

EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN FreeLibrary:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleW:PROC
EXTERN ExitProcess:PROC

; =============================================================================
; .data Section
; =============================================================================

.data

; DLL name
szSyntaxDLL     BYTE "syntax_pipeline.dll", 0

; Test lines
szTestLine1     BYTE "mov rax, rbx", 0
szTestLine2     BYTE "; This is a comment", 0
szTestLine3     BYTE "call MyFunction", 0
szTestLine4     BYTE ".code", 0
szTestLine5     BYTE "mov rax, 0x12345678", 0

; Messages
szLoadSuccess   BYTE "Loaded syntax_pipeline.dll", 13, 10, 0
szVTableSuccess BYTE "Got VTable pointer", 13, 10, 0
szInitSuccess   BYTE "Syntax_Init() succeeded", 13, 10, 0
szScanSuccess   BYTE "Syntax_ScanLine() succeeded", 13, 10, 0
szTestFailed    BYTE "Test failed!", 13, 10, 0
szShutdown      BYTE "Syntax_Shutdown() completed", 13, 10, 0

; =============================================================================
; .bss Section
; =============================================================================

.bss

hModule         QWORD ?
pVTable         QWORD ?
hHeap           QWORD ?
hStdOut         QWORD ?

; =============================================================================
; .code Section
; =============================================================================

.code

; -----------------------------------------------------------------------------
; PrintString - Print a null-terminated string to stdout
; -----------------------------------------------------------------------------
; Parameters:
;   RCX = pointer to string (BYTE*)
; -----------------------------------------------------------------------------
PrintString PROC
    push rbx
    push rsi
    push rdi
    
    ; Get string length
    mov rsi, rcx
    xor ecx, ecx
strlen_loop:
    mov al, [rsi + rcx]
    test al, al
    jz strlen_done
    inc ecx
    jmp strlen_loop
strlen_done:
    
    ; Write to console
    mov rdi, rcx         ; length
    mov rcx, hStdOut
    mov rdx, rsi
    mov r8, rdi
    xor r9, r9
    sub rsp, 8
    mov qword ptr [rsp], 0
    call WriteConsoleW
    add rsp, 8
    
    pop rdi
    pop rsi
    pop rbx
    ret
PrintString ENDP

; -----------------------------------------------------------------------------
; main - Entry point
; -----------------------------------------------------------------------------
main PROC
    ; Save registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Get process heap
    call GetProcessHeap
    mov hHeap, rax
    
    ; Get stdout handle
    mov ecx, -11         ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    ; Load syntax_pipeline.dll
    lea rcx, szSyntaxDLL
    call LoadLibraryA
    test rax, rax
    jz test_failed
    mov hModule, rax
    
    ; Print success message
    lea rcx, szLoadSuccess
    call PrintString
    
    ; Get VTable
    mov rcx, hModule
    lea rdx, szGetVTable
    call GetProcAddress
    test rax, rax
    jz test_failed
    
    ; Call GetVTable
    call rax
    mov pVTable, rax
    
    ; Print VTable success
    lea rcx, szVTableSuccess
    call PrintString
    
    ; Call Syntax_Init via VTable
    mov rbx, pVTable
    call [rbx].SYNTAX_HIGHLIGHTER_VTABLE.pfnInit
    test eax, eax
    jz test_failed
    
    ; Print init success
    lea rcx, szInitSuccess
    call PrintString
    
    ; Test Syntax_ScanLine
    mov rbx, pVTable
    mov ecx, 0          ; line number
    lea rdx, szTestLine1 ; text
    mov r8d, 12         ; length
    call [rbx].SYNTAX_HIGHLIGHTER_VTABLE.pfnScanLine
    test eax, eax
    jz test_failed
    
    ; Print scan success
    lea rcx, szScanSuccess
    call PrintString
    
    ; Call Syntax_Shutdown
    mov rbx, pVTable
    call [rbx].SYNTAX_HIGHLIGHTER_VTABLE.pfnShutdown
    
    ; Print shutdown message
    lea rcx, szShutdown
    call PrintString
    
    ; Free library
    mov rcx, hModule
    call FreeLibrary
    
    ; Exit success
    xor ecx, ecx
    call ExitProcess
    
test_failed:
    ; Print failure message
    lea rcx, szTestFailed
    call PrintString
    
    ; Exit with error
    mov ecx, 1
    call ExitProcess
    
main ENDP

; VTable function name for GetProcAddress
szGetVTable BYTE "GetVTable", 0

END
