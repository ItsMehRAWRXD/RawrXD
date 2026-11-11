; hello.asm - Minimal Sovereign Bootstrap Example
; Produces valid PE32+ executable with zero dependencies
; Target: S0.1 - PE Writer validation
;
; Build with MSVC (Stage 0):
;   ml64 hello.asm /link /entry:mainCRTStartup /subsystem:console kernel32.lib
;
; Build with Sovereign (Stage 1):
;   sovereign_asm hello.asm -o hello.obj
;   sovereign_link hello.obj -o hello.exe

option casemap:none

; =============================================================================
; CONSTANTS
; =============================================================================

STD_OUTPUT_HANDLE equ -11
NULL equ 0

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Message to display
msg_hello db "Hello from Sovereign Toolchain!", 13, 10
msg_hello_len equ $ - msg_hello

msg_stage db "Stage 0: Bootstrap Complete", 13, 10
msg_stage_len equ $ - msg_stage

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; External imports from kernel32.dll
; In Stage 0: Use MS linker with kernel32.lib
; In Stage 1: Direct PE import table generation
extrn GetStdHandle:proc
extrn WriteFile:proc
extrn ExitProcess:proc

; =============================================================================
; mainCRTStartup - Entry point (no CRT)
; =============================================================================

mainCRTStartup PROC FRAME
    ; Prologue
    push rbp
    .pushreg rbp
    mov rbp, rsp
    sub rsp, 56                 ; Shadow space (32) + local vars + align
    .allocstack 56
    .endprolog

    ; Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov r12, rax                  ; Save handle (r12 is preserved)

    ; Write first message
    mov rcx, r12                  ; hConsoleOutput
    lea rdx, msg_hello            ; lpBuffer
    mov r8d, msg_hello_len        ; nNumberOfCharsToWrite
    lea r9, [rsp+32]              ; lpNumberOfCharsWritten (stack)
    mov qword ptr [rsp+40], NULL  ; lpReserved
    call WriteFile

    ; Write second message
    mov rcx, r12
    lea rdx, msg_stage
    mov r8d, msg_stage_len
    lea r9, [rsp+32]
    mov qword ptr [rsp+40], NULL
    call WriteFile

    ; Epilogue
    mov rsp, rbp
    pop rbp

    ; Exit with code 0
    xor ecx, ecx
    call ExitProcess

mainCRTStartup ENDP

; =============================================================================
; END
; =============================================================================

end
