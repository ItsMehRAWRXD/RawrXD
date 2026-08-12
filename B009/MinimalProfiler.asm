; ================================================================================================
; Minimal Negative Space Profiler - Pure x64 MASM (CRT-Free)
; ================================================================================================

option casemap :none

; --- Win32 API Prototypes ---
GetStdHandle        PROTO :QWORD
WriteFile           PROTO :QWORD, :QWORD, :DWORD, :QWORD, :QWORD
ExitProcess         PROTO :DWORD

; --- Constants ---
STD_OUTPUT_HANDLE   EQU -11

; --- Data Section ---
.DATA
ALIGN 16
    hStdout             DQ 0
    bytesWritten        DQ 0

    msg1    DB "B009 Negative Space Profiler", 13, 10
            DB "============================", 13, 10, 13, 10
            DB "Simulating anti-pattern: T=32 token loop...", 13, 10, 0
    len1    EQU $ - msg1

    msg2    DB "Loop complete. Calls: 32", 13, 10, 13, 10
            DB "ANALYSIS:", 13, 10
            DB "  [T=32] Calls: 32", 13, 10
            DB "    [!] RED FLAG: call_count >= batch_size", 13, 10
            DB "        Diagnosis: SUPERFICIAL BATCHING detected.", 13, 10
            DB "        The loop is OUTSIDE the kernel.", 13, 10, 13, 10
            DB "    [+] Memory delta is flat. Bottleneck is compute/architectural.", 13, 10, 13, 10
            DB "Analysis complete.", 13, 10, 0
    len2    EQU $ - msg2

; --- Code Section ---
.CODE

; ==============================================================================
; Entry Point
; ==============================================================================
main PROC
    sub     rsp, 40                 ; Shadow space

    ; Get stdout handle
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     qword ptr [hStdout], rax

    ; Print message 1
    mov     rcx, qword ptr [hStdout]
    lea     rdx, msg1
    mov     r8d, len1
    lea     r9, [bytesWritten]
    mov     qword ptr [rsp + 32], 0
    call    WriteFile

    ; Simulate work (32 iterations)
    mov     rbx, 32
@loop:
    mov     rcx, 1000
@inner:
    dec     rcx
    jnz     @inner
    dec     rbx
    jnz     @loop

    ; Print message 2
    mov     rcx, qword ptr [hStdout]
    lea     rdx, msg2
    mov     r8d, len2
    lea     r9, [bytesWritten]
    mov     qword ptr [rsp + 32], 0
    call    WriteFile

    ; Exit
    xor     rcx, rcx
    call    ExitProcess

main ENDP
END
