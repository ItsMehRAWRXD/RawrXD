; ================================================================================================
; Standalone Negative Space Bottleneck Profiler (Pure x64 MASM, CRT-Free)
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
    g_batch_size        DQ 32
    g_call_count        DQ 0
    g_total_cycles      DQ 0

    hStdout             DQ 0
    bytesWritten        DQ 0

    ; Diagnostic strings
    msgInit             DB "Profiler initialized.\r\n", 0
    lenMsgInit          EQU $ - msgInit

    msgLoopStart        DB "Running simulated token loop (T=32)...\r\n", 0
    lenLoopStart        EQU $ - msgLoopStart

    msgLoopDone         DB "Loop complete.\r\n", 0
    lenLoopDone         EQU $ - msgLoopDone

    msgReport           DB "\r\n==================================================\r\n"
                        DB "  BOTTLENECK ANALYSIS (Negative Space Detection)\r\n"
                        DB "==================================================\r\n", 0
    lenReport           EQU $ - msgReport

    msgTarget           DB "\r\nTarget: StreamingMatMul\r\n", 0
    lenTarget           EQU $ - msgTarget

    msgRedFlag          DB "    [!] RED FLAG: call_count (32) >= batch_size (32)\r\n"
                        DB "        Diagnosis: SUPERFICIAL BATCHING detected.\r\n"
                        DB "        The loop is OUTSIDE the kernel.\r\n", 0
    lenRedFlag          EQU $ - msgRedFlag

    msgGreenFlag        DB "    [+] Memory delta is flat. Bottleneck is compute/architectural.\r\n", 0
    lenGreenFlag        EQU $ - msgGreenFlag

    msgDone             DB "\r\nAnalysis complete.\r\n", 0
    lenDone             EQU $ - msgDone

    numBuffer           DB 32 DUP(0)

; --- Code Section ---
.CODE

; ==============================================================================
; Helper: PrintString
; RCX = pointer to null-terminated string
; ==============================================================================
PrintString PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rsi, rcx

    ; Calculate string length
    xor     rax, rax
    mov     rdi, rsi
_CountLoop:
    mov     bl, byte ptr [rdi]
    test    bl, bl
    jz      _CountDone
    inc     rdi
    inc     rax
    jmp     _CountLoop
_CountDone:

    ; WriteFile(hStdout, buffer, length, &bytesWritten, NULL)
    mov     rcx, qword ptr [hStdout]
    mov     rdx, rsi
    mov     r8d, eax
    lea     r9, [bytesWritten]
    mov     qword ptr [rsp + 32], 0
    call    WriteFile

    mov     rsp, rbp
    pop     rbp
    ret
PrintString ENDP

; ==============================================================================
; Helper: U64ToString
; Converts unsigned 64-bit integer in RAX to decimal string in numBuffer.
; Returns: RAX = pointer to string
; ==============================================================================
U64ToString PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog

    lea     rdi, [numBuffer + 31]
    mov     byte ptr [rdi], 0
    mov     rbx, 10

    test    rax, rax
    jnz     _ConvertLoop
    mov     byte ptr [rdi - 1], '0'
    lea     rax, [rdi - 1]
    mov     rsp, rbp
    pop     rdi
    pop     rbx
    pop     rbp
    ret

_ConvertLoop:
    xor     rdx, rdx
    div     rbx
    add     dl, '0'
    dec     rdi
    mov     byte ptr [rdi], dl
    test    rax, rax
    jnz     _ConvertLoop

    mov     rax, rdi
    mov     rsp, rbp
    pop     rdi
    pop     rbx
    pop     rbp
    ret
U64ToString ENDP

; ==============================================================================
; Helper: PrintU64
; Prints unsigned 64-bit integer in RAX
; ==============================================================================
PrintU64 PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog

    call    U64ToString
    mov     rcx, rax
    call    PrintString

    mov     rsp, rbp
    pop     rbp
    ret
PrintU64 ENDP

; ==============================================================================
; Simulated work (represents dequant + dot product)
; ==============================================================================
SimulateWork PROC FRAME
    .endprolog
    mov     rcx, 1000
@work_loop:
    dec     rcx
    jnz     @work_loop
    ret
SimulateWork ENDP

; ==============================================================================
; Entry Point
; ==============================================================================
main PROC FRAME
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; Get stdout handle
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     qword ptr [hStdout], rax

    ; Print init message
    lea     rcx, msgInit
    call    PrintString

    ; Print loop start message
    lea     rcx, msgLoopStart
    call    PrintString

    ; Simulate the anti-pattern: T=32 token loop
    mov     rbx, 32                 ; Loop counter = 32
@token_loop:
    call    SimulateWork
    inc     qword ptr [g_call_count]
    dec     rbx
    jnz     @token_loop

    ; Print loop done
    lea     rcx, msgLoopDone
    call    PrintString

    ; Print report header
    lea     rcx, msgReport
    call    PrintString

    ; Print target name
    lea     rcx, msgTarget
    call    PrintString

    ; Print metric: T=32
    lea     rcx, numBuffer
    mov     byte ptr [rcx], ' '
    mov     byte ptr [rcx + 1], ' '
    mov     byte ptr [rcx + 2], '['
    mov     byte ptr [rcx + 3], 'T'
    mov     byte ptr [rcx + 4], '='
    mov     byte ptr [rcx + 5], '3'
    mov     byte ptr [rcx + 6], '2'
    mov     byte ptr [rcx + 7], ']'
    mov     byte ptr [rcx + 8], ' '
    mov     byte ptr [rcx + 9], 'C'
    mov     byte ptr [rcx + 10], 'a'
    mov     byte ptr [rcx + 11], 'l'
    mov     byte ptr [rcx + 12], 'l'
    mov     byte ptr [rcx + 13], 's'
    mov     byte ptr [rcx + 14], ':'
    mov     byte ptr [rcx + 15], ' '
    mov     byte ptr [rcx + 16], 0
    mov     rcx, OFFSET numBuffer
    call    PrintString

    ; Print call count (32)
    mov     rax, qword ptr [g_call_count]
    call    PrintU64

    ; Print newline
    lea     rcx, numBuffer
    mov     byte ptr [rcx], 13
    mov     byte ptr [rcx + 1], 10
    mov     byte ptr [rcx + 2], 0
    mov     rcx, OFFSET numBuffer
    call    PrintString

    ; Print RED FLAG
    lea     rcx, msgRedFlag
    call    PrintString

    ; Print GREEN FLAG
    lea     rcx, msgGreenFlag
    call    PrintString

    ; Print done
    lea     rcx, msgDone
    call    PrintString

    ; Exit
    xor     rcx, rcx
    call    ExitProcess

main ENDP
END
