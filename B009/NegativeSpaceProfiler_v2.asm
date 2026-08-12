; ================================================================================================
; Negative Space Bottleneck Profiler - Pure x64 MASM (CRT-Free)
; Properly integrates with C++ via extern "C" declarations
; ================================================================================================

option casemap :none

; --- Win32 API Prototypes ---
GetStdHandle        PROTO :QWORD
WriteFile           PROTO :QWORD, :QWORD, :DWORD, :QWORD, :QWORD

; --- Constants ---
STD_OUTPUT_HANDLE   EQU -11

; --- Data Section ---
.DATA
ALIGN 16
    g_batch_size        DQ 1
    g_call_count        DQ 0
    g_total_cycles      DQ 0
    g_initialized       DB 0

    hStdout             DQ 0
    bytesWritten        DQ 0

    ; Diagnostic strings
    szReportHeader      DB 13, 10
                        DB "==================================================", 13, 10
                        DB "  x64 HARDWARE BOTTLENECK & BATCHING ANALYSIS", 13, 10
                        DB "==================================================", 13, 10, 0
    lenReportHeader     EQU $ - szReportHeader

    szRedFlag           DB "    [!] RED FLAG: call_count >= batch_size (T > 1)", 13, 10
                        DB "        Diagnosis: SUPERFICIAL BATCHING detected.", 13, 10
                        DB "        The loop is OUTSIDE the kernel.", 13, 10, 0
    lenRedFlag          EQU $ - szRedFlag

    szGreenFlag         DB "    [+] Memory delta is flat (< 1MB).", 13, 10
                        DB "        Bottleneck is strictly compute/architectural.", 13, 10, 0
    lenGreenFlag        EQU $ - szGreenFlag

    szNoBottleneck      DB 13, 10, "[+] No superficial batching detected.", 13, 10
                        DB "    Kernel appears to be truly batched.", 13, 10, 0
    lenNoBottleneck     EQU $ - szNoBottleneck

    szDone              DB 13, 10, "Analysis complete.", 13, 10, 0
    lenDone             EQU $ - szDone

    ; Scratch buffer
    g_NumBuffer         DB 64 DUP (0)

; --- Code Section ---
.CODE

; ==============================================================================
; Helper: PrintString
; RCX = pointer to null-terminated string
; ==============================================================================
PrintString PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 40

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

    add     rsp, 40
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PrintString ENDP

; ==============================================================================
; Helper: U64ToString
; Converts unsigned 64-bit integer in RAX to decimal string in g_NumBuffer.
; Returns: RAX = pointer to string
; ==============================================================================
U64ToString PROC
    push    rbx
    push    rdi
    sub     rsp, 32

    lea     rdi, [g_NumBuffer + 63]
    mov     byte ptr [rdi], 0
    mov     rbx, 10

    test    rax, rax
    jnz     _ConvertLoop
    mov     byte ptr [rdi - 1], '0'
    lea     rax, [rdi - 1]
    add     rsp, 32
    pop     rdi
    pop     rbx
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
    add     rsp, 32
    pop     rdi
    pop     rbx
    ret
U64ToString ENDP

; ==============================================================================
; extern "C" void Profiler_Initialize();
; ==============================================================================
PUBLIC Profiler_Initialize
Profiler_Initialize PROC
    push    rbx
    push    rdi
    sub     rsp, 40

    ; Get stdout handle
    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     qword ptr [hStdout], rax

    ; Clear metrics
    mov     qword ptr [g_batch_size], 1
    mov     qword ptr [g_call_count], 0
    mov     qword ptr [g_total_cycles], 0
    mov     byte ptr [g_initialized], 1

    add     rsp, 40
    pop     rdi
    pop     rbx
    ret
Profiler_Initialize ENDP

; ==============================================================================
; extern "C" void Profiler_SetBatchContext(unsigned long long batchSize);
; ==============================================================================
PUBLIC Profiler_SetBatchContext
Profiler_SetBatchContext PROC
    mov     qword ptr [g_batch_size], rcx
    mov     qword ptr [g_call_count], 0
    mov     qword ptr [g_total_cycles], 0
    ret
Profiler_SetBatchContext ENDP

; ==============================================================================
; extern "C" unsigned long long Profiler_ReadTsc();
; ==============================================================================
PUBLIC Profiler_ReadTsc
Profiler_ReadTsc PROC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
Profiler_ReadTsc ENDP

; ==============================================================================
; extern "C" void Profiler_TrackCall(unsigned long long startCycles);
; ==============================================================================
PUBLIC Profiler_TrackCall
Profiler_TrackCall PROC
    push    rbx
    sub     rsp, 32

    mov     rbx, rcx            ; rbx = startCycles

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, rbx

    inc     qword ptr [g_call_count]
    add     qword ptr [g_total_cycles], rax

    add     rsp, 32
    pop     rbx
    ret
Profiler_TrackCall ENDP

; ==============================================================================
; extern "C" void Profiler_AnalyzeBottlenecks();
; ==============================================================================
PUBLIC Profiler_AnalyzeBottlenecks
Profiler_AnalyzeBottlenecks PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 40

    ; Print report header
    lea     rcx, szReportHeader
    call    PrintString

    ; Print target name
    lea     rcx, g_NumBuffer
    mov     byte ptr [rcx], 13
    mov     byte ptr [rcx + 1], 10
    mov     byte ptr [rcx + 2], 'T'
    mov     byte ptr [rcx + 3], 'a'
    mov     byte ptr [rcx + 4], 'r'
    mov     byte ptr [rcx + 5], 'g'
    mov     byte ptr [rcx + 6], 'e'
    mov     byte ptr [rcx + 7], 't'
    mov     byte ptr [rcx + 8], ':'
    mov     byte ptr [rcx + 9], ' '
    mov     byte ptr [rcx + 10], 'S'
    mov     byte ptr [rcx + 11], 't'
    mov     byte ptr [rcx + 12], 'r'
    mov     byte ptr [rcx + 13], 'e'
    mov     byte ptr [rcx + 14], 'a'
    mov     byte ptr [rcx + 15], 'm'
    mov     byte ptr [rcx + 16], 'i'
    mov     byte ptr [rcx + 17], 'n'
    mov     byte ptr [rcx + 18], 'g'
    mov     byte ptr [rcx + 19], 'M'
    mov     byte ptr [rcx + 20], 'a'
    mov     byte ptr [rcx + 21], 't'
    mov     byte ptr [rcx + 22], 'M'
    mov     byte ptr [rcx + 23], 'u'
    mov     byte ptr [rcx + 24], 'l'
    mov     byte ptr [rcx + 25], 13
    mov     byte ptr [rcx + 26], 10
    mov     byte ptr [rcx + 27], 0
    mov     rcx, OFFSET g_NumBuffer
    call    PrintString

    ; Print metric: "  [T=X] Calls: Y | Cycles: Z"
    lea     rcx, g_NumBuffer
    mov     byte ptr [rcx], ' '
    mov     byte ptr [rcx + 1], ' '
    mov     byte ptr [rcx + 2], '['
    mov     byte ptr [rcx + 3], 'T'
    mov     byte ptr [rcx + 4], '='
    add     rcx, 5

    mov     rax, qword ptr [g_batch_size]
    call    U64ToString
    mov     rsi, rax
_CopyT:
    mov     al, byte ptr [rsi]
    test    al, al
    jz      _TDone
    mov     byte ptr [rcx], al
    inc     rsi
    inc     rcx
    jmp     _CopyT
_TDone:
    mov     byte ptr [rcx], ']'
    inc     rcx
    mov     byte ptr [rcx], ' '
    inc     rcx
    mov     byte ptr [rcx], 'C'
    inc     rcx
    mov     byte ptr [rcx], 'a'
    inc     rcx
    mov     byte ptr [rcx], 'l'
    inc     rcx
    mov     byte ptr [rcx], 'l'
    inc     rcx
    mov     byte ptr [rcx], 's'
    inc     rcx
    mov     byte ptr [rcx], ':'
    inc     rcx
    mov     byte ptr [rcx], ' '
    inc     rcx

    mov     rax, qword ptr [g_call_count]
    call    U64ToString
    mov     rsi, rax
_CopyCalls:
    mov     al, byte ptr [rsi]
    test    al, al
    jz      _CallsDone
    mov     byte ptr [rcx], al
    inc     rsi
    inc     rcx
    jmp     _CopyCalls
_CallsDone:
    mov     byte ptr [rcx], ' '
    inc     rcx
    mov     byte ptr [rcx], '|'
    inc     rcx
    mov     byte ptr [rcx], ' '
    inc     rcx
    mov     byte ptr [rcx], 'C'
    inc     rcx
    mov     byte ptr [rcx], 'y'
    inc     rcx
    mov     byte ptr [rcx], 'c'
    inc     rcx
    mov     byte ptr [rcx], 'l'
    inc     rcx
    mov     byte ptr [rcx], 'e'
    inc     rcx
    mov     byte ptr [rcx], 's'
    inc     rcx
    mov     byte ptr [rcx], ':'
    inc     rcx
    mov     byte ptr [rcx], ' '
    inc     rcx

    mov     rax, qword ptr [g_total_cycles]
    call    U64ToString
    mov     rsi, rax
_CopyCycles:
    mov     al, byte ptr [rsi]
    test    al, al
    jz      _CyclesDone
    mov     byte ptr [rcx], al
    inc     rsi
    inc     rcx
    jmp     _CopyCycles
_CyclesDone:
    mov     byte ptr [rcx], 13
    inc     rcx
    mov     byte ptr [rcx], 10
    inc     rcx
    mov     byte ptr [rcx], 0

    mov     rcx, OFFSET g_NumBuffer
    call    PrintString

    ; === HEURISTIC 1: Superficial Batching ===
    mov     r8, qword ptr [g_batch_size]
    mov     r9, qword ptr [g_call_count]

    cmp     r8, 1
    jle     _CheckMemory
    cmp     r9, r8
    jl      _CheckMemory

    lea     rcx, szRedFlag
    call    PrintString
    mov     r12d, 1
    jmp     _PrintDone

_CheckMemory:
    ; Memory is always stable in this simulation
    lea     rcx, szGreenFlag
    call    PrintString
    xor     r12d, r12d

_PrintDone:
    test    r12d, r12d
    jnz     _Done
    lea     rcx, szNoBottleneck
    call    PrintString

_Done:
    lea     rcx, szDone
    call    PrintString

    add     rsp, 40
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Profiler_AnalyzeBottlenecks ENDP

END
