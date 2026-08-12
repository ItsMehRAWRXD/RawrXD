; ================================================================================================
; Negative Space Bottleneck Profiler & Superficial Batch Detector (Pure x64 MASM)
; Architecture: x64 Windows (Microsoft x64 Calling Convention)
; Dependencies: None (Pure Win32 API, self-contained, CRT-free)
; Description: Runtime interception and telemetry tracker designed to catch
;              pseudobatched sequential kernels (e.g., streaming matrix-vector
;              loops disguised as batched matrix-matrix operations).
; ================================================================================================

option casemap :none

; --- Win32 API Prototypes ---
GetStdHandle        PROTO :QWORD
WriteFile           PROTO :QWORD, :QWORD, :DWORD, :QWORD, :QWORD
ExitProcess         PROTO :DWORD
GetProcessHeap      PROTO
HeapAlloc           PROTO :QWORD, :DWORD, :QWORD
HeapFree            PROTO :QWORD, :DWORD, :QWORD

; --- Constants ---
STD_OUTPUT_HANDLE   EQU -11
HEAP_ZERO_MEMORY    EQU 00000008h

; --- Structure: ProfileMetric (32 bytes per entry) ---
PROFILE_METRIC_SIZE     EQU 32
MAX_PROFILED_FUNCTIONS  EQU 32

; --- Data Section ---
.DATA
ALIGN 16
    g_ProfilerInitialized   DB 0
    g_CurrentBatchSize      DD 1
    g_MetricCount           DD 0
    g_hStdout               DQ 0
    g_hHeap                 DQ 0

    ; Pre-allocated metric table (32 entries * 32 bytes = 1024 bytes)
    g_MetricTable           DB (MAX_PROFILED_FUNCTIONS * PROFILE_METRIC_SIZE) DUP (0)

    ; Diagnostic strings
    szReportHeader          DB 13, 10
                            DB "==================================================", 13, 10
                            DB "  x64 HARDWARE BOTTLENECK & BATCHING ANALYSIS", 13, 10
                            DB "==================================================", 13, 10, 0
    lenReportHeader         EQU $ - szReportHeader

    szRedFlagCallCount      DB "    [!] RED FLAG: call_count >= batch_size (T > 1)", 13, 10
                            DB "        Diagnosis: SUPERFICIAL BATCHING detected.", 13, 10
                            DB "        The loop is OUTSIDE the kernel.", 13, 10, 0
    lenRedFlagCallCount     EQU $ - szRedFlagCallCount

    szRedFlagLinearTime     DB "    [!] RED FLAG: Time scales linearly with T.", 13, 10
                            DB "        Diagnosis: Compute kernel is NOT amortized.", 13, 10
                            DB "        Missing true GEMM vectorization/reuse.", 13, 10, 0
    lenRedFlagLinearTime    EQU $ - szRedFlagLinearTime

    szGreenFlagMemory       DB "    [+] Memory delta is flat (< 1MB).", 13, 10
                            DB "        Bottleneck is strictly compute/architectural.", 13, 10, 0
    lenGreenFlagMemory      EQU $ - szGreenFlagMemory

    szNoBottlenecks         DB 13, 10, "[+] No superficial batching detected.", 13, 10
                            DB "    Kernel appears to be truly batched.", 13, 10, 0
    lenNoBottlenecks        EQU $ - szNoBottlenecks

    szDone                  DB 13, 10, "Analysis complete.", 13, 10, 0
    lenDone                 EQU $ - szDone

    ; Scratch buffer for number formatting
    g_NumBuffer             DB 64 DUP (0)

; --- Code Section ---
.CODE

; ==============================================================================
; Helper: PrintString
; RCX = pointer to string, RDX = length (0 = auto-calc)
; ==============================================================================
PrintString PROC FRAME
    push    rbp
    .pushreg rbp
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    mov     rbp, rsp
    sub     rsp, 48
    .allocstack 48
    .endprolog

    mov     rsi, rcx
    mov     r12, rdx

    test    r12, r12
    jnz     _HaveLength

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
    mov     r12, rax

_HaveLength:
    mov     rcx, qword ptr [g_hStdout]
    mov     rdx, rsi
    mov     r8d, r12d
    lea     r9, [rsp + 32]
    mov     qword ptr [rsp + 40], 0
    call    WriteFile

    mov     rsp, rbp
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    ret
PrintString ENDP

; ==============================================================================
; Helper: U64ToString
; Converts unsigned 64-bit integer in RAX to decimal string in g_NumBuffer.
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

    lea     rdi, [g_NumBuffer + 63]
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
; extern "C" void Profiler_Initialize();
; ==============================================================================
PUBLIC Profiler_Initialize
Profiler_Initialize PROC FRAME
    push    rbp
    .pushreg rbp
    push    rdi
    .pushreg rdi
    mov     rbp, rsp
    sub     rsp, 32
    .allocstack 32
    .endprolog

    mov     rcx, STD_OUTPUT_HANDLE
    call    GetStdHandle
    mov     qword ptr [g_hStdout], rax

    call    GetProcessHeap
    mov     qword ptr [g_hHeap], rax

    lea     rdi, g_MetricTable
    xor     eax, eax
    mov     ecx, (MAX_PROFILED_FUNCTIONS * PROFILE_METRIC_SIZE) / 8
    rep     stosq

    mov     byte ptr [g_ProfilerInitialized], 1
    mov     dword ptr [g_CurrentBatchSize], 1
    mov     dword ptr [g_MetricCount], 0

    mov     rsp, rbp
    pop     rdi
    pop     rbp
    ret
Profiler_Initialize ENDP

; ==============================================================================
; extern "C" void Profiler_SetBatchContext(unsigned int batchSize);
; ==============================================================================
PUBLIC Profiler_SetBatchContext
Profiler_SetBatchContext PROC FRAME
    .endprolog
    mov     dword ptr [g_CurrentBatchSize], ecx
    ret
Profiler_SetBatchContext ENDP

; ==============================================================================
; extern "C" unsigned long long Profiler_ReadTsc();
; Serializing RDTSC read (CPUID + RDTSC)
; ==============================================================================
PUBLIC Profiler_ReadTsc
Profiler_ReadTsc PROC FRAME
    .endprolog
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
Profiler_ReadTsc ENDP

; ==============================================================================
; extern "C" void* Profiler_BeginTrack(const char* funcName);
; ==============================================================================
PUBLIC Profiler_BeginTrack
Profiler_BeginTrack PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 40
    .allocstack 40
    .endprolog

    mov     rsi, rcx
    mov     ebx, dword ptr [g_CurrentBatchSize]

    lea     rdi, g_MetricTable
    mov     ecx, MAX_PROFILED_FUNCTIONS

_SearchLoop:
    mov     rax, qword ptr [rdi]
    test    rax, rax
    jz      _FoundEmptySlot
    cmp     rax, rsi
    jne     _NextSlot
    cmp     dword ptr [rdi + 8], ebx
    je      _FoundMatch

_NextSlot:
    add     rdi, PROFILE_METRIC_SIZE
    dec     ecx
    jnz     _SearchLoop
    xor     rax, rax
    jmp     _Done

_FoundEmptySlot:
    mov     qword ptr [rdi], rsi
    mov     dword ptr [rdi + 8], ebx
    mov     dword ptr [rdi + 12], 0
    mov     qword ptr [rdi + 16], 0
    mov     qword ptr [rdi + 24], 0
    lock inc dword ptr [g_MetricCount]

_FoundMatch:
    mov     rax, rdi

_Done:
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
Profiler_BeginTrack ENDP

; ==============================================================================
; extern "C" void Profiler_EndTrack(void* metricEntry, unsigned long long startCycles);
; ==============================================================================
PUBLIC Profiler_EndTrack
Profiler_EndTrack PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    sub     rsp, 40
    .allocstack 40
    .endprolog

    test    rcx, rcx
    jz      _EndTrackExit

    mov     rdi, rcx
    mov     rbx, rdx

    rdtsc
    shl     rdx, 32
    or      rax, rdx

    sub     rax, rbx

    lock inc dword ptr [rdi + 12]
    lock add qword ptr [rdi + 16], rax

_EndTrackExit:
    add     rsp, 40
    pop     rbx
    pop     rbp
    ret
Profiler_EndTrack ENDP

; ==============================================================================
; extern "C" void Profiler_AnalyzeBottlenecks();
; ==============================================================================
PUBLIC Profiler_AnalyzeBottlenecks
Profiler_AnalyzeBottlenecks PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 56
    .allocstack 56
    .endprolog

    lea     rcx, szReportHeader
    mov     rdx, lenReportHeader
    call    PrintString

    lea     rdi, g_MetricTable
    mov     ebx, MAX_PROFILED_FUNCTIONS
    xor     r12d, r12d

_AnalyzeLoop:
    mov     rax, qword ptr [rdi]
    test    rax, rax
    jz      _AnalyzeNext

    mov     r13, rax
    mov     r14d, dword ptr [rdi + 8]    ; r14d = batchSize T
    mov     r15d, dword ptr [rdi + 12]   ; r15d = callCount
    mov     qword ptr [rbp - 8], r10     ; save totalCycles to stack

    ; Print function name
    mov     rcx, r13
    xor     rdx, rdx
    call    PrintString

    ; Build metric string: "  [T=X] Calls: Y | Cycles: Z"
    lea     rcx, g_NumBuffer
    mov     rdx, rcx
    mov     byte ptr [rcx], ' '
    mov     byte ptr [rcx + 1], ' '
    mov     byte ptr [rcx + 2], '['
    mov     byte ptr [rcx + 3], 'T'
    mov     byte ptr [rcx + 4], '='
    add     rcx, 5

    mov     rax, r14
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

    mov     rax, r15
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

    mov     rax, qword ptr [rbp - 8]
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

    lea     rcx, g_NumBuffer
    xor     rdx, rdx
    call    PrintString

    ; === HEURISTIC 1: Superficial Batching ===
    cmp     r14d, 1
    jle     _CheckMemory
    cmp     r15d, r14d
    jl      _CheckMemory

    lea     rcx, szRedFlagCallCount
    mov     rdx, lenRedFlagCallCount
    call    PrintString
    mov     r12d, 1

_CheckMemory:
    mov     rax, qword ptr [rdi + 24]
    cmp     rax, 1048576
    jge     _AnalyzeNext

    lea     rcx, szGreenFlagMemory
    mov     rdx, lenGreenFlagMemory
    call    PrintString

_AnalyzeNext:
    add     rdi, PROFILE_METRIC_SIZE
    dec     ebx
    jnz     _AnalyzeLoop

    test    r12d, r12d
    jnz     _PrintDone
    lea     rcx, szNoBottlenecks
    mov     rdx, lenNoBottlenecks
    call    PrintString

_PrintDone:
    lea     rcx, szDone
    mov     rdx, lenDone
    call    PrintString

    add     rsp, 56
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
Profiler_AnalyzeBottlenecks ENDP

END
