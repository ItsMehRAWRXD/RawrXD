; =============================================================================
; SwarmV29_Benchmark_Harness.asm - Performance Validation
; =============================================================================
; Cycle-accurate benchmarking for AZDO operations
; RDTSC/RTDSCP timing, cache flush, memory fence
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_Benchmark_Init
PUBLIC SwarmV29_Benchmark_Start
PUBLIC SwarmV29_Benchmark_Stop
PUBLIC SwarmV29_Benchmark_GetCycles
PUBLIC SwarmV29_Benchmark_GetNanoseconds
PUBLIC SwarmV29_Benchmark_RunSuite
PUBLIC SwarmV29_Benchmark_Report

; =============================================================================
;                            DATA
; =============================================================================
.data

; Benchmark state
ALIGN 64
BenchmarkStart QWORD 0
BenchmarkEnd   QWORD 0
BenchmarkCycles QWORD 0
BenchmarkRuns   QWORD 0

; Calibration data
ALIGN 64
CyclesPerNanosecond QWORD 0
CalibrationCycles QWORD 0
CalibrationNanoseconds QWORD 10000000  ; 10ms calibration

; Benchmark suite results
ALIGN 64
SuiteResults QWORD 16 DUP (<>)
SuiteCount DWORD 0

; Report buffer
ALIGN 64
BenchmarkReport BYTE 2048 DUP (<>)
ReportSize QWORD 0

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_Benchmark_Init
; Initialize benchmark harness and calibrate TSC
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Benchmark_Init PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Calibrate TSC
    ; Measure cycles over 10ms to get cycles/nanosecond
    
    ; Get start time
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r12, rax            ; start cycles
    
    ; Sleep for calibration period (10ms)
    ; Use QueryPerformanceCounter for wall clock time
    sub rsp, 32             ; shadow space
    mov rcx, 10000          ; 10ms
    call Sleep              ; Windows Sleep function
    add rsp, 32
    
    ; Get end time
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r13, rax            ; end cycles
    
    ; Calculate cycles per nanosecond
    sub r13, r12            ; total cycles
    mov QWORD PTR [CalibrationCycles], r13
    
    ; cycles/nanosecond = cycles / nanoseconds
    ; 10ms = 10,000,000 nanoseconds
    mov rax, r13
    xor rdx, rdx
    mov rcx, 10000000       ; 10ms in nanoseconds
    div rcx
    
    mov QWORD PTR [CyclesPerNanosecond], rax
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
SwarmV29_Benchmark_Init ENDP

; =============================================================================
; SwarmV29_Benchmark_Start
; Start benchmark timer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Benchmark_Start PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Serialize CPU (prevent out-of-order execution)
    cpuid
    mfence
    
    ; Get start TSC
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov QWORD PTR [BenchmarkStart], rax
    
    ; Serialize again
    lfence
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
SwarmV29_Benchmark_Start ENDP

; =============================================================================
; SwarmV29_Benchmark_Stop
; Stop benchmark timer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Benchmark_Stop PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Serialize CPU
    lfence
    
    ; Get end TSC
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov QWORD PTR [BenchmarkEnd], rax
    
    ; Serialize again
    mfence
    cpuid
    
    ; Calculate cycles
    mov rax, QWORD PTR [BenchmarkEnd]
    sub rax, QWORD PTR [BenchmarkStart]
    mov QWORD PTR [BenchmarkCycles], rax
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
SwarmV29_Benchmark_Stop ENDP

; =============================================================================
; SwarmV29_Benchmark_GetCycles
; Get elapsed cycles from last benchmark
;
; Returns: RAX = cycles
; =============================================================================
SwarmV29_Benchmark_GetCycles PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov rax, QWORD PTR [BenchmarkCycles]
    
    SWARMV29_ABI_EPILOG
SwarmV29_Benchmark_GetCycles ENDP

; =============================================================================
; SwarmV29_Benchmark_GetNanoseconds
; Get elapsed nanoseconds from last benchmark
;
; Returns: RAX = nanoseconds
; =============================================================================
SwarmV29_Benchmark_GetNanoseconds PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; nanoseconds = cycles / cycles_per_nanosecond
    mov rax, QWORD PTR [BenchmarkCycles]
    xor rdx, rdx
    mov rcx, QWORD PTR [CyclesPerNanosecond]
    test rcx, rcx
    jz @@no_calibration
    
    div rcx
    jmp @@done
    
@@no_calibration:
    ; No calibration, return 0
    xor rax, rax
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Benchmark_GetNanoseconds ENDP

; =============================================================================
; SwarmV29_Benchmark_RunSuite
; Run benchmark suite
;
; RCX = function pointer array
; RDX = function count
; R8  = iterations per function
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Benchmark_RunSuite PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    test rdx, rdx
    jz @@invalid_params
    test r8, r8
    jz @@invalid_params
    
    mov r12, rcx            ; function array
    mov r13, rdx            ; function count
    mov r14, r8             ; iterations
    
    ; Clear suite results
    lea rdi, SuiteResults
    xor eax, eax
    mov ecx, 16 * 2         ; 16 QWORDs * 2 (cycles + nanoseconds)
    rep stosq
    
    mov DWORD PTR [SuiteCount], 0
    
    ; Run each function
    xor ebx, ebx            ; function index
    
@@suite_loop:
    cmp ebx, r13d
    jge @@suite_done
    
    ; Get function pointer
    mov rax, QWORD PTR [r12 + rbx * 8]
    test rax, rax
    jz @@next_function
    
    ; Save context
    push rbx
    push r12
    push r13
    push r14
    
    ; Warmup (1 iteration)
    call rax
    
    ; Start benchmark
    call SwarmV29_Benchmark_Start
    
    ; Run iterations
    mov rcx, r14            ; iterations
    
@@iter_loop:
    test rcx, rcx
    jz @@iter_done
    
    call rax
    
    dec rcx
    jmp @@iter_loop
    
@@iter_done:
    ; Stop benchmark
    call SwarmV29_Benchmark_Stop
    
    ; Restore context
    pop r14
    pop r13
    pop r12
    pop rbx
    
    ; Store result
    mov eax, DWORD PTR [SuiteCount]
    call SwarmV29_Benchmark_GetCycles
    mov SuiteResults[rax * 16], rax
    call SwarmV29_Benchmark_GetNanoseconds
    mov SuiteResults[rax * 16 + 8], rax
    
    inc DWORD PTR [SuiteCount]
    
@@next_function:
    inc ebx
    jmp @@suite_loop
    
@@suite_done:
    xor eax, eax
    jmp @@done
    
@@invalid_params:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Benchmark_RunSuite ENDP

; =============================================================================
; SwarmV29_Benchmark_Report
; Generate benchmark report
;
; RCX = output buffer
; RDX = buffer size
;
; Returns: RAX = bytes written
; =============================================================================
SwarmV29_Benchmark_Report PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    test rdx, rdx
    jz @@invalid_params
    
    mov r12, rcx            ; output buffer
    mov r13, rdx            ; buffer size
    xor r14, r14            ; bytes written
    
    ; Write header
    lea rsi, ReportHeader
    call @@copy_string
    
    ; Write calibration info
    lea rsi, ReportCalibration
    call @@copy_string
    
    mov rax, QWORD PTR [CyclesPerNanosecond]
    call @@append_number
    
    lea rsi, ReportNewline
    call @@copy_string
    
    ; Write suite results
    lea rsi, ReportSuiteHeader
    call @@copy_string
    
    xor ebx, ebx            ; result index
    
@@result_loop:
    mov eax, DWORD PTR [SuiteCount]
    cmp ebx, eax
    jge @@result_done
    
    ; Write result
    lea rsi, ReportResultPrefix
    call @@copy_string
    
    ; Cycles
    mov rax, SuiteResults[rbx * 16]
    call @@append_number
    
    lea rsi, ReportSeparator
    call @@copy_string
    
    ; Nanoseconds
    mov rax, SuiteResults[rbx * 16 + 8]
    call @@append_number
    
    lea rsi, ReportNewline
    call @@copy_string
    
    inc ebx
    jmp @@result_loop
    
@@result_done:
    mov rax, r14
    jmp @@done
    
@@invalid_params:
    mov rax, -1
    jmp @@done
    
; Helper: copy string
@@copy_string:
    push rax
    push rcx
    
    mov rdi, r12
    add rdi, r14
    
@@copy_loop:
    mov al, BYTE PTR [rsi]
    test al, al
    jz @@copy_done
    
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    inc r14
    
    jmp @@copy_loop
    
@@copy_done:
    pop rcx
    pop rax
    ret
    
; Helper: append number
@@append_number:
    push rax
    push rcx
    push rdx
    
    mov rdi, r12
    add rdi, r14
    
    mov ecx, 10
    xor edx, edx
    div ecx
    
    push 0
@@digit_loop:
    xor edx, edx
    div ecx
    add edx, '0'
    push dx
    test eax, eax
    jnz @@digit_loop
    
@@pop_loop:
    pop ax
    test al, al
    jz @@pop_done
    
    mov BYTE PTR [rdi], al
    inc rdi
    inc r14
    
    jmp @@pop_loop
    
@@pop_done:
    pop rdx
    pop rcx
    pop rax
    ret
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Benchmark_Report ENDP

; Report strings
ALIGN 8
ReportHeader BYTE "SwarmV29 Benchmark Report", 0Dh, 0Ah, 0
ReportCalibration BYTE "Cycles/Nanosecond: ", 0
ReportNewline BYTE 0Dh, 0Ah, 0
ReportSuiteHeader BYTE "Suite Results:", 0Dh, 0Ah, 0
ReportResultPrefix BYTE "  ", 0
ReportSeparator BYTE " cycles, ", 0

END