; =============================================================================
; rawrxd_runtime_api.asm - RawrXD Runtime C ABI Implementation
; =============================================================================
; Implements the public C-callable API surface declared in
; rawrxd_runtime_api.inc. This is the single entry point for all
; external callers (sovereign_main.asm, C/C++ wrappers, etc.).
;
; Each function validates parameters, checks runtime state, and
; delegates to the appropriate internal implementation.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE rawrxd_runtime_api.inc
INCLUDE masm_kernel_api.inc

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Runtime state
align 8
g_RuntimeState          DQ RAWRXD_STATE_UNINIT
g_LastError             DB 256 DUP(0)
g_StopRequested         DB 0

; Sampling parameters
align 8
g_SampleTemp            REAL4 0.8
g_SampleTopK            DQ 40
g_SampleTopP            REAL4 0.9

; Error strings
align 8
szNoError               DB 0
szNullPtr               DB 'Null pointer', 0
szInvalidParam          DB 'Invalid parameter', 0
szOOM                   DB 'Out of memory', 0
szNotInit               DB 'Runtime not initialized', 0
szNoModel               DB 'No model loaded', 0
szFileNotFound          DB 'File not found', 0
szBadMagic              DB 'Invalid GGUF magic', 0

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; RawrXD_InitRuntime - Initialize the entire runtime
; =============================================================================
RawrXD_InitRuntime PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 32
    .allocstack 32
    .endprolog

    ; Check if already initialized
    cmp QWORD PTR [g_RuntimeState], RAWRXD_STATE_UNINIT
    jne @@already_init

    ; Initialize kernel registry (CPUID detection + dispatch table)
    call RawrXD_InitKernelRegistry
    test rax, rax
    jnz @@fail

    ; Initialize sampling defaults
    movss xmm0, DWORD PTR [g_SampleTemp]
    movss DWORD PTR [g_SampleTemp], xmm0
    mov QWORD PTR [g_SampleTopK], 40
    movss xmm0, DWORD PTR [g_SampleTopP]
    movss DWORD PTR [g_SampleTopP], xmm0

    ; Set state to initialized
    mov QWORD PTR [g_RuntimeState], RAWRXD_STATE_INIT
    mov BYTE PTR [g_StopRequested], 0

    xor rax, rax
    jmp @@exit

@@already_init:
    xor rax, rax                    ; Already init is not an error
    jmp @@exit

@@fail:
    mov QWORD PTR [g_RuntimeState], RAWRXD_STATE_ERROR
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_InitRuntime ENDP

; =============================================================================
; RawrXD_Shutdown - Shut down the runtime
; =============================================================================
RawrXD_Shutdown PROC FRAME
    .endprolog

    mov QWORD PTR [g_RuntimeState], RAWRXD_STATE_UNINIT
    xor rax, rax
    ret

RawrXD_Shutdown ENDP

; =============================================================================
; RawrXD_GetRuntimeState - Get current runtime state
; =============================================================================
RawrXD_GetRuntimeState PROC FRAME
    .endprolog
    mov rax, QWORD PTR [g_RuntimeState]
    ret
RawrXD_GetRuntimeState ENDP

; =============================================================================
; RawrXD_GetLastError - Get last error message
; =============================================================================
RawrXD_GetLastError PROC FRAME
    .endprolog
    lea rax, g_LastError
    ret
RawrXD_GetLastError ENDP

; =============================================================================
; RawrXD_LoadModel - Load a GGUF model file
; =============================================================================
RawrXD_LoadModel PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@null_ptr

    ; Check runtime state
    cmp QWORD PTR [g_RuntimeState], RAWRXD_STATE_INIT
    jb @@not_init

    ; Delegate to GGUF_Load
    call GGUF_Load
    test rax, rax
    jz @@load_failed

    mov QWORD PTR [g_RuntimeState], RAWRXD_STATE_MODEL_LOADED
    xor rax, rax
    jmp @@exit

@@null_ptr:
    lea rax, szNullPtr
    mov QWORD PTR [g_LastError], rax
    mov rax, RAWRXD_ERR_NULL_PTR
    jmp @@exit

@@not_init:
    lea rax, szNotInit
    mov QWORD PTR [g_LastError], rax
    mov rax, RAWRXD_ERR_INVALID_PARAM
    jmp @@exit

@@load_failed:
    mov QWORD PTR [g_RuntimeState], RAWRXD_STATE_ERROR
    mov rax, RAWRXD_ERR_FILE_NOT_FOUND

@@exit:
    add rsp, 32
    pop rbx
    pop rbp
    ret

RawrXD_LoadModel ENDP

; =============================================================================
; RawrXD_UnloadModel - Unload the current model
; =============================================================================
RawrXD_UnloadModel PROC FRAME
    .endprolog
    mov QWORD PTR [g_RuntimeState], RAWRXD_STATE_INIT
    xor rax, rax
    ret
RawrXD_UnloadModel ENDP

; =============================================================================
; RawrXD_GetModelInfo - Get model metadata
; =============================================================================
RawrXD_GetModelInfo PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; out_buffer
    mov rdi, rdx                    ; buffer_size

    ; Write model info as JSON-like string
    lea rcx, szModelInfo
    mov rdx, rsi
    mov r8, rdi
    call RawrXD_StrCopyBounded

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, RAWRXD_ERR_NULL_PTR

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_GetModelInfo ENDP

; =============================================================================
; RawrXD_SetTemperature - Set sampling temperature
; =============================================================================
RawrXD_SetTemperature PROC FRAME
    .endprolog
    movss DWORD PTR [g_SampleTemp], xmm0
    ret
RawrXD_SetTemperature ENDP

; =============================================================================
; RawrXD_SetTopK - Set top-K sampling parameter
; =============================================================================
RawrXD_SetTopK PROC FRAME
    .endprolog
    mov QWORD PTR [g_SampleTopK], rcx
    ret
RawrXD_SetTopK ENDP

; =============================================================================
; RawrXD_SetTopP - Set top-P sampling parameter
; =============================================================================
RawrXD_SetTopP PROC FRAME
    .endprolog
    movss DWORD PTR [g_SampleTopP], xmm0
    ret
RawrXD_SetTopP ENDP

; =============================================================================
; RawrXD_StopGeneration - Stop an in-progress generation
; =============================================================================
RawrXD_StopGeneration PROC FRAME
    .endprolog
    mov BYTE PTR [g_StopRequested], 1
    xor rax, rax
    ret
RawrXD_StopGeneration ENDP

; =============================================================================
; RawrXD_Benchmark - Run performance benchmark
; =============================================================================
RawrXD_Benchmark PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov r12, rcx                    ; num_iterations
    mov rdi, rdx                    ; out_results

    ; Run tensor create/free benchmark
    xor rsi, rsi
@@bench_loop:
    cmp rsi, r12
    jge @@done

    ; Create a small tensor
    lea rcx, g_BenchShape
    mov rdx, 2
    mov r8d, DTYPE_F32
    call RawrXD_TensorCreate
    test rax, rax
    jz @@error

    ; Free it
    mov rcx, rax
    call RawrXD_TensorFree

    inc rsi
    jmp @@bench_loop

@@done:
    ; Write results
    mov QWORD PTR [rdi], r12       ; iterations completed
    xor rax, rax
    jmp @@exit

@@error:
    mov rax, RAWRXD_ERR_INVALID_PARAM

@@exit:
    add rsp, 32
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

RawrXD_Benchmark ENDP

; =============================================================================
; RawrXD_StrCopyBounded - Bounded string copy
; Parameters: RCX = src, RDX = dst, R8 = max_len
; =============================================================================
RawrXD_StrCopyBounded PROC PRIVATE FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit
    test r8, r8
    jz @@exit

    xor eax, eax
@@loop:
    test r8, r8
    jz @@exit
    mov al, BYTE PTR [rcx]
    mov BYTE PTR [rdx], al
    test al, al
    jz @@exit
    inc rcx
    inc rdx
    dec r8
    jmp @@loop

@@exit:
    ret

RawrXD_StrCopyBounded ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 8
szModelInfo             DB '{ "runtime": "RawrXD MASM", "version": "1.0.0", "arch": "x64" }', 0
g_BenchShape            DQ 64, 64

END
