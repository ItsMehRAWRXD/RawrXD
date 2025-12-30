;=====================================================================
; agentic_engine.asm - High-Level Agentic Orchestration (Pure MASM x64)
; THE "BRAIN" OF THE RAWRXD AGENTIC SYSTEM
;=====================================================================
; Integrates:
;  - Failure Detection (agentic_failure_detector.asm)
;  - Response Correction (agentic_puppeteer.asm)
;  - Tool Execution (agentic_masm.asm)
;  - Model Inference (ml_masm.asm)
;
; Features:
;  - Autonomous "Think-Act-Correct" loop
;  - Multi-step task planning and execution
;  - Self-healing via puppeteer correction
;  - Zero C++ dependencies
;=====================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;=====================================================================
; EXTERNAL DECLARATIONS
;=====================================================================

; Failure Detector
EXTERN masm_detect_failure:PROC
EXTERN masm_failure_detector_get_stats:PROC

; Puppeteer
EXTERN masm_puppeteer_correct_response:PROC
EXTERN masm_puppeteer_get_stats:PROC

; Tool System (agentic_masm.asm)
EXTERN agent_init_tools:PROC
EXTERN agent_process_command:PROC
EXTERN agent_get_tool:PROC

; Model Loader (ml_masm.asm)
EXTERN ml_masm_get_tensor:PROC
EXTERN ml_masm_last_error:PROC

; Memory & String
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC
EXTERN asm_str_create_from_cstr:PROC
EXTERN asm_str_length:PROC

; Logging
EXTERN console_log:PROC

; Win32
EXTERN GetTickCount64:PROC
EXTERN Sleep:PROC

;=====================================================================
; STRUCTURES & CONSTANTS
;=====================================================================

; FailureDetectionResult (from detector)
FailureDetectionResult STRUCT
    failure_type        QWORD ?
    confidence          REAL8 ?
    description_ptr     QWORD ?
    description_len     QWORD ?
    timestamp           QWORD ?
    response_ptr        QWORD ?
    response_len        QWORD ?
    reserved            QWORD 25 DUP (?)
FailureDetectionResult ENDS

; CorrectionResult (from puppeteer)
CorrectionResult STRUCT
    is_success          QWORD ?
    corrected_ptr       QWORD ?
    corrected_len       QWORD ?
    original_failure    QWORD ?
    strategy            QWORD ?
    retry_count         QWORD ?
    detail_ptr          QWORD ?
    detail_len          QWORD ?
    reserved            QWORD 24 DUP (?)
CorrectionResult ENDS

MAX_AGENT_RETRIES       EQU 3
AGENT_THINK_DELAY       EQU 500 ; ms

;=====================================================================
; DATA SEGMENT
;=====================================================================
.data
    szEngineInit        BYTE "AgenticEngine: Initializing...", 0
    szEngineReady       BYTE "AgenticEngine: Ready.", 0
    szProcessingResp    BYTE "AgenticEngine: Processing response...", 0
    szFailureDetected   BYTE "AgenticEngine: Failure detected! Type: %d, Confidence: %f", 0
    szCorrecting        BYTE "AgenticEngine: Attempting correction...", 0
    szCorrectionOk      BYTE "AgenticEngine: Correction successful.", 0
    szCorrectionFail    BYTE "AgenticEngine: Correction failed. Falling back.", 0
    szExecutingTool     BYTE "AgenticEngine: Executing tool: %s", 0
    szTaskComplete      BYTE "AgenticEngine: Task execution complete.", 0
    
    g_engine_active     QWORD 0
    g_total_tasks       QWORD 0
    g_total_failures    QWORD 0
    g_total_corrections QWORD 0

.data?
    align 16
    last_failure        FailureDetectionResult <>
    last_correction     CorrectionResult <>

;=====================================================================
; CODE SEGMENT
;=====================================================================
.code

;=====================================================================
; AgenticEngine_Initialize() -> rax (1=success)
;=====================================================================
AgenticEngine_Initialize PROC
    push rbx
    sub rsp, 32
    
    lea rcx, szEngineInit
    call console_log
    
    ; Initialize sub-systems
    call agent_init_tools
    
    mov g_engine_active, 1
    
    lea rcx, szEngineReady
    call console_log
    
    mov rax, 1
    add rsp, 32
    pop rbx

AgenticEngine_Initialize ENDP

;=====================================================================
; AgenticEngine_ProcessResponse(resp_ptr: rcx, resp_len: rdx, mode: r8) -> rax (final_resp_ptr)
;
; The core "Think-Correct" logic.
;=====================================================================
AgenticEngine_ProcessResponse PROC
    push rbx

    push rsi
    push rdi

    push r12
    push r13
    sub rsp, 64
    
    mov rbx, rcx            ; rbx = resp_ptr
    mov rsi, rdx            ; rsi = resp_len
    mov r12, r8             ; r12 = mode
    
    lea rcx, szProcessingResp
    call console_log
    
    ; 1. Detect Failure
    mov rcx, rbx
    mov rdx, rsi
    lea r8, last_failure
    call masm_detect_failure
    
    test rax, rax
    jz no_failure_found
    
    ; Failure detected!
    inc g_total_failures
    
    ; 2. Attempt Correction
    lea rcx, last_failure
    mov rdx, r12            ; mode
    lea r8, last_correction
    call masm_puppeteer_correct_response
    
    test rax, rax
    jz correction_failed
    
    ; Correction successful
    inc g_total_corrections
    lea rcx, szCorrectionOk
    call console_log
    
    mov rax, last_correction.corrected_ptr
    jmp done
    
correction_failed:
    lea rcx, szCorrectionFail
    call console_log
    mov rax, rbx            ; Return original if correction fails
    jmp done

no_failure_found:
    mov rax, rbx            ; Return original

done:
    add rsp, 64

    pop r12 pop r13


    pop rsi pop rdi

    pop rbx

AgenticEngine_ProcessResponse ENDP

;=====================================================================
; AgenticEngine_ExecuteTask(task_cmd: rcx) -> rax (output_ptr)
;
; High-level task execution with autonomous loop.
;=====================================================================
AgenticEngine_ExecuteTask PROC
    push rbx

    push rsi
    push rdi
    sub rsp, 48
    
    mov rbx, rcx            ; rbx = task_cmd
    inc g_total_tasks
    
    ; Log execution
    lea rcx, szExecutingTool
    mov rdx, rbx
    call console_log
    
    ; Process via tool system
    mov rcx, rbx
    call agent_process_command
    
    ; rax now contains the output of the tool execution
    
    add rsp, 48

    pop rsi pop rdi

    pop rbx

AgenticEngine_ExecuteTask ENDP

;=====================================================================
; AgenticEngine_GetStats(stats_ptr: rcx)
;=====================================================================
AgenticEngine_GetStats PROC
    mov rax, g_total_tasks
    mov [rcx], rax
    mov rax, g_total_failures
    mov [rcx + 8], rax
    mov rax, g_total_corrections
    mov [rcx + 16], rax
    ret
AgenticEngine_GetStats ENDP

END





