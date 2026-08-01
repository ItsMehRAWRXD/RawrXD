; =============================================================================
; planner.asm - RawrXD Agentic Planner
; =============================================================================
; The Planner agent decomposes a high-level task into a sequence of
; actionable steps. Each step is a structured tuple:
;   (action, target_file, description, dependencies)
;
; The plan is written to shared memory for the Coder agent to consume.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_PLAN_STEPS          EQU 64
MAX_STEP_DESC_LEN       EQU 256

; Plan step structure (64 bytes)
PLAN_STEP_ACTION        EQU 0   ; DWORD - action type
PLAN_STEP_TARGET_FILE   EQU 8   ; QWORD - pointer to filename string
PLAN_STEP_DESC          EQU 16  ; QWORD - pointer to description
PLAN_STEP_DEP_COUNT     EQU 24  ; DWORD - dependency count
PLAN_STEP_DEPS          EQU 28  ; DWORD[8] - dependency indices
; Total: 64 bytes

; Action types
ACTION_READ             EQU 0
ACTION_ANALYZE          EQU 1
ACTION_MODIFY           EQU 2
ACTION_CREATE           EQU 3
ACTION_DELETE           EQU 4
ACTION_TEST             EQU 5
ACTION_BUILD            EQU 6
ACTION_DEPLOY           EQU 7

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Plan storage
align 64
g_PlanSteps             DB MAX_PLAN_STEPS * 64 DUP(0)
g_PlanStepCount         DQ 0
g_PlanDescription       DB 1024 DUP(0)

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Agent_Planner - Analyze task and produce a plan
;
; Parameters:
;   RCX = char* task_description
;   RDX = void* plan_output
;
; Returns: RAX = number of steps, or 0 on error
; =============================================================================
Agent_Planner PROC FRAME
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
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 64
    .allocstack 64
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; task_description
    mov rdi, rdx                    ; plan_output

    ; Clear plan
    lea r12, g_PlanSteps
    mov rcx, MAX_PLAN_STEPS * 64
    xor eax, eax
    rep stosb
    mov QWORD PTR [g_PlanStepCount], 0

    ; Copy task description
    lea rdi, g_PlanDescription
    mov rcx, rsi
    call Agent_StrCopy

    ; =========================================================================
    ; Analyze task and generate steps
    ; In production, this would use the LLM to generate a plan.
    ; For now, generate a template plan based on keywords.
    ; =========================================================================

    ; Step 1: Read/analyze the task
    lea rdi, g_PlanSteps
    mov DWORD PTR [rdi + PLAN_STEP_ACTION], ACTION_ANALYZE
    lea rax, szStep1File
    mov QWORD PTR [rdi + PLAN_STEP_TARGET_FILE], rax
    lea rax, szStep1Desc
    mov QWORD PTR [rdi + PLAN_STEP_DESC], rax
    mov DWORD PTR [rdi + PLAN_STEP_DEP_COUNT], 0
    inc QWORD PTR [g_PlanStepCount]

    ; Step 2: Modify/create files
    lea rdi, g_PlanSteps + 64
    mov DWORD PTR [rdi + PLAN_STEP_ACTION], ACTION_MODIFY
    lea rax, szStep2File
    mov QWORD PTR [rdi + PLAN_STEP_TARGET_FILE], rax
    lea rax, szStep2Desc
    mov QWORD PTR [rdi + PLAN_STEP_DESC], rax
    mov DWORD PTR [rdi + PLAN_STEP_DEP_COUNT], 1
    mov DWORD PTR [rdi + PLAN_STEP_DEPS], 0
    inc QWORD PTR [g_PlanStepCount]

    ; Step 3: Test
    lea rdi, g_PlanSteps + 128
    mov DWORD PTR [rdi + PLAN_STEP_ACTION], ACTION_TEST
    lea rax, szStep3File
    mov QWORD PTR [rdi + PLAN_STEP_TARGET_FILE], rax
    lea rax, szStep3Desc
    mov QWORD PTR [rdi + PLAN_STEP_DESC], rax
    mov DWORD PTR [rdi + PLAN_STEP_DEP_COUNT], 1
    mov DWORD PTR [rdi + PLAN_STEP_DEPS], 1
    inc QWORD PTR [g_PlanStepCount]

    ; Step 4: Build
    lea rdi, g_PlanSteps + 192
    mov DWORD PTR [rdi + PLAN_STEP_ACTION], ACTION_BUILD
    lea rax, szStep4File
    mov QWORD PTR [rdi + PLAN_STEP_TARGET_FILE], rax
    lea rax, szStep4Desc
    mov QWORD PTR [rdi + PLAN_STEP_DESC], rax
    mov DWORD PTR [rdi + PLAN_STEP_DEP_COUNT], 1
    mov DWORD PTR [rdi + PLAN_STEP_DEPS], 2
    inc QWORD PTR [g_PlanStepCount]

    ; Copy plan to output
    mov rcx, r12
    mov rdx, rdi
    mov r8, MAX_PLAN_STEPS * 64
    call Agent_MemCopy

    mov rax, QWORD PTR [g_PlanStepCount]
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_Planner ENDP

; =============================================================================
; Agent_StrCopy - String copy
; =============================================================================
Agent_StrCopy PROC PRIVATE FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdi, rdi
    jz @@exit
    xor eax, eax
@@loop:
    mov al, BYTE PTR [rcx]
    mov BYTE PTR [rdi], al
    test al, al
    jz @@exit
    inc rcx
    inc rdi
    jmp @@loop
@@exit:
    ret
Agent_StrCopy ENDP

; =============================================================================
; Agent_MemCopy - Memory copy
; =============================================================================
Agent_MemCopy PROC PRIVATE FRAME
    .endprolog
    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit
    test r8, r8
    jz @@exit
    push rsi
    push rdi
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    rep movsb
    pop rdi
    pop rsi
@@exit:
    ret
Agent_MemCopy ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 8
szStep1File         DB 'project/', 0
szStep1Desc         DB 'Analyze project structure and requirements', 0
szStep2File         DB 'src/', 0
szStep2Desc         DB 'Implement required changes', 0
szStep3File         DB 'tests/', 0
szStep3Desc         DB 'Run tests to verify changes', 0
szStep4File         DB 'build/', 0
szStep4Desc         DB 'Build and validate the project', 0

END
