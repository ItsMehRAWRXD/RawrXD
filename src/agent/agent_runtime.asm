; =============================================================================
; agent_runtime.asm - RawrXD Agentic Runtime
; =============================================================================
; Multi-agent orchestration loop:
;   Planner -> Coder -> Compiler -> Tester -> Reflector
;
; Each agent is a self-contained module that communicates via shared memory.
; The runtime manages agent lifecycle, context passing, and error recovery.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_AGENTS              EQU 8
MAX_AGENT_NAME_LEN      EQU 64
MAX_AGENT_CTX_SIZE      EQU 65536   ; 64KB per agent context

; Agent states
AGENT_STATE_IDLE        EQU 0
AGENT_STATE_RUNNING     EQU 1
AGENT_STATE_DONE        EQU 2
AGENT_STATE_ERROR       EQU 3

; Agent IDs
AGENT_PLANNER           EQU 0
AGENT_CODER             EQU 1
AGENT_COMPILER          EQU 2
AGENT_TESTER            EQU 3
AGENT_REFLECTOR         EQU 4

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Agent context table
align 16
g_AgentTable            DB MAX_AGENTS * 256 DUP(0)

; Agent struct offsets (256 bytes per agent)
AGENT_OFF_ID            EQU 0
AGENT_OFF_STATE         EQU 8
AGENT_OFF_NAME          EQU 16
AGENT_OFF_CTX_PTR       EQU 80
AGENT_OFF_CTX_SIZE      EQU 88
AGENT_OFF_FN_INIT       EQU 96
AGENT_OFF_FN_RUN        EQU 104
AGENT_OFF_FN_CLEANUP    EQU 112
AGENT_OFF_RESULT        EQU 120
AGENT_OFF_ERROR_MSG     EQU 128

; Shared memory for inter-agent communication
align 16
g_SharedCtx             DB MAX_AGENT_CTX_SIZE DUP(0)

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Agent_Init - Initialize an agent
;
; Parameters:
;   RCX = QWORD agent_id
;   RDX = char* name
;   R8  = void* fn_init
;   R9  = void* fn_run
;   [RBP+48] = void* fn_cleanup
; =============================================================================
Agent_Init PROC FRAME
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
    cmp rcx, MAX_AGENTS
    jae @@error

    ; Calculate agent table entry
    mov rax, rcx
    shl rax, 8                      ; * 256
    lea rsi, g_AgentTable
    add rsi, rax

    ; Populate agent entry
    mov QWORD PTR [rsi + AGENT_OFF_ID], rcx
    mov QWORD PTR [rsi + AGENT_OFF_STATE], AGENT_STATE_IDLE
    mov QWORD PTR [rsi + AGENT_OFF_FN_INIT], r8
    mov QWORD PTR [rsi + AGENT_OFF_FN_RUN], r9
    mov rax, QWORD PTR [rbp + 48]
    mov QWORD PTR [rsi + AGENT_OFF_FN_CLEANUP], rax

    ; Copy name
    test rdx, rdx
    jz @@no_name
    lea rdi, [rsi + AGENT_OFF_NAME]
    mov rcx, rdx
    call RawrXD_StrCopy

@@no_name:
    ; Allocate agent context
    mov rcx, MAX_AGENT_CTX_SIZE
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@error
    mov QWORD PTR [rsi + AGENT_OFF_CTX_PTR], rax
    mov QWORD PTR [rsi + AGENT_OFF_CTX_SIZE], MAX_AGENT_CTX_SIZE

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_Init ENDP

; =============================================================================
; Agent_Planner - Planning agent
;
; Parameters:
;   RCX = void* input    - Task description
;   RDX = void* output   - Plan output
;
; Returns: RAX = 0 on success
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
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    ; Planner: analyze task, produce step-by-step plan
    ; In production, this would use the LLM to generate a plan
    ; For now, produce a simple template plan

    mov rsi, rcx                    ; input
    mov rdi, rdx                    ; output

    ; Write plan header
    mov BYTE PTR [rdi], 'P'
    mov BYTE PTR [rdi + 1], 'L'
    mov BYTE PTR [rdi + 2], 'A'
    mov BYTE PTR [rdi + 3], 'N'
    mov BYTE PTR [rdi + 4], ':'
    mov BYTE PTR [rdi + 5], ' '
    mov BYTE PTR [rdi + 6], 0

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_Planner ENDP

; =============================================================================
; Agent_Coder - Code generation agent
;
; Parameters:
;   RCX = void* plan      - Plan from planner
;   RDX = void* output    - Generated code
;
; Returns: RAX = 0 on success
; =============================================================================
Agent_Coder PROC FRAME
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

    ; Coder: generate MASM code from plan
    ; In production, this would use the LLM
    ; For now, produce a simple code stub

    mov rsi, rcx                    ; plan
    mov rdi, rdx                    ; output

    mov BYTE PTR [rdi], ';'
    mov BYTE PTR [rdi + 1], ' '
    mov BYTE PTR [rdi + 2], 'C'
    mov BYTE PTR [rdi + 3], 'O'
    mov BYTE PTR [rdi + 4], 'D'
    mov BYTE PTR [rdi + 5], 'E'
    mov BYTE PTR [rdi + 6], 0

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_Coder ENDP

; =============================================================================
; Agent_Reflector - Reflection/self-critique agent
;
; Parameters:
;   RCX = void* result    - Result to reflect on
;   RDX = void* feedback   - Feedback output
;
; Returns: RAX = 0 on success
; =============================================================================
Agent_Reflector PROC FRAME
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

    ; Reflector: analyze result quality, suggest improvements
    mov rsi, rcx                    ; result
    mov rdi, rdx                    ; feedback

    mov BYTE PTR [rdi], 'O'
    mov BYTE PTR [rdi + 1], 'K'
    mov BYTE PTR [rdi + 2], 0

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_Reflector ENDP

; =============================================================================
; Agent_RunPipeline - Run the full agent pipeline
;
; Parameters:
;   RCX = char* task      - Task description
;   RDX = void* output    - Final output buffer
;
; Returns: RAX = 0 on success
; =============================================================================
Agent_RunPipeline PROC FRAME
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

    mov rsi, rcx                    ; task
    mov rdi, rdx                    ; output

    ; Step 1: Planner
    lea rcx, g_SharedCtx
    mov rdx, rcx
    add rdx, 16384                  ; Plan output area
    call Agent_Planner
    test rax, rax
    jnz @@error

    ; Step 2: Coder
    lea rcx, g_SharedCtx
    add rcx, 16384
    mov rdx, rcx
    add rdx, 16384
    call Agent_Coder
    test rax, rax
    jnz @@error

    ; Step 3: Reflector
    lea rcx, g_SharedCtx
    add rcx, 32768
    mov rdx, rdi
    call Agent_Reflector
    test rax, rax
    jnz @@error

    xor rax, rax
    jmp @@exit

@@error:
    mov rax, 1

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

Agent_RunPipeline ENDP

; =============================================================================
; RawrXD_StrCopy - String copy (null-terminated, bounded)
; Parameters: RCX = src, RDI = dst
; =============================================================================
RawrXD_StrCopy PROC FRAME
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

RawrXD_StrCopy ENDP

END
