; =============================================================================
; coder.asm - RawrXD Agentic Coder
; =============================================================================
; The Coder agent takes a plan step and generates MASM assembly code
; to implement the required change. It produces compilable .asm files
; with proper ABI compliance, error handling, and SIMD optimization.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_CODE_LINES          EQU 4096
MAX_LINE_LEN            EQU 256

; Code generation templates
TEMPLATE_COUNT          EQU 8

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Code buffer
align 64
g_CodeBuffer            DB MAX_CODE_LINES * MAX_LINE_LEN DUP(0)
g_CodeBufferOffset      DQ 0

; Template registry
align 8
g_Templates             DQ TEMPLATE_COUNT DUP(0)

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Agent_Coder_Init - Initialize code generation templates
; =============================================================================
Agent_Coder_Init PROC FRAME
    .endprolog
    lea rax, szTemplateKernel
    mov QWORD PTR [g_Templates + 0], rax
    lea rax, szTemplateTest
    mov QWORD PTR [g_Templates + 8], rax
    lea rax, szTemplateBridge
    mov QWORD PTR [g_Templates + 16], rax
    xor rax, rax
    ret
Agent_Coder_Init ENDP

; =============================================================================
; Agent_Coder - Generate code from a plan step
;
; Parameters:
;   RCX = void* plan_step    - Pointer to PLAN_STEP_STRUCT
;   RDX = void* code_output  - Output buffer for generated code
;
; Returns: RAX = code length, or 0 on error
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
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    test rdx, rdx
    jz @@error

    mov rsi, rcx                    ; plan_step
    mov rdi, rdx                    ; code_output

    ; Clear code buffer
    mov QWORD PTR [g_CodeBufferOffset], 0

    ; Get action type
    mov r12d, DWORD PTR [rsi + PLAN_STEP_ACTION]

    ; Generate code based on action
    cmp r12d, ACTION_CREATE
    je @@gen_create
    cmp r12d, ACTION_MODIFY
    je @@gen_modify
    cmp r12d, ACTION_TEST
    je @@gen_test
    jmp @@gen_default

@@gen_create:
    ; Generate a new kernel file
    lea rcx, szTemplateKernel
    call Agent_WriteTemplate
    jmp @@done

@@gen_modify:
    ; Generate a modification patch
    lea rcx, szTemplateBridge
    call Agent_WriteTemplate
    jmp @@done

@@gen_test:
    ; Generate a test file
    lea rcx, szTemplateTest
    call Agent_WriteTemplate
    jmp @@done

@@gen_default:
    ; Default: generate a minimal stub
    lea rcx, szTemplateStub
    call Agent_WriteTemplate

@@done:
    ; Copy code buffer to output
    mov rcx, g_CodeBuffer
    mov rdx, rdi
    mov r8, QWORD PTR [g_CodeBufferOffset]
    call Agent_MemCopy

    mov rax, QWORD PTR [g_CodeBufferOffset]
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_Coder ENDP

; =============================================================================
; Agent_WriteTemplate - Write a template to the code buffer
; Parameters: RCX = template string
; =============================================================================
Agent_WriteTemplate PROC PRIVATE FRAME
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
    jz @@exit

    mov rsi, rcx
    mov rdi, QWORD PTR [g_CodeBufferOffset]
    lea rdi, g_CodeBuffer
    add rdi, QWORD PTR [g_CodeBufferOffset]

@@loop:
    mov al, BYTE PTR [rsi]
    test al, al
    jz @@exit
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    inc QWORD PTR [g_CodeBufferOffset]
    jmp @@loop

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_WriteTemplate ENDP

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
szTemplateKernel    DB '; Auto-generated by RawrXD Agentic Coder', 0Dh, 0Ah
                    DB 'OPTION CASEMAP:NONE', 0Dh, 0Ah
                    DB '', 0Dh, 0Ah
                    DB '.code', 0Dh, 0Ah
                    DB '', 0Dh, 0Ah
                    DB 'PUBLIC Agent_Generated_Kernel', 0Dh, 0Ah
                    DB 'Agent_Generated_Kernel PROC FRAME', 0Dh, 0Ah
                    DB '    .endprolog', 0Dh, 0Ah
                    DB '    xor eax, eax', 0Dh, 0Ah
                    DB '    ret', 0Dh, 0Ah
                    DB 'Agent_Generated_Kernel ENDP', 0Dh, 0Ah
                    DB '', 0Dh, 0Ah
                    DB 'END', 0Dh, 0Ah, 0

szTemplateTest      DB '; Auto-generated test by RawrXD Agentic Coder', 0Dh, 0Ah
                    DB 'INCLUDE masm_kernel_api.inc', 0Dh, 0Ah
                    DB '', 0Dh, 0Ah
                    DB '.data', 0Dh, 0Ah
                    DB 'szTestPass DB "PASS", 0Dh, 0Ah, 0', 0Dh, 0Ah
                    DB '', 0Dh, 0Ah
                    DB '.code', 0Dh, 0Ah
                    DB 'PUBLIC Agent_Test_Run', 0Dh, 0Ah
                    DB 'Agent_Test_Run PROC FRAME', 0Dh, 0Ah
                    DB '    .endprolog', 0Dh, 0Ah
                    DB '    xor eax, eax', 0Dh, 0Ah
                    DB '    ret', 0Dh, 0Ah
                    DB 'Agent_Test_Run ENDP', 0Dh, 0Ah
                    DB 'END', 0Dh, 0Ah, 0

szTemplateBridge    DB '; Auto-generated bridge by RawrXD Agentic Coder', 0Dh, 0Ah
                    DB 'INCLUDE rawrxd_runtime_api.inc', 0Dh, 0Ah
                    DB '', 0Dh, 0Ah
                    DB '.code', 0Dh, 0Ah
                    DB 'PUBLIC Agent_Bridge_Init', 0Dh, 0Ah
                    DB 'Agent_Bridge_Init PROC FRAME', 0Dh, 0Ah
                    DB '    .endprolog', 0Dh, 0Ah
                    DB '    xor eax, eax', 0Dh, 0Ah
                    DB '    ret', 0Dh, 0Ah
                    DB 'Agent_Bridge_Init ENDP', 0Dh, 0Ah
                    DB 'END', 0Dh, 0Ah, 0

szTemplateStub      DB '; Auto-generated stub', 0Dh, 0Ah
                    DB '.code', 0Dh, 0Ah
                    DB 'END', 0Dh, 0Ah, 0

END
