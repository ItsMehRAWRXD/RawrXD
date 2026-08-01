; =============================================================================
; reflection.asm - RawrXD Agentic Reflection / Self-Critique
; =============================================================================
; The Reflection agent analyzes the output of the Coder and Tester agents,
; providing feedback on code quality, correctness, and optimization
; opportunities. It implements a simple rule-based code review system.
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; CONSTANTS
; =============================================================================
MAX_FEEDBACK_LINES      EQU 128
MAX_FEEDBACK_LINE_LEN   EQU 256

; Feedback severity
FEEDBACK_INFO           EQU 0
FEEDBACK_WARNING        EQU 1
FEEDBACK_ERROR          EQU 2
FEEDBACK_CRITICAL       EQU 3

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Feedback buffer
align 64
g_FeedbackBuffer        DB MAX_FEEDBACK_LINES * MAX_FEEDBACK_LINE_LEN DUP(0)
g_FeedbackCount         DQ 0

; Review rules (simplified)
align 8
g_RuleCount             DQ 5

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; Agent_Reflector - Analyze code and produce feedback
;
; Parameters:
;   RCX = void* code_input    - Code to review
;   RDX = QWORD code_length   - Length of code
;   R8  = void* feedback_out  - Output buffer for feedback
;
; Returns: RAX = number of feedback items, or 0 on error
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
    test r8, r8
    jz @@error

    mov rsi, rcx                    ; code_input
    mov r12, rdx                    ; code_length
    mov rdi, r8                     ; feedback_out

    ; Clear feedback buffer
    mov QWORD PTR [g_FeedbackCount], 0

    ; =========================================================================
    ; Rule 1: Check for FRAME directive (ABI compliance)
    ; =========================================================================
    mov rcx, rsi
    lea rdx, szPatternFRAME
    call Agent_FindPattern
    test rax, rax
    jnz @@rule2
    lea rcx, szFeedbackNoFrame
    call Agent_WriteFeedback

@@rule2:
    ; =========================================================================
    ; Rule 2: Check for error handling (error handlers)
    ; =========================================================================
    mov rcx, rsi
    lea rdx, szPatternError
    call Agent_FindPattern
    test rax, rax
    jnz @@rule3
    lea rcx, szFeedbackNoError
    call Agent_WriteFeedback

@@rule3:
    ; =========================================================================
    ; Rule 3: Check for SIMD instructions (AVX2/AVX512)
    ; =========================================================================
    mov rcx, rsi
    lea rdx, szPatternAVX
    call Agent_FindPattern
    test rax, rax
    jnz @@rule4
    lea rcx, szFeedbackNoSIMD
    call Agent_WriteFeedback

@@rule4:
    ; =========================================================================
    ; Rule 4: Check for vzeroupper (AVX state cleanup)
    ; =========================================================================
    mov rcx, rsi
    lea rdx, szPatternVZEROUPPER
    call Agent_FindPattern
    test rax, rax
    jnz @@rule5
    lea rcx, szFeedbackNoVZEROUPPER
    call Agent_WriteFeedback

@@rule5:
    ; =========================================================================
    ; Rule 5: Check for public exports
    ; =========================================================================
    mov rcx, rsi
    lea rdx, szPatternPUBLIC
    call Agent_FindPattern
    test rax, rax
    jnz @@done
    lea rcx, szFeedbackNoPublic
    call Agent_WriteFeedback

@@done:
    ; Copy feedback to output
    mov rcx, g_FeedbackBuffer
    mov rdx, rdi
    mov r8, MAX_FEEDBACK_LINES * MAX_FEEDBACK_LINE_LEN
    call Agent_MemCopy

    mov rax, QWORD PTR [g_FeedbackCount]
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

Agent_Reflector ENDP

; =============================================================================
; Agent_FindPattern - Find a pattern string in code
;
; Parameters:
;   RCX = char* code
;   RDX = char* pattern
;
; Returns: RAX = pointer to match, or NULL
; =============================================================================
Agent_FindPattern PROC PRIVATE FRAME
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
    jz @@not_found
    test rdx, rdx
    jz @@not_found

    mov rsi, rcx                    ; code
    mov rdi, rdx                    ; pattern

@@outer:
    mov al, BYTE PTR [rsi]
    test al, al
    jz @@not_found

    mov rcx, rsi
    mov rdx, rdi

@@inner:
    mov al, BYTE PTR [rdx]
    test al, al
    jz @@found
    mov bl, BYTE PTR [rcx]
    test bl, bl
    jz @@not_found
    ; Case-insensitive comparison
    or al, 20h
    or bl, 20h
    cmp al, bl
    jne @@next_pos
    inc rcx
    inc rdx
    jmp @@inner

@@next_pos:
    inc rsi
    jmp @@outer

@@found:
    mov rax, rsi
    jmp @@exit

@@not_found:
    xor rax, rax

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_FindPattern ENDP

; =============================================================================
; Agent_WriteFeedback - Write a feedback line
; Parameters: RCX = feedback string
; =============================================================================
Agent_WriteFeedback PROC PRIVATE FRAME
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
    mov rdi, QWORD PTR [g_FeedbackCount]
    imul rdi, MAX_FEEDBACK_LINE_LEN
    lea rdi, g_FeedbackBuffer
    add rdi, QWORD PTR [g_FeedbackCount]
    imul rdi, MAX_FEEDBACK_LINE_LEN

@@loop:
    mov al, BYTE PTR [rsi]
    test al, al
    jz @@done
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    jmp @@loop

@@done:
    inc QWORD PTR [g_FeedbackCount]

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

Agent_WriteFeedback ENDP

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
szPatternFRAME          DB 'FRAME', 0
szPatternError          DB 'error', 0
szPatternAVX            DB 'ymm', 0
szPatternVZEROUPPER     DB 'vzeroupper', 0
szPatternPUBLIC         DB 'PUBLIC', 0

szFeedbackNoFrame       DB '[INFO] Missing FRAME directive - ABI compliance recommended', 0Dh, 0Ah, 0
szFeedbackNoError       DB '[WARNING] No error handling detected', 0Dh, 0Ah, 0
szFeedbackNoSIMD        DB '[INFO] No SIMD instructions found - consider AVX2/AVX512', 0Dh, 0Ah, 0
szFeedbackNoVZEROUPPER  DB '[WARNING] Missing vzeroupper - AVX state may leak', 0Dh, 0Ah, 0
szFeedbackNoPublic      DB '[INFO] No PUBLIC exports - module may be inaccessible', 0Dh, 0Ah, 0

END
