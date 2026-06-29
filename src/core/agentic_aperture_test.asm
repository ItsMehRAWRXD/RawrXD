; ============================================================================
; agentic_aperture_test.asm — Aperture Integration Test Harness
; ============================================================================
;
; Tests the full integration: Agentic Core + Aperture Bridge + Prompt Parser
; This replaces the basic tests with full inference simulation.
;
; Build: ml64.exe /c agentic_aperture_test.asm
; Link:  link.exe agentic_sovereign_entry.obj agentic_aperture_bridge.obj agentic_aperture_test.obj aperture_q4_0_avx512_v2.obj
;
; ============================================================================

; ============================================================================
; External Imports
; ============================================================================

EXTERN Print : PROC
EXTERN PrintString : PROC
EXTERN PrintNewline : PROC
EXTERN PrintNumber : PROC
EXTERN Agentic_Init : PROC
EXTERN Agentic_SetTask : PROC
EXTERN Agentic_Shutdown : PROC
EXTERN Agentic_RunStep_WithAperture : PROC
EXTERN ParseDecision : PROC
EXTERN Aperture_Inference : PROC
EXTERN agent_state : DWORD
EXTERN step_count : DWORD

EXTERN ExitProcess : PROC
EXTERN Sleep : PROC

; ============================================================================
; Constants
; ============================================================================

AGENT_STATE_IDLE         equ 0
AGENT_STATE_THINKING     equ 1
AGENT_STATE_EXECUTING    equ 2
AGENT_STATE_COMPLETE     equ 3
AGENT_STATE_ERROR        equ 4

; ============================================================================
; Data Section
; ============================================================================

.data

; Test prompts
test_prompt_1           db "What is the current time?", 0
test_prompt_2           db "List the files in the current directory", 0
test_prompt_3           db "Calculate 123 multiplied by 456", 0

; Response buffer
response_buffer         db 4096 dup(0)

; Messages
banner_aperture         db "===================================================================", 13, 10
                        db "  RawrXD Agentic + Aperture Integration Test", 13, 10
                        db "  Full Stack: State Machine + Inference + Parser", 13, 10
                        db "===================================================================", 13, 10
banner_aperture_len     equ $ - banner_aperture

test_header_1           db 13, 10, "=== Test 1: Time Query (Aperture Integration) ===", 13, 10
test_header_1_len     equ $ - test_header_1

test_header_2           db 13, 10, "=== Test 2: Directory Listing (Aperture Integration) ===", 13, 10
test_header_2_len     equ $ - test_header_2

test_header_3           db 13, 10, "=== Test 3: Calculation (Aperture Integration) ===", 13, 10
test_header_3_len     equ $ - test_header_3

msg_prompt              db "[TEST] Prompt: ", 0
msg_inference           db "[APERTURE] Running inference...", 13, 10
msg_inference_len       equ $ - msg_inference

msg_parsing             db "[PARSER] Parsing decision markers...", 13, 10
msg_parsing_len         equ $ - msg_parsing

msg_marker_think        db "[RESULT] THINK marker detected", 13, 10
msg_marker_think_len    equ $ - msg_marker_think

msg_marker_act          db "[RESULT] ACT marker detected", 13, 10
msg_marker_act_len      equ $ - msg_marker_act

msg_marker_done         db "[RESULT] DONE marker detected", 13, 10
msg_marker_done_len     equ $ - msg_marker_done

msg_response            db "[RESPONSE] ", 0

msg_complete            db 13, 10, "[TEST] All Aperture integration tests passed!", 13, 10
msg_complete_len        equ $ - msg_complete

msg_separator           db "----------------------------------------", 13, 10
msg_separator_len       equ $ - msg_separator

; ============================================================================
; Code Section
; ============================================================================

.code

; ============================================================================
; Test Functions
; ============================================================================

; void Run_Aperture_Test(const char* prompt, const char* test_name)
; RCX = prompt, RDX = test name
Run_Aperture_Test proc
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 40
    
    mov rdi, rcx                ; prompt
    mov r12, rdx                ; test name
    
    ; Print test header
    mov rcx, r12
    call PrintString
    
    ; Print prompt
    lea rcx, [msg_prompt]
    call PrintString
    mov rcx, rdi
    call PrintString
    call PrintNewline
    
    ; Initialize agentic state
    call Agentic_Init
    mov rcx, rdi
    call Agentic_SetTask
    
    ; Run agentic loop with Aperture
    mov ebx, 0
@@step_loop:
    inc ebx
    
    ; Print step info
    call PrintNewline
    lea rcx, [msg_separator]
    mov rdx, msg_separator_len
    call Print
    
    ; Run step with Aperture
    call Agentic_RunStep_WithAperture
    
    ; Check state
    mov eax, [agent_state]
    cmp eax, AGENT_STATE_COMPLETE
    je @@complete
    cmp eax, AGENT_STATE_ERROR
    je @@error
    
    cmp ebx, 10
    jl @@step_loop
    
@@complete:
    call PrintNewline
    jmp @@done
    
@@error:
    call PrintNewline
    
@@done:
    add rsp, 40
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
Run_Aperture_Test endp

; ============================================================================
; Main Entry Point
; ============================================================================

AgenticApertureMain proc
    sub rsp, 40
    
    ; Print banner
    lea rcx, [banner_aperture]
    mov rdx, banner_aperture_len
    call Print
    call PrintNewline
    
    ; Test 1: Time Query
    lea rcx, [test_header_1]
    mov rdx, test_header_1_len
    call Print
    lea rcx, [test_prompt_1]
    lea rdx, [test_header_1]
    call Run_Aperture_Test
    
    ; Test 2: Directory Listing
    lea rcx, [test_header_2]
    mov rdx, test_header_2_len
    call Print
    lea rcx, [test_prompt_2]
    lea rdx, [test_header_2]
    call Run_Aperture_Test
    
    ; Test 3: Calculation
    lea rcx, [test_header_3]
    mov rdx, test_header_3_len
    call Print
    lea rcx, [test_prompt_3]
    lea rdx, [test_header_3]
    call Run_Aperture_Test
    
    ; Print completion
    lea rcx, [msg_complete]
    mov rdx, msg_complete_len
    call Print
    
    ; Shutdown
    call Agentic_Shutdown
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 40
    ret
AgenticApertureMain endp

; ============================================================================
; Export
; ============================================================================

public AgenticApertureMain

end
