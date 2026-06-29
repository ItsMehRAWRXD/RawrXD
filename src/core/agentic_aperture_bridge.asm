; ============================================================================
; agentic_aperture_bridge.asm — Aperture Integration for Sovereign Agentic Core
; ============================================================================
;
; Bridges the Agentic State Machine to Aperture AVX-512 Inference Kernels.
; Pure MASM — No C++ — Zero CRT.
;
; Integration Points:
;   - Aperture_Q4_0_Dequant_AVX512 (dequantization)
;   - Aperture_Fused_Q4_0_GEMV_AVX512 (GEMV operation)
;   - Prompt-to-Tool Parser (decision extraction)
;
; Build: ml64.exe /c agentic_aperture_bridge.asm
; Link:  link.exe agentic_sovereign_entry.obj agentic_aperture_bridge.obj aperture_q4_0_avx512_v2.obj
;
; ============================================================================

; ============================================================================
; External Imports (Aperture Kernels)
; ============================================================================

EXTERN Aperture_Q4_0_Dequant_AVX512 : PROC

; ============================================================================
; External Imports (Windows API)
; ============================================================================

EXTERN GetTickCount : PROC
EXTERN Sleep : PROC

; ============================================================================
; External Data References (from agentic_sovereign_entry.asm)
; ============================================================================

EXTERN agent_state : DWORD
EXTERN step_count : DWORD
EXTERN max_steps : DWORD
EXTERN current_task : BYTE

; Agent states (must match agentic_sovereign_entry.asm)
AGENT_STATE_IDLE         equ 0
AGENT_STATE_THINKING     equ 1
AGENT_STATE_EXECUTING    equ 2
AGENT_STATE_COMPLETE     equ 3
AGENT_STATE_ERROR        equ 4

; ============================================================================
; Constants
; ============================================================================

; Parser states
PARSE_STATE_IDLE        equ 0
PARSE_STATE_THINK       equ 1
PARSE_STATE_ACT         equ 2
PARSE_STATE_DONE        equ 3

; Marker strings (for parsing)
MARKER_THINK            equ 1
MARKER_ACT              equ 2
MARKER_DONE             equ 3

; Buffer sizes
PROMPT_BUFFER_SIZE      equ 4096
RESPONSE_BUFFER_SIZE    equ 8192
TOOL_NAME_SIZE          equ 256
TOOL_PARAM_SIZE         equ 1024

; ============================================================================
; Data Section
; ============================================================================

.data

; Parser state
parse_state             dd PARSE_STATE_IDLE

; Buffers
prompt_buffer           db PROMPT_BUFFER_SIZE dup(0)
response_buffer         db RESPONSE_BUFFER_SIZE dup(0)
tool_name               db TOOL_NAME_SIZE dup(0)
tool_params             db TOOL_PARAM_SIZE dup(0)

; Marker strings
str_think               db "[THINK]", 0
str_act                 db "[ACT]", 0
str_done                db "[DONE]", 0

; Tool names (for dispatch)
tool_readfile           db "ReadFile", 0
tool_writefile          db "WriteFile", 0
tool_listdir            db "ListDirectory", 0
tool_calculate          db "Calculate", 0
tool_gettime            db "GetSystemTime", 0

; Status messages
msg_parsing             db "[PARSER] Extracting decision markers...", 13, 10
msg_parsing_len         equ $ - msg_parsing

msg_think_detected      db "[PARSER] THINK marker detected", 13, 10
msg_think_len           equ $ - msg_think_detected

msg_act_detected        db "[PARSER] ACT marker detected: ", 0
msg_act_len             equ $ - msg_act_detected

msg_done_detected       db "[PARSER] DONE marker detected", 13, 10
msg_done_len            equ $ - msg_done_detected

msg_tool_dispatch       db "[DISPATCH] Executing tool: ", 0
msg_tool_dispatch_len   equ $ - msg_tool_dispatch

msg_aperture_call       db "[APERTURE] Invoking inference kernel...", 13, 10
msg_aperture_len        equ $ - msg_aperture_call

msg_aperture_done       db "[APERTURE] Inference complete", 13, 10
msg_aperture_done_len   equ $ - msg_aperture_done

; Timing
start_ticks             dd 0
end_ticks               dd 0

; ============================================================================
; Code Section
; ============================================================================

.code

; ============================================================================
; String Utilities
; ============================================================================

; int String_Find(const char* haystack, const char* needle)
; Returns: index of first occurrence, or -1 if not found
; RCX = haystack, RDX = needle
String_Find proc
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    sub rsp, 40
    
    mov rdi, rcx                ; haystack
    mov rsi, rdx                ; needle
    
    ; Get needle length
    xor r12, r12                ; needle length
    mov rbx, rsi
@@needle_len:
    mov al, [rbx]
    test al, al
    jz @@search
    inc r12
    inc rbx
    jmp @@needle_len
    
@@search:
    test r12, r12               ; empty needle?
    jz @@not_found
    
    xor r13, r13                ; current position in haystack
    
@@outer:
    mov al, [rdi + r13]
    test al, al
    jz @@not_found
    
    ; Compare at current position
    xor rbx, rbx
@@inner:
    cmp rbx, r12
    jge @@found
    
    ; Calculate address: rdi + r13 + rbx
    mov r14, r13
    add r14, rbx
    mov al, [rdi + r14]
    mov ah, [rsi + rbx]
    cmp al, ah
    jne @@next_pos
    inc rbx
    jmp @@inner
    
@@next_pos:
    inc r13
    jmp @@outer
    
@@found:
    mov rax, r13
    jmp @@done
    
@@not_found:
    mov rax, -1
    
@@done:
    add rsp, 40
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
String_Find endp

; void String_CopyUntil(char* dst, const char* src, char terminator, size_t max)
; RCX = dst, RDX = src, R8 = terminator, R9 = max
String_CopyUntil proc
    push rbx
    push rdi
    push rsi
    sub rsp, 32
    
    mov rdi, rcx                ; dst
    mov rsi, rdx                ; src
    mov bl, r8b                 ; terminator
    mov rcx, r9                 ; max
    
@@copy:
    cmp rcx, 1
    jle @@done
    mov al, [rsi]
    cmp al, bl
    je @@done
    test al, al
    jz @@done
    mov [rdi], al
    inc rdi
    inc rsi
    dec rcx
    jmp @@copy
    
@@done:
    mov byte ptr [rdi], 0       ; null terminate
    
    add rsp, 32
    pop rsi
    pop rdi
    pop rbx
    ret
String_CopyUntil endp

; ============================================================================
; Console Output (External from agentic_sovereign_entry.asm)
; ============================================================================

EXTERN Print : PROC
EXTERN PrintString : PROC
EXTERN PrintNewline : PROC

; ============================================================================
; Prompt-to-Tool Parser
; ============================================================================

; int ParseDecision(const char* response)
; Parses model output and extracts decision markers
; Returns: MARKER_THINK, MARKER_ACT, MARKER_DONE, or 0
; RCX = response string
ParseDecision proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rdi, rcx                ; save response pointer
    
    ; Check for [DONE] first (highest priority)
    mov rcx, rdi
    lea rdx, [str_done]
    call String_Find
    cmp rax, -1
    jne @@found_done
    
    ; Check for [ACT]
    mov rcx, rdi
    lea rdx, [str_act]
    call String_Find
    cmp rax, -1
    jne @@found_act
    
    ; Check for [THINK]
    mov rcx, rdi
    lea rdx, [str_think]
    call String_Find
    cmp rax, -1
    jne @@found_think
    
    ; No marker found
    xor eax, eax
    jmp @@done
    
@@found_done:
    mov eax, MARKER_DONE
    jmp @@done
    
@@found_act:
    ; Extract tool name after [ACT]
    lea rcx, [tool_name]
    lea rdx, [rdi + rax + 5]    ; skip "[ACT]"
    mov r8, '['                 ; stop at next marker
    mov r9, TOOL_NAME_SIZE
    call String_CopyUntil
    
    mov eax, MARKER_ACT
    jmp @@done
    
@@found_think:
    mov eax, MARKER_THINK
    
@@done:
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
ParseDecision endp

; ============================================================================
; Tool Dispatch
; ============================================================================

; void Dispatch_Tool(const char* tool_name)
; RCX = tool name
Dispatch_Tool proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    mov rdi, rcx
    
    ; Print dispatch message
    lea rcx, [msg_tool_dispatch]
    call PrintString
    mov rcx, rdi
    call PrintString
    call PrintNewline
    
    ; Compare tool names and dispatch
    ; For now, just simulate execution
    
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
Dispatch_Tool endp

; ============================================================================
; Aperture Inference Integration
; ============================================================================

; void Aperture_Inference(const char* prompt, char* response, size_t response_len)
; RCX = prompt, RDX = response buffer, R8 = response length
; This is a STUB that simulates Aperture inference
; In production, this calls the actual AVX-512 kernels
Aperture_Inference proc
    push rbx
    push rdi
    push rsi
    push r12
    sub rsp, 40
    
    mov rdi, rcx                ; prompt
    mov rsi, rdx                ; response buffer
    mov r12, r8                 ; response length
    
    ; Print aperture call message
    lea rcx, [msg_aperture_call]
    mov rdx, msg_aperture_len
    call Print
    
    ; Simulate inference latency
    mov rcx, 10                 ; 10ms simulated latency
    call Sleep
    
    ; Generate simulated response based on prompt content
    ; Check for keywords in prompt
    
    ; Check for "time"
    mov rcx, rdi
    lea rdx, [str_time]
    call String_Find
    cmp rax, -1
    jne @@time_response
    
    ; Check for "list"
    mov rcx, rdi
    lea rdx, [str_list]
    call String_Find
    cmp rax, -1
    jne @@list_response
    
    ; Check for "calculate"
    mov rcx, rdi
    lea rdx, [str_calc]
    call String_Find
    cmp rax, -1
    jne @@calc_response
    
    ; Default response
    jmp @@default_response
    
@@time_response:
    ; Copy time response
    mov rcx, rsi
    lea rdx, [response_time]
    mov r8, r12
    call String_Copy
    jmp @@done
    
@@list_response:
    mov rcx, rsi
    lea rdx, [response_list]
    mov r8, r12
    call String_Copy
    jmp @@done
    
@@calc_response:
    mov rcx, rsi
    lea rdx, [response_calc]
    mov r8, r12
    call String_Copy
    jmp @@done
    
@@default_response:
    mov rcx, rsi
    lea rdx, [response_default]
    mov r8, r12
    call String_Copy
    
@@done:
    ; Print completion message
    lea rcx, [msg_aperture_done]
    mov rdx, msg_aperture_done_len
    call Print
    
    add rsp, 40
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
    
; String copy helper
String_Copy:
    push rdi
    push rsi
    push rcx
    
    mov rdi, rcx                ; dst
    mov rsi, rdx                ; src
    mov rcx, r8                 ; max
    
@@copy_loop:
    cmp rcx, 1
    jle @@copy_done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    test al, al
    jnz @@copy_loop
    
@@copy_done:
    pop rcx
    pop rsi
    pop rdi
    ret
    
; Keyword strings
str_time                db "time", 0
str_list                db "list", 0
str_calc                db "calculate", 0

; Simulated responses
response_time           db "[THINK] The user wants to know the current time.", 13, 10
                        db "[ACT] GetSystemTime[]", 13, 10
                        db "[DONE] Current time retrieved.", 0
response_list           db "[THINK] The user wants to list directory contents.", 13, 10
                        db "[ACT] ListDirectory[.]", 13, 10
                        db "[DONE] Directory listed.", 0
response_calc           db "[THINK] This is a calculation task.", 13, 10
                        db "[ACT] Calculate[123 * 456]", 13, 10
                        db "[DONE] Result: 56088", 0
response_default        db "[THINK] Processing request...", 13, 10
                        db "[DONE] Task completed.", 0

Aperture_Inference endp

; ============================================================================
; Integrated Agentic Step with Aperture
; ============================================================================

; int Agentic_RunStep_WithAperture()
; Runs one agentic step with Aperture inference
; Returns: 0 = success, state in agent_state
Agentic_RunStep_WithAperture proc
    push rbx
    push rdi
    push rsi
    sub rsp, 40
    
    ; Increment step count
    inc dword ptr [step_count]
    
    ; Check max steps
    mov eax, [step_count]
    cmp eax, [max_steps]
    jge @@error
    
    ; Get current task
    lea rdi, [current_task]
    
    ; Call Aperture inference
    mov rcx, rdi
    lea rdx, [response_buffer]
    mov r8, RESPONSE_BUFFER_SIZE
    call Aperture_Inference
    
    ; Parse decision from response
    lea rcx, [response_buffer]
    call ParseDecision
    
    ; Update state based on marker
    cmp eax, MARKER_THINK
    je @@state_think
    cmp eax, MARKER_ACT
    je @@state_act
    cmp eax, MARKER_DONE
    je @@state_done
    jmp @@state_think           ; default
    
@@state_think:
    mov dword ptr [agent_state], AGENT_STATE_THINKING
    jmp @@success
    
@@state_act:
    mov dword ptr [agent_state], AGENT_STATE_EXECUTING
    ; Dispatch tool
    lea rcx, [tool_name]
    call Dispatch_Tool
    jmp @@success
    
@@state_done:
    mov dword ptr [agent_state], AGENT_STATE_COMPLETE
    jmp @@success
    
@@success:
    xor eax, eax
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret
    
@@error:
    mov dword ptr [agent_state], AGENT_STATE_ERROR
    mov eax, -1
    add rsp, 40
    pop rsi
    pop rdi
    pop rbx
    ret

Agentic_RunStep_WithAperture endp

; ============================================================================
; Export Table
; ============================================================================

public ParseDecision
public Dispatch_Tool
public Aperture_Inference
public Agentic_RunStep_WithAperture
public String_Find
public String_CopyUntil

end
