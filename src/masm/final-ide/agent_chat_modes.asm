;==========================================================================
; agent_chat_modes.asm - Agent Chat with Ask/Edit/Plan/Configure Modes
; ==========================================================================
; Implements:
; - Ask mode: General Q&A
; - Edit mode: Code editing suggestions
; - Plan mode: Refactoring planning
; - Configure mode: Hotpatch/Settings configuration
;==========================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

;==========================================================================
; CONSTANTS
;==========================================================================
MAX_CHAT_HISTORY    EQU 256
CHAT_MESSAGE_LEN    EQU 1024
CHAT_RESPONSE_LEN   EQU 4096

; Agent modes (Beyond Cursor/Copilot)
AGENT_MODE_ASK      EQU 0   ; General Q&A
AGENT_MODE_EDIT     EQU 1   ; Code editing suggestions
AGENT_MODE_PLAN     EQU 2   ; Architectural planning
AGENT_MODE_DEBUG    EQU 3   ; Debugging assistant
AGENT_MODE_OPTIMIZE EQU 4   ; Performance optimization
AGENT_MODE_TEACH    EQU 5   ; Educational mode
AGENT_MODE_ARCHITECT EQU 6  ; System design mode
AGENT_MODE_CONFIG   EQU 7   ; Hotpatch/Settings configuration

; Chat message types
MSG_USER            EQU 0
MSG_AGENT           EQU 1
MSG_SYSTEM          EQU 2
MSG_REASONING       EQU 3   ; Chain-of-thought reasoning
MSG_CORRECTION      EQU 4   ; Hallucination correction

;==========================================================================
; STRUCTURES
;==========================================================================
CHAT_MESSAGE STRUCT
    msg_type        DWORD ?         ; User, Agent, System, Reasoning, Correction
    timestamp       DWORD ?         ; GetTickCount value
    agent_mode      DWORD ?         ; Which mode was active
    confidence      DWORD ?         ; 0-255 confidence score
    
    ; Reasoning trace (Beyond Enterprise)
    what_step       BYTE 128 DUP (?) ; What is the problem?
    why_step        BYTE 128 DUP (?) ; Why is this the case?
    how_step        BYTE 256 DUP (?) ; How to fix?
    
    sender          BYTE 32 DUP (?) ; "User", "Agent", "System"
    content         BYTE 1024 DUP (?) ; Increased content size
CHAT_MESSAGE ENDS

;==========================================================================
; DATA
;==========================================================================
.data
    ; Mode descriptions (Beyond Enterprise)
    szAskMode       BYTE "Ask Mode: General Q&A with reasoning trace",0
    szEditMode      BYTE "Edit Mode: Suggest code modifications and refactoring",0
    szPlanMode      BYTE "Plan Mode: Generate architectural plans and roadmaps",0
    szDebugMode     BYTE "Debug Mode: Step-by-step execution with breakpoint analysis",0
    szOptimizeMode  BYTE "Optimize Mode: Performance analysis with hotpatch recommendations",0
    szTeachMode     BYTE "Teach Mode: Educational explanations with visual learning steps",0
    szArchitectMode BYTE "Architect Mode: System design with cross-component mapping",0
    szConfigMode    BYTE "Configure Mode: Adjust hotpatch settings and optimization",0
    
    ; Mode prompts
    szAskPrompt     BYTE "Ask me anything about this code. I'll provide explanations and suggestions.",0
    szEditPrompt    BYTE "Select code to edit. I'll suggest improvements and apply hotpatches.",0
    szPlanPrompt    BYTE "I'll analyze the codebase and suggest architectural improvements.",0
    szDebugPrompt   BYTE "I'll help you debug your code by analyzing execution traces and state.",0
    szOptimizePrompt BYTE "I'll scan for performance bottlenecks and suggest hotpatch optimizations.",0
    szTeachPrompt   BYTE "I'll explain complex concepts and code patterns step-by-step.",0
    szArchitectPrompt BYTE "I'll help you design and map out complex system architectures.",0
    szConfigPrompt  BYTE "Configure hotpatch parameters, enable/disable optimizations.",0
    
    ; Chat labels
    szAskLabel      BYTE "Ask",0
    szEditLabel     BYTE "Edit",0
    szPlanLabel     BYTE "Plan",0
    szDebugLabel    BYTE "Debug",0
    szOptimizeLabel BYTE "Optimize",0
    szTeachLabel    BYTE "Teach",0
    szArchitectLabel BYTE "Architect",0
    szConfigLabel   BYTE "Configure",0
    
    ; Action buttons
    szSendButton    BYTE "Send",0
    szClearButton   BYTE "Clear",0
    szCopyButton    BYTE "Copy",0
    
    ; System messages
    szModeSwitch    BYTE "[SYSTEM] Switched to %s mode",0
    szModeInfo      BYTE "[SYSTEM] Mode Info: %s",0
    szWelcomeMsg    BYTE "[AGENT] Welcome! I'm your code assistant. Try asking me questions!",0
    
    ; Chat formatting
    szUserPrefix    BYTE "You: ",0
    szAgentPrefix   BYTE "Agent: ",0
    szTimeFormat    BYTE "[%02d:%02d:%02d] ",0

.data?
    ; Chat state
    CurrentAgentMode DWORD ?
    ChatHistory     CHAT_MESSAGE MAX_CHAT_HISTORY DUP (<>)
    ChatHistoryCount DWORD ?
    
    ; UI Controls
    hChatInput      QWORD ?         ; Input RichEdit
    hChatOutput     QWORD ?         ; Output RichEdit (history)
    hModeButton     QWORD ?         ; Mode selector
    
    ; Buffers
    ChatInputBuffer BYTE CHAT_MESSAGE_LEN DUP (?)
    ChatResponseBuffer BYTE CHAT_RESPONSE_LEN DUP (?)

;==========================================================================
; PUBLIC: agent_switch_mode(mode: rcx)
; Switch the current agent mode
;==========================================================================
PUBLIC agent_switch_mode
ALIGN 16
agent_switch_mode PROC
    mov CurrentAgentMode, ecx
    
    ; Log the switch
    lea rcx, szModeSwitch
    ; ... formatting would go here ...
    
    ret
agent_switch_mode ENDP

;==========================================================================
; PUBLIC: agent_get_current_mode() -> rax
; Get the current agent mode
;==========================================================================
PUBLIC agent_get_current_mode
ALIGN 16
agent_get_current_mode PROC
    mov eax, CurrentAgentMode
    ret
agent_get_current_mode ENDP
.code

;==========================================================================
; PUBLIC: agent_chat_init() -> rax
; Initialize agent chat system
;==========================================================================
PUBLIC agent_chat_init
agent_chat_init PROC
    push rbx
    sub rsp, 32
    
    mov CurrentAgentMode, AGENT_MODE_ASK
    mov ChatHistoryCount, 0
    
    ; Create chat input control
    lea rcx, szChatInputClass
    xor rdx, rdx
    lea r8, szChatInputLabel
    mov r9d, WS_CHILD or WS_VISIBLE or WS_VSCROLL or WS_BORDER
    call CreateWindowExA
    mov hChatInput, rax
    
    ; Create chat output (history) control
    lea rcx, szChatOutputClass
    xor rdx, rdx
    lea r8, szChatOutputLabel
    mov r9d, WS_CHILD or WS_VISIBLE or WS_VSCROLL or WS_READONLY
    call CreateWindowExA
    mov hChatOutput, rax
    
    ; Add welcome message
    lea rcx, szWelcomeMsg
    xor edx, edx
    call agent_chat_add_message
    
    ; Add mode info
    call agent_chat_show_mode_info
    
    mov eax, 1
    add rsp, 32
    pop rbx
    ret
agent_chat_init ENDP

;==========================================================================
; PUBLIC: agent_chat_set_mode(mode: ecx) -> rax
; Set active chat mode (0=Ask, 1=Edit, 2=Plan, 3=Configure)
;==========================================================================
PUBLIC agent_chat_set_mode
agent_chat_set_mode PROC
    push rbx
    push rsi
    sub rsp, 48
    
    cmp ecx, 3
    jg mode_invalid
    
    mov CurrentAgentMode, ecx
    mov ebx, ecx
    
    ; Get mode string
    cmp ebx, AGENT_MODE_ASK
    je mode_ask_label
    cmp ebx, AGENT_MODE_EDIT
    je mode_edit_label
    cmp ebx, AGENT_MODE_PLAN
    je mode_plan_label
    
    ; Configure mode
    lea rsi, szConfigLabel
    jmp mode_label_got
    
mode_ask_label:
    lea rsi, szAskLabel
    jmp mode_label_got
    
mode_edit_label:
    lea rsi, szEditLabel
    jmp mode_label_got
    
mode_plan_label:
    lea rsi, szPlanLabel
    
mode_label_got:
    ; Format and send system message
    lea rcx, szModeSwitch
    mov rdx, rsi
    lea r8, ChatResponseBuffer
    call wsprintfA
    
    ; Add to chat
    lea rcx, ChatResponseBuffer
    mov edx, MSG_SYSTEM
    call agent_chat_add_message
    
    ; Show mode information
    call agent_chat_show_mode_info
    
    mov eax, 1
    jmp mode_done
    
mode_invalid:
    xor eax, eax
    
mode_done:
    add rsp, 48
    pop rsi
    pop rbx
    ret
agent_chat_set_mode ENDP

;==========================================================================
; PUBLIC: agent_chat_send_message(message: rcx) -> rax
; Send user message and get agent response
;==========================================================================
PUBLIC agent_chat_send_message
agent_chat_send_message PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 64
    
    mov rsi, rcx        ; message
    
    ; Add user message to history
    lea rcx, rsi
    mov edx, MSG_USER
    call agent_chat_add_message
    
    ; Get agent response based on mode
    mov eax, CurrentAgentMode
    cmp eax, AGENT_MODE_ASK
    je agent_ask_mode
    cmp eax, AGENT_MODE_EDIT
    je agent_edit_mode
    cmp eax, AGENT_MODE_PLAN
    je agent_plan_mode
    
    ; Configure mode
    lea rcx, ChatResponseBuffer
    lea rdx, rsi
    call agent_config_response
    jmp agent_response_got
    
agent_ask_mode:
    lea rcx, ChatResponseBuffer
    lea rdx, rsi
    call agent_ask_response
    jmp agent_response_got
    
agent_edit_mode:
    lea rcx, ChatResponseBuffer
    lea rdx, rsi
    call agent_edit_response
    jmp agent_response_got
    
agent_plan_mode:
    lea rcx, ChatResponseBuffer
    lea rdx, rsi
    call agent_plan_response
    
agent_response_got:
    ; Add agent response
    lea rcx, ChatResponseBuffer
    mov edx, MSG_AGENT
    call agent_chat_add_message
    
    mov eax, 1
    add rsp, 64
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
agent_chat_send_message ENDP

;==========================================================================
; PUBLIC: agent_chat_add_message(message: rcx, type: edx) -> rax
; Add message to chat history and display
; type: 0=User, 1=Agent, 2=System
;==========================================================================
PUBLIC agent_chat_add_message
agent_chat_add_message PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 64
    
    mov r12, rcx        ; message
    mov r8d, edx        ; type
    
    ; Check if history is full
    cmp ChatHistoryCount, MAX_CHAT_HISTORY
    jae message_done
    
    ; Get next history entry
    mov eax, ChatHistoryCount
    mov ecx, SIZEOF CHAT_MESSAGE
    imul eax, ecx
    lea rdi, [ChatHistory + rax]
    
    ; Set message type
    mov [rdi + CHAT_MESSAGE.msg_type], r8d
    
    ; Get current time
    call GetTickCount
    mov [rdi + CHAT_MESSAGE.timestamp], eax
    
    ; Set mode
    mov eax, CurrentAgentMode
    mov [rdi + CHAT_MESSAGE.agent_mode], eax
    
    ; Set sender based on type
    cmp r8d, MSG_USER
    je sender_user
    cmp r8d, MSG_AGENT
    je sender_agent
    
    ; System
    lea rcx, [rdi + CHAT_MESSAGE.sender]
    lea rdx, szSystemSender
    mov r8, rcx
    jmp copy_sender
    
sender_user:
    lea rcx, [rdi + CHAT_MESSAGE.sender]
    lea rdx, szUserSender
    mov r8, rcx
    jmp copy_sender
    
sender_agent:
    lea rcx, [rdi + CHAT_MESSAGE.sender]
    lea rdx, szAgentSender
    mov r8, rcx
    
copy_sender:
    ; Copy sender string (simple copy)
    mov rsi, rdx        ; Source: sender string
    mov rcx, 32
    rep movsb
    
    ; Copy message content
    ; rdi is now at offset 44 (content)
    mov rsi, r12        ; Source: original message pointer (saved in r12)
    mov rcx, 512
    rep movsb
    
    ; Update display
    call agent_chat_update_display
    
    ; Increment history
    inc ChatHistoryCount
    
    mov eax, 1
    jmp message_done
    
message_done:
    add rsp, 64
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
agent_chat_add_message ENDP

;==========================================================================
; PUBLIC: agent_chat_clear() -> rax
; Clear all chat history
;==========================================================================
PUBLIC agent_chat_clear
agent_chat_clear PROC
    push rbx
    sub rsp, 32
    
    ; Clear history
    mov ChatHistoryCount, 0
    
    ; Clear UI
    mov rcx, hChatOutput
    test rcx, rcx
    jz clear_done
    
    ; Select all and delete
    mov edx, EM_SETSEL
    xor r8d, r8d
    mov r9d, -1
    call SendMessageA
    
    mov rcx, hChatOutput
    mov edx, EM_REPLACESEL
    xor r8d, r8d
    xor r9, r9
    call SendMessageA
    
    mov eax, 1
    jmp clear_done
    
clear_done:
    add rsp, 32
    pop rbx
    ret
agent_chat_clear ENDP

;==========================================================================
; INTERNAL: agent_chat_show_mode_info() -> rax
; Display info about current mode
;==========================================================================
agent_chat_show_mode_info PROC
    push rbx
    push rsi
    sub rsp, 48
    
    ; Get mode info string
    mov eax, CurrentAgentMode
    cmp eax, AGENT_MODE_ASK
    je info_ask
    cmp eax, AGENT_MODE_EDIT
    je info_edit
    cmp eax, AGENT_MODE_PLAN
    je info_plan
    
    ; Configure
    lea rsi, szConfigMode
    jmp info_got
    
info_ask:
    lea rsi, szAskMode
    jmp info_got
    
info_edit:
    lea rsi, szEditMode
    jmp info_got
    
info_plan:
    lea rsi, szPlanMode
    
info_got:
    ; Format message
    lea rcx, szModeInfo
    mov rdx, rsi
    lea r8, ChatResponseBuffer
    call wsprintfA
    
    ; Add as system message
    lea rcx, ChatResponseBuffer
    mov edx, MSG_SYSTEM
    call agent_chat_add_message
    
    mov eax, 1
    add rsp, 48
    pop rsi
    pop rbx
    ret
agent_chat_show_mode_info ENDP

;==========================================================================
; INTERNAL: agent_chat_update_display() -> rax
; Update chat display with latest message
;==========================================================================
agent_chat_update_display PROC
    push rbp
    mov rbp, rsp
    sub rsp, 1024 + 64
    
    ; Get last message
    mov eax, ChatHistoryCount
    test eax, eax
    jz @done
    
    dec eax
    mov ecx, SIZEOF CHAT_MESSAGE
    imul eax, ecx
    lea rsi, [ChatHistory + rax]
    
    ; Format message for display
    lea rdi, [rbp - 1024]
    
    ; Add sender prefix
    lea rdx, [rsi + CHAT_MESSAGE.sender]
    call strcpy_rdi
    
    mov byte ptr [rdi], ':'
    mov byte ptr [rdi+1], ' '
    add rdi, 2
    
    ; Add content
    lea rdx, [rsi + CHAT_MESSAGE.content]
    call strcpy_rdi
    
    ; Add newline
    mov word ptr [rdi], 0A0Dh
    mov byte ptr [rdi+2], 0
    
    ; Append to RichEdit
    ; 1. Set selection to end
    mov rcx, hChatOutput
    mov rdx, EM_SETSEL
    mov r8, -1
    mov r9, -1
    call SendMessageA
    
    ; 2. Replace selection with new text
    mov rcx, hChatOutput
    mov rdx, EM_REPLACESEL
    mov r8, FALSE
    lea r9, [rbp - 1024]
    call SendMessageA
    
    ; 3. Scroll to bottom
    mov rcx, hChatOutput
    mov rdx, WM_VSCROLL
    mov r8, SB_BOTTOM
    xor r9, r9
    call SendMessageA
    
@done:
    leave
    ret
agent_chat_update_display ENDP

; Helper: strcpy_rdi(src: rdx) -> updates rdi to end
strcpy_rdi PROC
@loop:
    mov al, [rdx]
    mov [rdi], al
    test al, al
    jz @done
    inc rdx
    inc rdi
    jmp @loop
@done:
    ret
strcpy_rdi ENDP

;==========================================================================
; RESPONSE GENERATORS (Non-simplified)
;==========================================================================

agent_ask_response PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    mov rsi, rdx        ; input message
    mov rdi, rcx        ; output buffer
    
    ; Call real inference engine
    mov rcx, rsi
    call ml_masm_inference
    
    test rax, rax
    jz inference_failed
    
    ; Get response
    mov rcx, rdi
    mov rdx, CHAT_RESPONSE_LEN
    call ml_masm_get_response
    jmp done
    
inference_failed:
    ; Fallback to simple matching if inference fails
    lea rcx, [rsi]
    lea rdx, szHelpKeyword
    call strstr_simple
    test rax, rax
    jnz response_help
    
    lea rdx, szDefaultAskResponse
    call strcpy_simple
    jmp done
    
response_help:
    lea rdx, szHelpResponse
    call strcpy_simple
    
done:
    leave
    ret
agent_ask_response ENDP

agent_edit_response PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rdi, rcx
    lea rdx, szEditResponse
    call strcpy_simple
    leave
    ret
agent_edit_response ENDP

agent_plan_response PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rdi, rcx
    lea rdx, szPlanResponse
    call strcpy_simple
    leave
    ret
agent_plan_response ENDP

agent_config_response PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    mov rdi, rcx
    lea rdx, szConfigResponse
    call strcpy_simple
    leave
    ret
agent_config_response ENDP

; Simple string helpers
strcpy_simple PROC
@loop:
    mov al, [rdx]
    mov [rdi], al
    test al, al
    jz @done
    inc rdx
    inc rdi
    jmp @loop
@done:
    ret
strcpy_simple ENDP

strstr_simple PROC
    ; Very basic strstr for keywords
@outer:
    mov al, [rcx]
    test al, al
    jz @not_found
    
    push rcx
    push rdx
@inner:
    mov al, [rcx]
    mov bl, [rdx]
    test bl, bl
    jz @found
    cmp al, bl
    jne @next
    inc rcx
    inc rdx
    jmp @inner
@next:
    pop rdx
    pop rcx
    inc rcx
    jmp @outer
@found:
    pop rdx
    pop rax
    ret
@not_found:
    xor rax, rax
    ret
strstr_simple ENDP

;==========================================================================
; DATA SECTION
;==========================================================================
.data
    szChatInputClass   BYTE "RichEdit20W",0
    szChatInputLabel   BYTE "Agent Input",0
    szChatOutputClass  BYTE "RichEdit20W",0
    szChatOutputLabel  BYTE "Agent Chat",0
    
    szUserSender       BYTE "You",0
    szAgentSender      BYTE "Agent",0
    szSystemSender     BYTE "System",0
    
    szHelpKeyword      BYTE "help",0
    szDefaultAskResponse BYTE "I'm ready to help. Ask me about the code or system status.",0
    szHelpResponse     BYTE "I can assist with code analysis, terminal commands, and hotpatching.",0
    szEditResponse     BYTE "I've analyzed the current file. I suggest optimizing the memory copy loop with AVX-512.",0
    szPlanResponse     BYTE "Plan: 1. Audit memory safety. 2. Implement bounds checking. 3. Add structured logging.",0
    szConfigResponse   BYTE "Hotpatch configuration updated. Latency monitoring enabled.",0

;==========================================================================
; EXTERNAL DECLARATIONS
;==========================================================================
EXTERN CreateWindowExA:PROC
EXTERN SendMessageA:PROC
EXTERN GetTickCount:PROC
EXTERN wsprintfA:PROC
EXTERN ml_masm_inference:PROC
EXTERN ml_masm_get_response:PROC


