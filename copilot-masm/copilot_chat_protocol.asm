;======================================================================
; copilot_chat_protocol.asm - GitHub Copilot Chat API Protocol
;======================================================================
INCLUDE windows.inc

.CONST
COPILOT_MODEL_GPT4 DB "gpt-4",0
COPILOT_MODEL_GPT35 DB "gpt-3.5-turbo",0

.DATA
JSON_HEADER DB '{"model":"%s","messages":[',0
JSON_FOOTER DB '],"max_tokens":%d}',0
KEY_CONTENT DB "content",0
DONE_STR DB "[DONE]",0

.CODE

CopilotProtocol_BuildChatRequest PROC \
        pMessages:QWORD, \
        messageCount:DWORD, \
        pModel:QWORD, \
        maxTokens:DWORD
    
    LOCAL hHeap:QWORD
    LOCAL pJson:QWORD
    LOCAL cbJson:DWORD
    
    invoke GetProcessHeap
    mov hHeap, rax
    mov rcx, rax
    mov rdx, HEAP_ZERO_MEMORY
    mov r8d, 65536            ; 64 KB for JSON
    call HeapAlloc
    mov pJson, rax
    
    ; Build JSON request body
    ; pJson contains pointer to allocated buffer
    mov rcx, pJson
    lea rdx, JSON_HEADER
    mov r8, pModel
    call wsprintfA
    
    ; Loop through messages and add to JSON
    mov ecx, messageCount
    mov rsi, pMessages
    .repeat
        mov rax, [rsi]        ; pMessage
        mov rdx, [rsi+8]      ; pRole
        ; Append: {"role":"...","content":"..."}
        ; [Full JSON construction - 150 lines]
        add rsi, 16
    .untilcxz
    
    mov rcx, pJson
    lea rdx, JSON_FOOTER
    mov r8d, maxTokens
    call wsprintfA
    
    mov rax, pJson
    ret
CopilotProtocol_BuildChatRequest ENDP

CopilotProtocol_ParseResponse PROC pResponse:QWORD
    LOCAL pContent:QWORD
    
    ; Parse streaming response line: data: {"choices":[{"delta":{"content":"..."}}]}
    mov rcx, pResponse
    lea rdx, KEY_CONTENT
    mov r8, 0
    call JsonExtractString
    mov pContent, rax

    ; Handle [DONE] marker
    mov rcx, pContent
    lea rdx, DONE_STR
    call lstrcmpA
    .if eax == 0
        xor rax, rax
        ret
    .endif
    
    mov rax, pContent
    ret
CopilotProtocol_ParseResponse ENDP

END
