;==============================================================================
; ollama_bridge.asm - Production-Ready Ollama API Bridge
; ==============================================================================
; Provides complete bridge to Ollama API for model management and inference.
; Zero C++ runtime dependencies.
;==============================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib

include http_client.inc
include json_parser.inc
include logging.inc

;==============================================================================
; EXTERNAL DECLARATIONS
;==============================================================================
EXTERN wsprintfA:PROC
EXTERN lstrlenA:PROC
EXTERN lstrcpyA:PROC
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC

;==============================================================================
; DATA SEGMENT
;==============================================================================
.data
    szApiGenerate     BYTE "/api/generate",0
    szApiChat         BYTE "/api/chat",0
    szApiList         BYTE "/api/tags",0
    szApiShow         BYTE "/api/show",0
    szApiDelete       BYTE "/api/delete",0
    szApiCopy         BYTE "/api/copy",0
    
    szGenerateJson    BYTE "{\"model\":\"%s\",\"prompt\":\"%s\",\"stream\":false}",0
    szChatJson        BYTE "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}]}",0
    szListJson        BYTE "{}",0
    szShowJson        BYTE "{\"name\":\"%s\"}",0
    szDeleteJson      BYTE "{\"name\":\"%s\"}",0
    szCopyJson        BYTE "{\"source\":\"%s\",\"destination\":\"%s\"}",0
    
    szOllamaSuccess   BYTE "Ollama API call succeeded",0
    szOllamaError      BYTE "Ollama API call failed",0

.data?
    api_buffer        BYTE 8192 DUP (?)
    api_response      QWORD ?

;==============================================================================
; CODE SEGMENT
;==============================================================================
.code

;==============================================================================
; PUBLIC: OllamaGenerate(model: rcx, prompt: rdx, pResponse: r8) -> eax
; Generates text using Ollama API
;==============================================================================
PUBLIC OllamaGenerate
ALIGN 16
OllamaGenerate PROC
    LOCAL request:HTTP_REQUEST
    LOCAL jsonBody[2048]:BYTE
    LOCAL response:QWORD
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 512
    
    mov r12, rcx        ; model
    mov r13, rdx        ; prompt
    mov r14, r8         ; pResponse
    
    ; Format JSON request
    lea rcx, jsonBody
    lea rdx, szGenerateJson
    mov r8, r12
    mov r9, r13
    call wsprintfA
    
    ; Get body length
    lea rcx, jsonBody
    call lstrlenA
    mov rdi, rax
    
    ; Setup request
    mov [request.method], HTTP_METHOD_POST
    lea rax, szApiGenerate
    mov [request.url], rax
    xor rax, rax
    mov [request.headers], rax
    lea rax, jsonBody
    mov [request.body], rax
    mov [request.body_len], rdi
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz generate_fail
    
    mov [r14], rax      ; Return response body
    
    lea rcx, szOllamaSuccess
    call LogInfo
    
    mov eax, 1          ; Success
    jmp generate_done
    
generate_fail:
    lea rcx, szOllamaError
    call LogError
    xor eax, eax
    
generate_done:
    add rsp, 512
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaGenerate ENDP

;==============================================================================
; PUBLIC: OllamaChat(model: rcx, message: rdx, pResponse: r8) -> eax
; Sends a chat message to Ollama API
;==============================================================================
PUBLIC OllamaChat
ALIGN 16
OllamaChat PROC
    LOCAL request:HTTP_REQUEST
    LOCAL jsonBody[2048]:BYTE
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 512
    
    mov r12, rcx        ; model
    mov r13, rdx        ; message
    mov r14, r8         ; pResponse
    
    ; Format JSON request
    lea rcx, jsonBody
    lea rdx, szChatJson
    mov r8, r12
    mov r9, r13
    call wsprintfA
    
    ; Get body length
    lea rcx, jsonBody
    call lstrlenA
    mov rdi, rax
    
    ; Setup request
    mov [request.method], HTTP_METHOD_POST
    lea rax, szApiChat
    mov [request.url], rax
    xor rax, rax
    mov [request.headers], rax
    lea rax, jsonBody
    mov [request.body], rax
    mov [request.body_len], rdi
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz chat_fail
    
    mov [r14], rax      ; Return response body
    
    lea rcx, szOllamaSuccess
    call LogInfo
    
    mov eax, 1          ; Success
    jmp chat_done
    
chat_fail:
    lea rcx, szOllamaError
    call LogError
    xor eax, eax
    
chat_done:
    add rsp, 512
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaChat ENDP

;==============================================================================
; PUBLIC: OllamaListModels(pResponse: rcx) -> eax
; Lists available models in Ollama
;==============================================================================
PUBLIC OllamaListModels
ALIGN 16
OllamaListModels PROC
    LOCAL request:HTTP_REQUEST
    
    push rbx
    push rsi
    push rdi
    sub rsp, 256
    
    mov rbx, rcx        ; pResponse
    
    ; Setup request
    mov [request.method], HTTP_METHOD_GET
    lea rax, szApiList
    mov [request.url], rax
    xor rax, rax
    mov [request.headers], rax
    mov [request.body], rax
    mov [request.body_len], 0
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz list_fail
    
    mov [rbx], rax      ; Return response body
    
    mov eax, 1          ; Success
    jmp list_done
    
list_fail:
    xor eax, eax
    
list_done:
    add rsp, 256
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaListModels ENDP

END
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz generate_fail
    
    mov response, rax
    
    ; Store response pointer
    test r14, r14
    jz generate_done
    mov [r14], rax
    
    lea rcx, szOllamaSuccess
    call LogInfo
    
    mov eax, 1
    jmp generate_done
    
generate_fail:
    lea rcx, szOllamaError
    call LogError
    xor eax, eax
    
generate_done:
    add rsp, 512
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaGenerate ENDP

;==============================================================================
; PUBLIC: OllamaChat(model: rcx, message: rdx, pResponse: r8) -> eax
; Sends chat message to Ollama API
;==============================================================================
PUBLIC OllamaChat
ALIGN 16
OllamaChat PROC
    LOCAL request:HTTP_REQUEST
    LOCAL jsonBody[2048]:BYTE
    LOCAL response:QWORD
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 512
    
    mov r12, rcx        ; model
    mov r13, rdx        ; message
    mov r14, r8         ; pResponse
    
    ; Format JSON request
    lea rcx, jsonBody
    lea rdx, szChatJson
    mov r8, r12
    mov r9, r13
    call wsprintfA
    
    ; Get body length
    lea rcx, jsonBody
    call lstrlenA
    mov rdi, rax
    
    ; Setup request
    mov [request.method], HTTP_METHOD_POST
    lea rax, szApiChat
    mov [request.url], rax
    xor rax, rax
    mov [request.headers], rax
    lea rax, jsonBody
    mov [request.body], rax
    mov [request.body_len], rdi
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz chat_fail
    
    mov response, rax
    
    ; Store response pointer
    test r14, r14
    jz chat_done
    mov [r14], rax
    
    lea rcx, szOllamaSuccess
    call LogInfo
    
    mov eax, 1
    jmp chat_done
    
chat_fail:
    lea rcx, szOllamaError
    call LogError
    xor eax, eax
    
chat_done:
    add rsp, 512
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaChat ENDP

;==============================================================================
; PUBLIC: OllamaListModels(pResponse: rcx) -> eax
; Lists all available models
;==============================================================================
PUBLIC OllamaListModels
ALIGN 16
OllamaListModels PROC
    LOCAL request:HTTP_REQUEST
    LOCAL jsonBody[64]:BYTE
    LOCAL response:QWORD
    
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 256
    
    mov r12, rcx        ; pResponse
    
    ; Format JSON request (empty)
    lea rcx, jsonBody
    lea rdx, szListJson
    call lstrcpyA
    
    ; Get body length
    lea rcx, jsonBody
    call lstrlenA
    mov rdi, rax
    
    ; Setup request
    mov [request.method], HTTP_METHOD_GET
    lea rax, szApiList
    mov [request.url], rax
    xor rax, rax
    mov [request.headers], rax
    lea rax, jsonBody
    mov [request.body], rax
    mov [request.body_len], rdi
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz list_fail
    
    mov response, rax
    
    ; Store response pointer
    test r12, r12
    jz list_done
    mov [r12], rax
    
    lea rcx, szOllamaSuccess
    call LogInfo
    
    mov eax, 1
    jmp list_done
    
list_fail:
    lea rcx, szOllamaError
    call LogError
    xor eax, eax
    
list_done:
    add rsp, 256
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaListModels ENDP

;==============================================================================
; PUBLIC: OllamaShowModel(modelName: rcx, pResponse: rdx) -> eax
; Shows model information
;==============================================================================
PUBLIC OllamaShowModel
ALIGN 16
OllamaShowModel PROC
    LOCAL request:HTTP_REQUEST
    LOCAL jsonBody[256]:BYTE
    LOCAL response:QWORD
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 256
    
    mov r12, rcx        ; modelName
    mov r13, rdx        ; pResponse
    
    ; Format JSON request
    lea rcx, jsonBody
    lea rdx, szShowJson
    mov r8, r12
    call wsprintfA
    
    ; Get body length
    lea rcx, jsonBody
    call lstrlenA
    mov rdi, rax
    
    ; Setup request
    mov [request.method], HTTP_METHOD_POST
    lea rax, szApiShow
    mov [request.url], rax
    xor rax, rax
    mov [request.headers], rax
    lea rax, jsonBody
    mov [request.body], rax
    mov [request.body_len], rdi
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz show_fail
    
    mov response, rax
    
    ; Store response pointer
    test r13, r13
    jz show_done
    mov [r13], rax
    
    lea rcx, szOllamaSuccess
    call LogInfo
    
    mov eax, 1
    jmp show_done
    
show_fail:
    lea rcx, szOllamaError
    call LogError
    xor eax, eax
    
show_done:
    add rsp, 256
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaShowModel ENDP

;==============================================================================
; PUBLIC: OllamaDeleteModel(modelName: rcx) -> eax
; Deletes a model
;==============================================================================
PUBLIC OllamaDeleteModel
ALIGN 16
OllamaDeleteModel PROC
    LOCAL request:HTTP_REQUEST
    LOCAL jsonBody[256]:BYTE
    LOCAL response:QWORD
    
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 256
    
    mov r12, rcx        ; modelName
    
    ; Format JSON request
    lea rcx, jsonBody
    lea rdx, szDeleteJson
    mov r8, r12
    call wsprintfA
    
    ; Get body length
    lea rcx, jsonBody
    call lstrlenA
    mov rdi, rax
    
    ; Setup request
    mov [request.method], HTTP_METHOD_DELETE
    lea rax, szApiDelete
    mov [request.url], rax
    xor rax, rax
    mov [request.headers], rax
    lea rax, jsonBody
    mov [request.body], rax
    mov [request.body_len], rdi
    mov [request.timeout], 0
    
    ; Execute request
    lea rcx, g_HttpClient
    lea rdx, request
    call HttpClientRequest
    
    test rax, rax
    jz delete_fail
    
    mov response, rax
    
    ; Free response
    mov rcx, rax
    call asm_free
    
    lea rcx, szOllamaSuccess
    call LogInfo
    
    mov eax, 1
    jmp delete_done
    
delete_fail:
    lea rcx, szOllamaError
    call LogError
    xor eax, eax
    
delete_done:
    add rsp, 256
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
OllamaDeleteModel ENDP

END

