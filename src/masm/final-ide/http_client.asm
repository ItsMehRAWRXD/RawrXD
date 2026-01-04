;==============================================================================
; http_client.asm - Production-Ready HTTP Client for RawrXD IDE
; ==============================================================================
; Implements HTTP/1.1 client using WinHTTP for Ollama and other API calls.
; Zero C++ runtime dependencies.
;==============================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib winhttp.lib

include logging.inc

;==============================================================================
; HTTP CONSTANTS
;==============================================================================
HTTP_METHOD_GET     EQU 1
HTTP_METHOD_POST     EQU 2
HTTP_METHOD_PUT      EQU 3
HTTP_METHOD_DELETE   EQU 4

HTTP_STATUS_OK       EQU 200
HTTP_STATUS_CREATED   EQU 201
HTTP_STATUS_BAD_REQUEST EQU 400
HTTP_STATUS_NOT_FOUND EQU 404
HTTP_STATUS_ERROR    EQU 500

MAX_HTTP_RESPONSE    EQU 10485760  ; 10MB
MAX_HTTP_HEADERS     EQU 4096
MAX_URL_LENGTH       EQU 2048

;==============================================================================
; EXTERNAL DECLARATIONS
;==============================================================================
EXTERN WinHttpOpen:PROC
EXTERN WinHttpConnect:PROC
EXTERN WinHttpOpenRequest:PROC
EXTERN WinHttpSendRequest:PROC
EXTERN WinHttpReceiveResponse:PROC
EXTERN WinHttpQueryDataAvailable:PROC
EXTERN WinHttpReadData:PROC
EXTERN WinHttpCloseHandle:PROC
EXTERN WinHttpAddRequestHeaders:PROC
EXTERN lstrlenA:PROC
EXTERN lstrcpyA:PROC
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC

;==============================================================================
; STRUCTURES
;==============================================================================
HTTP_REQUEST STRUCT
    method          DWORD ?
    url             QWORD ?
    headers         QWORD ?
    body            QWORD ?
    body_len        QWORD ?
    timeout         DWORD ?
HTTP_REQUEST ENDS

HTTP_RESPONSE STRUCT
    status_code     DWORD ?
    headers         QWORD ?
    body            QWORD ?
    body_len        QWORD ?
HTTP_RESPONSE ENDS

HTTP_CLIENT STRUCT
    hSession        QWORD ?
    hConnect        QWORD ?
    base_url        QWORD ?
    timeout         DWORD ?
    user_agent      QWORD ?
HTTP_CLIENT ENDS

;==============================================================================
; DATA SEGMENT
;==============================================================================
.data?
    g_HttpClient    HTTP_CLIENT <>
    response_buffer BYTE MAX_HTTP_RESPONSE DUP (?)
    header_buffer   BYTE MAX_HTTP_HEADERS DUP (?)

.data
    szUserAgent     BYTE "RawrXD-IDE/1.0",0
    szDefaultHost   BYTE "localhost",0
    szDefaultPort   BYTE "11434",0  ; Ollama default
    szContentType   BYTE "Content-Type: application/json",13,10,0
    szAccept        BYTE "Accept: application/json",13,10,0
    szHttpSuccess   BYTE "HTTP request completed successfully",0
    szHttpError     BYTE "HTTP request failed: %d",0
    szHttpConnError BYTE "Failed to connect to HTTP server",0

;==============================================================================
; CODE SEGMENT
;==============================================================================
.code

;==============================================================================
; PUBLIC: HttpClientInitialize(base_url: rcx, port: rdx) -> eax
;==============================================================================
PUBLIC HttpClientInitialize
ALIGN 16
HttpClientInitialize PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 64
    
    mov rbx, rcx        ; base_url
    mov rsi, rdx        ; port
    
    ; Open WinHTTP session
    lea rcx, szUserAgent
    mov rdx, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
    xor r8, r8
    xor r9, r9
    mov dword ptr [rsp + 32], 0  ; dwFlags
    call WinHttpOpen
    
    test rax, rax
    jz http_init_fail
    
    mov [g_HttpClient.hSession], rax
    
    ; Connect to server
    mov rcx, rax
    mov rdx, rbx        ; hostname
    mov r8, rsi         ; port
    xor r9, r9
    call WinHttpConnect
    
    test rax, rax
    jz http_connect_fail
    
    mov [g_HttpClient.hConnect], rax
    
    ; Store base URL
    mov [g_HttpClient.base_url], rbx
    
    ; Set timeout (30 seconds)
    mov dword ptr [g_HttpClient.timeout], 30000  ; Store user agent
    lea rax, szUserAgent
    mov [g_HttpClient.user_agent], rax
    
    lea rcx, szHttpSuccess
    call LogInfo
    
    mov eax, 1
    jmp http_init_done
    
http_connect_fail:
    mov rcx, [g_HttpClient.hSession]
    call WinHttpCloseHandle
    jmp http_init_fail
    
http_init_fail:
    lea rcx, szHttpConnError
    call LogError
    xor eax, eax
    
http_init_done:
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    ret
HttpClientInitialize ENDP

;==============================================================================
; PUBLIC: HttpClientRequest(pClient: rcx, pRequest: rdx) -> eax (response body or NULL)
;==============================================================================
PUBLIC HttpClientRequest
ALIGN 16
HttpClientRequest PROC
    LOCAL hRequest:QWORD
    LOCAL bytesRead:QWORD
    LOCAL totalRead:QWORD
    LOCAL dataAvailable:QWORD
    
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 512
    
    mov r12, rcx        ; pClient
    mov r13, rdx        ; pRequest
    
    ; Validate parameters
    test r12, r12
    jz http_req_fail
    test r13, r13
    jz http_req_fail
    
    ; Get method string
    mov eax, [r13 + HTTP_REQUEST.method]
    cmp eax, HTTP_METHOD_GET
    je set_get
    cmp eax, HTTP_METHOD_POST
    je set_post
    cmp eax, HTTP_METHOD_PUT
    je set_put
    cmp eax, HTTP_METHOD_DELETE
    je set_delete
    lea rbx, szGetMethod
    jmp method_set
    
set_get:
    lea rbx, szGetMethod
    jmp method_set
set_post:
    lea rbx, szPostMethod
    jmp method_set
set_put:
    lea rbx, szPutMethod
    jmp method_set
set_delete:
    lea rbx, szDeleteMethod
    
method_set:
    ; Open request
    mov rcx, [r12 + HTTP_CLIENT.hConnect]
    mov rdx, rbx        ; method
    mov r8, [r13 + HTTP_REQUEST.url]
    mov r9, 0           ; version (NULL = HTTP/1.1)
    mov dword ptr [rsp + 32], 0  ; referrer
    mov dword ptr [rsp + 40], 0  ; accept types
    mov [rsp + 48], WINHTTP_NO_REFERER
    call WinHttpOpenRequest
    
    test rax, rax
    jz http_req_fail
    
    mov hRequest, rax
    
    ; Add headers
    mov rcx, rax
    lea rdx, szContentType
    mov r8, -1          ; length (-1 = null-terminated)
    mov r9, WINHTTP_ADDREQ_FLAG_ADD or WINHTTP_ADDREQ_FLAG_REPLACE
    call WinHttpAddRequestHeaders
    
    mov rcx, hRequest
    lea rdx, szAccept
    mov r8, -1
    mov r9, WINHTTP_ADDREQ_FLAG_ADD or WINHTTP_ADDREQ_FLAG_REPLACE
    call WinHttpAddRequestHeaders
    
    ; Add custom headers if provided
    cmp [r13 + HTTP_REQUEST.headers], 0
    je skip_custom_headers
    
    mov rcx, hRequest
    mov rdx, [r13 + HTTP_REQUEST.headers]
    mov r8, -1
    mov r9, WINHTTP_ADDREQ_FLAG_ADD or WINHTTP_ADDREQ_FLAG_REPLACE
    call WinHttpAddRequestHeaders
    
skip_custom_headers:
    ; Send request
    mov rcx, hRequest
    mov rdx, [r13 + HTTP_REQUEST.body]
    mov r8, [r13 + HTTP_REQUEST.body_len]
    mov r9, [r13 + HTTP_REQUEST.body_len]
    mov dword ptr [rsp + 32], 0  ; dwTotalLength
    mov dword ptr [rsp + 40], 0  ; dwContext
    call WinHttpSendRequest
    
    test eax, eax
    jz http_send_fail
    
    ; Receive response
    mov rcx, hRequest
    xor rdx, rdx
    call WinHttpReceiveResponse
    
    test eax, eax
    jz http_receive_fail
    
    ; Read response data
    mov totalRead, 0
    lea r14, response_buffer
    
read_loop:
    ; Check available data
    mov rcx, hRequest
    lea rdx, dataAvailable
    call WinHttpQueryDataAvailable
    
    test eax, eax
    jz http_read_fail
    
    cmp dataAvailable, 0
    je read_complete
    
    ; Check buffer space
    mov rax, totalRead
    add rax, dataAvailable
    cmp rax, MAX_HTTP_RESPONSE - 1
    ja buffer_full
    
    ; Read data
    mov rcx, hRequest
    lea rdx, [r14 + totalRead]
    mov r8, dataAvailable
    lea r9, bytesRead
    call WinHttpReadData
    
    test eax, eax
    jz http_read_fail
    
    add totalRead, bytesRead
    jmp read_loop
    
buffer_full:
    ; Truncate at buffer limit
    mov rax, MAX_HTTP_RESPONSE - 1
    sub rax, totalRead
    mov rcx, hRequest
    lea rdx, [r14 + totalRead]
    mov r8, rax
    lea r9, bytesRead
    call WinHttpReadData
    
    add totalRead, bytesRead
    
read_complete:
    ; Null terminate
    mov rax, totalRead
    mov byte ptr [r14 + rax], 0
    
    ; Close request handle
    mov rcx, hRequest
    call WinHttpCloseHandle
    
    ; Allocate response buffer
    mov rcx, totalRead
    add rcx, 1          ; +1 for null terminator
    call asm_malloc
    
    test rax, rax
    jz http_alloc_fail
    
    ; Copy response data
    mov rdi, rax
    mov rsi, r14
    mov rcx, totalRead
    inc rcx
    rep movsb
    
    jmp http_req_done
    
http_alloc_fail:
http_read_fail:
http_receive_fail:
http_send_fail:
    mov rcx, hRequest
    call WinHttpCloseHandle
    jmp http_req_fail
    
http_req_fail:
    xor rax, rax
    
http_req_done:
    add rsp, 512
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
HttpClientRequest ENDP

;==============================================================================
; PUBLIC: HttpClientShutdown()
;==============================================================================
PUBLIC HttpClientShutdown
ALIGN 16
HttpClientShutdown PROC
    push rbx
    sub rsp, 32
    
    ; Close connection
    cmp [g_HttpClient.hConnect], 0
    je skip_connect
    
    mov rcx, [g_HttpClient.hConnect]
    call WinHttpCloseHandle
    mov [g_HttpClient.hConnect], 0
    
skip_connect:
    ; Close session
    cmp [g_HttpClient.hSession], 0
    je shutdown_done
    
    mov rcx, [g_HttpClient.hSession]
    call WinHttpCloseHandle
    mov [g_HttpClient.hSession], 0
    
shutdown_done:
    add rsp, 32
    pop rbx
    ret
HttpClientShutdown ENDP

.data
    szGetMethod     BYTE "GET",0
    szPostMethod    BYTE "POST",0
    szPutMethod     BYTE "PUT",0
    szDeleteMethod  BYTE "DELETE",0

END


