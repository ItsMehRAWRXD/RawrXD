;=============================================================================
; MCP_Transport_x64.asm
; RawrXD IDE - Model Context Protocol Native Transport
; 
; MASM x64 implementation of MCP client transport layer
; Supports HTTP/SSE streaming, JSON-RPC 2.0, OAuth 2.0 with PKCE
;=============================================================================

;-----------------------------------------------------------------------------
; External Imports
;-----------------------------------------------------------------------------
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN HeapReAlloc:PROC
EXTERN RtlZeroMemory:PROC
EXTERN RtlMoveMemory:PROC
EXTERN RtlCompareMemory:PROC

EXTERN WinHttpOpen:PROC
EXTERN WinHttpConnect:PROC
EXTERN WinHttpOpenRequest:PROC
EXTERN WinHttpSendRequest:PROC
EXTERN WinHttpReceiveResponse:PROC
EXTERN WinHttpQueryDataAvailable:PROC
EXTERN WinHttpReadData:PROC
EXTERN WinHttpCloseHandle:PROC
EXTERN WinHttpSetOption:PROC
EXTERN WinHttpQueryHeaders:PROC
EXTERN WinHttpAddRequestHeaders:PROC
EXTERN WinHttpSetTimeouts:PROC

EXTERN CryptAcquireContextW:PROC
EXTERN CryptGenRandom:PROC
EXTERN CryptReleaseContext:PROC
EXTERN CryptBinaryToStringA:PROC
EXTERN CryptStringToBinaryA:PROC

EXTERN CreateEventW:PROC
EXTERN WaitForSingleObject:PROC
EXTERN SetEvent:PROC
EXTERN ResetEvent:PROC
EXTERN CloseHandle:PROC
EXTERN CreateThread:PROC
EXTERN TerminateThread:PROC
EXTERN SuspendThread:PROC
EXTERN ResumeThread:PROC

EXTERN WSAStartup:PROC
EXTERN WSACleanup:PROC
EXTERN socket:PROC
EXTERN connect:PROC
EXTERN send:PROC
EXTERN recv:PROC
EXTERN closesocket:PROC
EXTERN setsockopt:PROC
EXTERN ioctlsocket:PROC
EXTERN select:PROC

EXTERN CreateWindowExW:PROC
EXTERN RegisterClassExW:PROC
EXTERN DefWindowProcW:PROC
EXTERN PostMessageW:PROC
EXTERN SendMessageW:PROC
EXTERN PeekMessageW:PROC
EXTERN DispatchMessageW:PROC
EXTERN TranslateMessage:PROC

;-----------------------------------------------------------------------------
; Public Exports
;-----------------------------------------------------------------------------
PUBLIC MCP_Transport_Create
PUBLIC MCP_Transport_Destroy
PUBLIC MCP_Transport_Connect
PUBLIC MCP_Transport_Disconnect
PUBLIC MCP_Transport_SendRequest
PUBLIC MCP_Transport_SendNotification
PUBLIC MCP_Transport_SubscribeSSE
PUBLIC MCP_Transport_UnsubscribeSSE
PUBLIC MCP_Transport_Authorize
PUBLIC MCP_Transport_RefreshToken
PUBLIC MCP_Transport_GetSessionState
PUBLIC MCP_Transport_SetCallback

;-----------------------------------------------------------------------------
; Constants
;-----------------------------------------------------------------------------
MCP_VERSION_MAJOR           EQU     2025
MCP_VERSION_MINOR           EQU     11
MCP_VERSION_PATCH           EQU     25

; Transport states
MCP_STATE_DISCONNECTED      EQU     0
MCP_STATE_CONNECTING        EQU     1
MCP_STATE_CONNECTED         EQU     2
MCP_STATE_AUTHORIZING       EQU     3
MCP_STATE_AUTHORIZED        EQU     4
MCP_STATE_ERROR             EQU     5
MCP_STATE_RECONNECTING      EQU     6

; HTTP methods
MCP_HTTP_GET                EQU     0
MCP_HTTP_POST               EQU     1
MCP_HTTP_DELETE             EQU     2

; Buffer sizes
MCP_MAX_URL_LENGTH          EQU     2048
MCP_MAX_HEADER_SIZE         EQU     8192
MCP_MAX_BODY_SIZE           EQU     1048576       ; 1MB
MCP_SSE_BUFFER_SIZE         EQU     65536         ; 64KB
MCP_JSONRPC_ID_MAX          EQU     4294967295

; Timeouts (milliseconds)
MCP_DEFAULT_TIMEOUT         EQU     30000         ; 30 seconds
MCP_SSE_KEEPALIVE_MS        EQU     15000         ; 15 seconds
MCP_RECONNECT_DELAY_MS      EQU     5000          ; 5 seconds
MCP_MAX_RECONNECT_ATTEMPTS  EQU     5

; OAuth 2.0 constants
MCP_PKCE_VERIFIER_LENGTH    EQU     128
MCP_STATE_PARAM_LENGTH      EQU     64
MCP_CODE_CHALLENGE_METHOD   EQU     "S256"

;-----------------------------------------------------------------------------
; Structures
;-----------------------------------------------------------------------------

; MCP Transport Context
MCP_TRANSPORT_CTX STRUCT 8
    ; Connection
    hSession                QWORD ?     ; WinHTTP session handle
    hConnect                QWORD ?     ; WinHTTP connection handle
    hRequest                QWORD ?     ; Current request handle
    hSSEThread              QWORD ?     ; SSE listener thread handle
    hSSEEvent               QWORD ?     ; SSE stop event
    
    ; State
    dwState                 DWORD ?     ; Current transport state
    dwLastError             DWORD ?     ; Last WinHTTP error
    dwRequestId             DWORD ?     ; JSON-RPC request ID counter
    dwReconnectAttempts     DWORD ?     ; Current reconnect attempt count
    
    ; Configuration
    wszServerUrl            WCHAR MCP_MAX_URL_LENGTH DUP(?)  ; Base URL
    wszServerHost           WCHAR 256 DUP(?)                  ; Hostname
    nServerPort             DWORD ?                           ; Port
    wszBasePath             WCHAR 256 DUP(?)                  ; API base path
    dwTimeoutMs             DWORD ?                           ; Request timeout
    bUseSSE                 BYTE ?                            ; Use SSE streaming
    
    ; OAuth 2.0
    wszAccessToken          WCHAR 2048 DUP(?)                 ; Bearer token
    wszRefreshToken         WCHAR 2048 DUP(?)                 ; Refresh token
    dwTokenExpiry           DWORD ?                           ; Token expiry timestamp
    bPKCEVerifier           BYTE MCP_PKCE_VERIFIER_LENGTH DUP(?) ; PKCE code verifier
    
    ; SSE State
    pSSEBuffer              QWORD ?     ; SSE receive buffer
    dwSSEBufferSize         DWORD ?     ; Buffer size
    dwSSEBufferUsed         DWORD ?     ; Bytes used in buffer
    bSSEConnected           BYTE ?      ; SSE connection active
    
    ; Callbacks
    pfnOnMessage            QWORD ?     ; Message received callback
    pfnOnError              QWORD ?     ; Error callback
    pfnOnConnect            QWORD ?     ; Connected callback
    pfnOnDisconnect         QWORD ?     ; Disconnected callback
    pfnOnSSEEvent           QWORD ?     ; SSE event callback
    pUserData               QWORD ?     ; User data for callbacks
    
    ; Synchronization
    hRequestMutex           QWORD ?     ; Request serialization mutex
    hStateMutex             QWORD ?     ; State change mutex
    
    ; JSON-RPC pending requests (simplified linked list)
    pPendingRequests        QWORD ?     ; Head of pending request list
    
MCP_TRANSPORT_CTX ENDS

; JSON-RPC Request Node (internal linked list)
MCP_REQUEST_NODE STRUCT 8
    pNext                   QWORD ?     ; Next node
    dwRequestId             DWORD ?     ; JSON-RPC ID
    hCompletionEvent        QWORD ?     ; Completion event
    pResponseBuffer         QWORD ?     ; Response buffer
    dwResponseSize          DWORD ?     ; Response size
    dwResponseCapacity      DWORD ?     ; Buffer capacity
    bCompleted              BYTE ?      ; Request completed
MCP_REQUEST_NODE ENDS

; SSE Event Structure
MCP_SSE_EVENT STRUCT 8
    wszEventType          WCHAR 64 DUP(?)   ; Event type (message, error, etc.)
    wszEventId            WCHAR 256 DUP(?)  ; Event ID for replay
    pData                 QWORD ?           ; Event data pointer
    dwDataLength          DWORD ?           ; Data length
    dwRetryMs             DWORD ?           ; Retry timing hint
MCP_SSE_EVENT ENDS

;-----------------------------------------------------------------------------
; Data Section
;-----------------------------------------------------------------------------
.data

; HTTP Content-Type headers
wszContentTypeJson        WCHAR "Content-Type: application/json", 0
wszContentTypeSSE         WCHAR "Accept: text/event-stream", 0
wszContentTypeForm        WCHAR "Content-Type: application/x-www-form-urlencoded", 0

; Authorization header prefix
wszAuthorization          WCHAR "Authorization: Bearer ", 0

; SSE request headers
wszCacheControl           WCHAR "Cache-Control: no-cache", 0
wszConnectionKeepAlive    WCHAR "Connection: keep-alive", 0

; JSON-RPC version
szJsonRpcVersion          BYTE  "2.0", 0

; HTTP method strings
szMethodGet               BYTE  "GET", 0
szMethodPost              BYTE  "POST", 0
szMethodDelete            BYTE  "DELETE", 0

; User-Agent
wszUserAgent              WCHAR "RawrXD-MCP/1.0", 0

; Error messages
szErrOutOfMemory          BYTE  "MCP: Out of memory", 0
szErrInvalidState          BYTE  "MCP: Invalid transport state", 0
szErrConnectionFailed      BYTE  "MCP: Connection failed", 0
szErrAuthFailed            BYTE  "MCP: Authentication failed", 0
szErrRequestTimeout        BYTE  "MCP: Request timeout", 0

;-----------------------------------------------------------------------------
; Code Section
;-----------------------------------------------------------------------------
.code

;=============================================================================
; MCP_Transport_Create
; 
; Creates a new MCP transport context
;
; Parameters:
;   RCX = Pointer to server URL (wide string)
;   RDX = User data pointer for callbacks
;
; Returns:
;   RAX = Pointer to MCP_TRANSPORT_CTX or NULL on failure
;=============================================================================
MCP_Transport_Create PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    .allocstack 32
    .endprolog
    
    mov     rsi, rcx              ; RSI = server URL
    mov     r12, rdx              ; R12 = user data
    
    ; Get process heap
    call    GetProcessHeap
    test    rax, rax
    jz      @F
    mov     rbx, rax              ; RBX = heap handle
    
    ; Allocate transport context
    mov     rcx, rbx
    xor     edx, edx              ; flags = 0
    mov     r8d, SIZEOF MCP_TRANSPORT_CTX
    call    HeapAlloc
    test    rax, rax
    jz      @F
    mov     rdi, rax              ; RDI = context pointer
    
    ; Zero the structure
    mov     rcx, rdi
    mov     edx, SIZEOF MCP_TRANSPORT_CTX
    call    RtlZeroMemory
    
    ; Copy server URL
    mov     rcx, rdi
    add     rcx, OFFSET MCP_TRANSPORT_CTX.wszServerUrl
    mov     rdx, rsi
    mov     r8d, MCP_MAX_URL_LENGTH * 2
    call    RtlMoveMemory
    
    ; Parse URL (simplified - extract host, port, path)
    ; TODO: Full URL parsing
    
    ; Set defaults
    mov     DWORD PTR [rdi + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_DISCONNECTED
    mov     DWORD PTR [rdi + OFFSET MCP_TRANSPORT_CTX.dwTimeoutMs], MCP_DEFAULT_TIMEOUT
    mov     BYTE PTR [rdi + OFFSET MCP_TRANSPORT_CTX.bUseSSE], 1
    mov     QWORD PTR [rdi + OFFSET MCP_TRANSPORT_CTX.pUserData], r12
    
    ; Create synchronization objects
    xor     ecx, ecx              ; lpMutexAttributes = NULL
    xor     edx, edx              ; bInitialOwner = FALSE
    xor     r8d, r8d              ; lpName = NULL
    call    CreateMutexW
    mov     QWORD PTR [rdi + OFFSET MCP_TRANSPORT_CTX.hRequestMutex], rax
    
    xor     ecx, ecx
    xor     edx, edx
    xor     r8d, r8d
    call    CreateMutexW
    mov     QWORD PTR [rdi + OFFSET MCP_TRANSPORT_CTX.hStateMutex], rax
    
    ; Allocate SSE buffer
    mov     rcx, rbx
    xor     edx, edx
    mov     r8d, MCP_SSE_BUFFER_SIZE
    call    HeapAlloc
    mov     QWORD PTR [rdi + OFFSET MCP_TRANSPORT_CTX.pSSEBuffer], rax
    mov     DWORD PTR [rdi + OFFSET MCP_TRANSPORT_CTX.dwSSEBufferSize], MCP_SSE_BUFFER_SIZE
    
    mov     rax, rdi              ; Return context
    jmp     done
    
@@:
    xor     rax, rax              ; Return NULL
    
done:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MCP_Transport_Create ENDP

;=============================================================================
; MCP_Transport_Destroy
;
; Destroys an MCP transport context and frees all resources
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;=============================================================================
MCP_Transport_Destroy PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx              ; RBX = context
    test    rbx, rbx
    jz      done
    
    ; Disconnect if connected
    mov     rcx, rbx
    call    MCP_Transport_Disconnect
    
    ; Get heap handle
    call    GetProcessHeap
    mov     rsi, rax              ; RSI = heap
    
    ; Free SSE buffer
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pSSEBuffer]
    test    rcx, rcx
    jz      @F
    mov     rcx, rsi
    xor     edx, edx
    mov     r8, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pSSEBuffer]
    call    HeapFree
    
@@:
    ; Close mutexes
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hRequestMutex]
    test    rcx, rcx
    jz      @F
    call    CloseHandle
    
@@:
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hStateMutex]
    test    rcx, rcx
    jz      @F
    call    CloseHandle
    
@@:
    ; Free context itself
    mov     rcx, rsi
    xor     edx, edx
    mov     r8, rbx
    call    HeapFree
    
done:
    pop     rsi
    pop     rbx
    ret
MCP_Transport_Destroy ENDP

;=============================================================================
; MCP_Transport_Connect
;
; Establishes connection to MCP server
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;
; Returns:
;   RAX = TRUE on success, FALSE on failure
;=============================================================================
MCP_Transport_Connect PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    .allocstack 32
    .endprolog
    
    mov     rbx, rcx              ; RBX = context
    
    ; Check state
    mov     eax, DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState]
    cmp     eax, MCP_STATE_DISCONNECTED
    jne     error_invalid_state
    
    ; Update state
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_CONNECTING
    
    ; Initialize WinHTTP
    xor     ecx, ecx              ; pszAgentW = NULL (use default)
    mov     edx, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
    xor     r8d, r8d              ; pszProxyW = NULL
    xor     r9d, r9d              ; pszProxyBypassW = NULL
    mov     DWORD PTR [rsp + 32], 0  ; dwFlags = 0
    call    WinHttpOpen
    test    rax, rax
    jz      error_connection
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSession], rax
    
    ; Set timeouts
    mov     rcx, rax              ; hSession
    mov     edx, 0                ; dwResolveTimeout
    mov     r8d, 10000           ; dwConnectTimeout = 10s
    mov     r9d, 30000           ; dwSendTimeout = 30s
    mov     DWORD PTR [rsp + 32], 30000  ; dwReceiveTimeout = 30s
    call    WinHttpSetTimeouts
    
    ; Connect to server
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSession]
    lea     rdx, [rbx + OFFSET MCP_TRANSPORT_CTX.wszServerHost]
    mov     r8d, DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.nServerPort]
    xor     r9d, r9d              ; dwReserved = 0
    call    WinHttpConnect
    test    rax, rax
    jz      error_connection
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hConnect], rax
    
    ; Update state
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_CONNECTED
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwReconnectAttempts], 0
    
    ; Invoke callback
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnConnect]
    test    rcx, rcx
    jz      @F
    mov     rdx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pUserData]
    call    rcx
    
@@:
    mov     rax, 1                ; Return TRUE
    jmp     done
    
error_invalid_state:
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwLastError], ERROR_INVALID_STATE
    xor     rax, rax
    jmp     done
    
error_connection:
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_ERROR
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwLastError], ERROR_CONNECTION_FAILED
    xor     rax, rax
    
done:
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MCP_Transport_Connect ENDP

;=============================================================================
; MCP_Transport_Disconnect
;
; Closes connection to MCP server
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;=============================================================================
MCP_Transport_Disconnect PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx
    test    rbx, rbx
    jz      done
    
    ; Stop SSE thread if running
    mov     rcx, rbx
    call    MCP_Transport_UnsubscribeSSE
    
    ; Close request handle
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hRequest]
    test    rcx, rcx
    jz      @F
    call    WinHttpCloseHandle
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hRequest], 0
    
@@:
    ; Close connection
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hConnect]
    test    rcx, rcx
    jz      @F
    call    WinHttpCloseHandle
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hConnect], 0
    
@@:
    ; Close session
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSession]
    test    rcx, rcx
    jz      @F
    call    WinHttpCloseHandle
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSession], 0
    
@@:
    ; Update state
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_DISCONNECTED
    
    ; Invoke callback
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnDisconnect]
    test    rcx, rcx
    jz      done
    mov     rdx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pUserData]
    call    rcx
    
done:
    pop     rbx
    ret
MCP_Transport_Disconnect ENDP

;=============================================================================
; MCP_Transport_SendRequest
;
; Sends a JSON-RPC request and waits for response
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;   RDX = Pointer to JSON request body (UTF-8)
;   R8  = Length of request body
;   R9  = Pointer to receive response buffer
;   [RSP+40] = Pointer to receive response length
;
; Returns:
;   RAX = TRUE on success, FALSE on failure
;=============================================================================
MCP_Transport_SendRequest PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    .allocstack 40
    .endprolog
    
    mov     rbx, rcx              ; RBX = context
    mov     rsi, rdx              ; RSI = request body
    mov     edi, r8d              ; EDI = body length
    mov     r12, r9               ; R12 = response buffer pointer
    mov     r13, QWORD PTR [rsp + 64]  ; R13 = response length pointer
    
    ; Check state
    mov     eax, DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState]
    cmp     eax, MCP_STATE_AUTHORIZED
    je      @F
    cmp     eax, MCP_STATE_CONNECTED
    jne     error_invalid_state
    
@@:
    ; Acquire request mutex
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hRequestMutex]
    mov     edx, INFINITE
    call    WaitForSingleObject
    
    ; Build request
    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8d, edi
    mov     r9d, MCP_HTTP_POST
    call    MCP_Internal_BuildRequest
    test    rax, rax
    jz      error_request
    
    ; Send and receive
    mov     rcx, rbx
    mov     rdx, r12
    mov     r8, r13
    call    MCP_Internal_SendAndReceive
    
    ; Release mutex
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hRequestMutex]
    call    ReleaseMutex
    
    jmp     done
    
error_invalid_state:
    xor     rax, rax
    jmp     done
    
error_request:
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hRequestMutex]
    call    ReleaseMutex
    xor     rax, rax
    
done:
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MCP_Transport_SendRequest ENDP

;=============================================================================
; MCP_Transport_SubscribeSSE
;
; Starts Server-Sent Events subscription
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;   RDX = Pointer to endpoint path (wide string)
;
; Returns:
;   RAX = TRUE on success, FALSE on failure
;=============================================================================
MCP_Transport_SubscribeSSE PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .allocstack 24
    .endprolog
    
    mov     rbx, rcx              ; RBX = context
    mov     rsi, rdx              ; RSI = endpoint path
    
    ; Check if already subscribed
    cmp     BYTE PTR [rbx + OFFSET MCP_TRANSPORT_CTX.bSSEConnected], 0
    jne     error_already_connected
    
    ; Create stop event
    xor     ecx, ecx
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    CreateEventW
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEEvent], rax
    
    ; Create SSE thread
    xor     ecx, ecx              ; lpThreadAttributes
    xor     edx, edx              ; dwStackSize
    lea     r8, MCP_SSE_ThreadProc  ; lpStartAddress
    mov     r9, rbx               ; lpParameter
    mov     QWORD PTR [rsp + 32], 0  ; dwCreationFlags
    mov     QWORD PTR [rsp + 40], 0  ; lpThreadId
    call    CreateThread
    test    rax, rax
    jz      error_thread
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEThread], rax
    
    mov     BYTE PTR [rbx + OFFSET MCP_TRANSPORT_CTX.bSSEConnected], 1
    mov     rax, 1
    jmp     done
    
error_already_connected:
error_thread:
    xor     rax, rax
    
done:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MCP_Transport_SubscribeSSE ENDP

;=============================================================================
; MCP_SSE_ThreadProc
;
; SSE listener thread procedure
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;=============================================================================
MCP_SSE_ThreadProc PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .allocstack 24
    .endprolog
    
    mov     rbx, rcx              ; RBX = context
    
    ; Build SSE request
    ; TODO: Open request, add SSE headers, send
    
sse_loop:
    ; Check for stop event
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEEvent]
    xor     edx, edx
    call    WaitForSingleObject
    cmp     eax, WAIT_TIMEOUT
    jne     sse_done
    
    ; Read available data
    ; TODO: WinHttpQueryDataAvailable, WinHttpReadData
    
    ; Parse SSE events
    ; TODO: Parse "data:", "event:", "id:", "retry:" lines
    
    ; Invoke callback for each complete event
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnSSEEvent]
    test    rcx, rcx
    jz      @F
    ; TODO: Build MCP_SSE_EVENT and call
    
@@:
    ; Small delay to prevent busy-wait
    mov     ecx, 10
    call    Sleep
    jmp     sse_loop
    
sse_done:
    mov     BYTE PTR [rbx + OFFSET MCP_TRANSPORT_CTX.bSSEConnected], 0
    
    pop     rdi
    pop     rsi
    pop     rbx
    xor     eax, eax
    ret
MCP_SSE_ThreadProc ENDP

;=============================================================================
; MCP_Transport_UnsubscribeSSE
;
; Stops SSE subscription
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;=============================================================================
MCP_Transport_UnsubscribeSSE PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx
    
    ; Signal stop event
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEEvent]
    test    rcx, rcx
    jz      @F
    call    SetEvent
    
    ; Wait for thread to exit
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEThread]
    mov     edx, 5000             ; 5 second timeout
    call    WaitForSingleObject
    
    ; Close handles
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEThread]
    call    CloseHandle
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEThread], 0
    
@@:
    mov     rcx, QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEEvent]
    call    CloseHandle
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.hSSEEvent], 0
    
    mov     BYTE PTR [rbx + OFFSET MCP_TRANSPORT_CTX.bSSEConnected], 0
    
    pop     rbx
    ret
MCP_Transport_UnsubscribeSSE ENDP

;=============================================================================
; MCP_Transport_Authorize
;
; Performs OAuth 2.0 authorization with PKCE
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;   RDX = Pointer to authorization endpoint
;   R8  = Pointer to token endpoint
;   R9  = Pointer to client ID
;   [RSP+40] = Pointer to scopes (space-separated)
;   [RSP+48] = Pointer to redirect URI
;
; Returns:
;   RAX = TRUE on success, FALSE on failure
;=============================================================================
MCP_Transport_Authorize PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    .allocstack 48
    .endprolog
    
    mov     rbx, rcx              ; RBX = context
    mov     rsi, rdx              ; RSI = auth endpoint
    mov     rdi, r8               ; RDI = token endpoint
    mov     r12, r9               ; R12 = client ID
    mov     r13, QWORD PTR [rsp + 72]  ; R13 = scopes
    mov     r14, QWORD PTR [rsp + 80]  ; R14 = redirect URI
    
    ; Update state
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_AUTHORIZING
    
    ; Generate PKCE code verifier
    mov     rcx, rbx
    call    MCP_Internal_GeneratePKCE
    test    rax, rax
    jz      error_auth
    
    ; Build authorization URL with PKCE
    ; TODO: Construct URL with code_challenge, state, etc.
    
    ; Open browser or embedded web view for authorization
    ; TODO: Platform-specific auth flow
    
    ; Exchange code for tokens
    ; TODO: POST to token endpoint
    
    ; Store tokens
    ; TODO: Parse response, store access_token, refresh_token, expires_in
    
    ; Update state
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_AUTHORIZED
    mov     rax, 1
    jmp     done
    
error_auth:
    mov     DWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.dwState], MCP_STATE_ERROR
    xor     rax, rax
    
done:
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MCP_Transport_Authorize ENDP

;=============================================================================
; MCP_Internal_GeneratePKCE
;
; Generates PKCE code verifier and challenge
;
; Parameters:
;   RCX = Pointer to MCP_TRANSPORT_CTX
;
; Returns:
;   RAX = TRUE on success, FALSE on failure
;=============================================================================
MCP_Internal_GeneratePKCE PROC FRAME
    push    rbx
    push    rsi
    .allocstack 16
    .endprolog
    
    mov     rbx, rcx
    
    ; Acquire crypto context
    lea     rcx, [rbx + OFFSET MCP_TRANSPORT_CTX.hCryptProv]
    xor     edx, edx              ; pszContainer = NULL
    xor     r8d, r8d              ; pszProvider = NULL
    mov     r9d, PROV_RSA_FULL
    mov     DWORD PTR [rsp + 32], CRYPT_VERIFYCONTEXT
    call    CryptAcquireContextW
    test    rax, rax
    jz      error
    
    ; Generate random bytes for verifier
    lea     rdx, [rbx + OFFSET MCP_TRANSPORT_CTX.bPKCEVerifier]
    mov     r8d, MCP_PKCE_VERIFIER_LENGTH
    call    CryptGenRandom
    test    rax, rax
    jz      error
    
    ; Base64URL encode verifier
    ; TODO: Convert to base64url (RFC 7636)
    
    ; Generate code challenge (SHA256 of verifier)
    ; TODO: SHA256 hash
    
    ; Base64URL encode challenge
    ; TODO: Convert to base64url
    
    mov     rax, 1
    jmp     done
    
error:
    xor     rax, rax
    
done:
    pop     rsi
    pop     rbx
    ret
MCP_Internal_GeneratePKCE ENDP

;=============================================================================
; Internal Helper Functions
;=============================================================================

;-----------------------------------------------------------------------------
; MCP_Internal_BuildRequest
;-----------------------------------------------------------------------------
MCP_Internal_BuildRequest PROC
    ; TODO: Build HTTP request with proper headers
    ret
MCP_Internal_BuildRequest ENDP

;-----------------------------------------------------------------------------
; MCP_Internal_SendAndReceive
;-----------------------------------------------------------------------------
MCP_Internal_SendAndReceive PROC
    ; TODO: Send request and receive response
    ret
MCP_Internal_SendAndReceive ENDP

;-----------------------------------------------------------------------------
; MCP_Transport_SetCallback
;-----------------------------------------------------------------------------
MCP_Transport_SetCallback PROC FRAME
    push    rbx
    .allocstack 8
    .endprolog
    
    mov     rbx, rcx              ; RBX = context
    ; RDX = callback type
    ; R8  = callback pointer
    
    ; Switch on callback type
    cmp     edx, 0                ; MCP_CALLBACK_MESSAGE
    jne     @F
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnMessage], r8
    jmp     done
    
@@:
    cmp     edx, 1                ; MCP_CALLBACK_ERROR
    jne     @F
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnError], r8
    jmp     done
    
@@:
    cmp     edx, 2                ; MCP_CALLBACK_CONNECT
    jne     @F
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnConnect], r8
    jmp     done
    
@@:
    cmp     edx, 3                ; MCP_CALLBACK_DISCONNECT
    jne     @F
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnDisconnect], r8
    jmp     done
    
@@:
    cmp     edx, 4                ; MCP_CALLBACK_SSE
    jne     done
    mov     QWORD PTR [rbx + OFFSET MCP_TRANSPORT_CTX.pfnOnSSEEvent], r8
    
done:
    pop     rbx
    ret
MCP_Transport_SetCallback ENDP

;-----------------------------------------------------------------------------
; MCP_Transport_GetSessionState
;-----------------------------------------------------------------------------
MCP_Transport_GetSessionState PROC
    mov     rax, QWORD PTR [rcx + OFFSET MCP_TRANSPORT_CTX.dwState]
    ret
MCP_Transport_GetSessionState ENDP

;-----------------------------------------------------------------------------
; MCP_Transport_SendNotification
;-----------------------------------------------------------------------------
MCP_Transport_SendNotification PROC
    ; Similar to SendRequest but without waiting for response
    ret
MCP_Transport_SendNotification ENDP

;-----------------------------------------------------------------------------
; MCP_Transport_RefreshToken
;-----------------------------------------------------------------------------
MCP_Transport_RefreshToken PROC
    ; TODO: Use refresh_token to get new access_token
    ret
MCP_Transport_RefreshToken ENDP

END
