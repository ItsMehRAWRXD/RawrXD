; ============================================================================
; RawrXD Named Pipe Bytecode Injection Server
; MASM64 implementation for hotpatch router IPC
; ============================================================================
; Pipe: \\.\pipe\RawrXD_Inference
; Protocol: JSON-RPC 2.0 over named pipe
; ============================================================================

; =============================================================================
; External Imports
; =============================================================================
EXTERN CreateNamedPipeA:PROC
EXTERN ConnectNamedPipe:PROC
EXTERN DisconnectNamedPipe:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN GetLastError:PROC
EXTERN CreateThread:PROC
EXTERN ExitThread:PROC
EXTERN CloseHandle:PROC

; From hotpatch router
EXTERN RawrXD_RequestHotpatch:PROC
EXTERN RawrXD_CheckEpochSwap:PROC

; =============================================================================
; Data Section
; =============================================================================
.data

; Pipe configuration
PIPE_NAME               BYTE "\\\\.\\pipe\\RawrXD_Inference", 0
PIPE_BUFFER_SIZE        EQU 4096
PIPE_MAX_INSTANCES      EQU 1
INVALID_HANDLE_VALUE    EQU -1

; JSON-RPC constants
JSONRPC_VERSION         BYTE '{"jsonrpc":"2.0"', 0
JSONRPC_ERROR_PREFIX    BYTE ',"error":', 0
JSONRPC_RESULT_PREFIX   BYTE ',"result":', 0
JSONRPC_ID_PREFIX       BYTE ',"id":', 0

; Error codes
ERROR_PARSE             EQU -32700
ERROR_INVALID_REQUEST   EQU -32600
ERROR_METHOD_NOT_FOUND  EQU -32601
ERROR_INVALID_PARAMS    EQU -32602
ERROR_INTERNAL          EQU -32603

; Method names
METHOD_HOTPATCH         BYTE "hotpatch.inject", 0
METHOD_STATUS           BYTE "hotpatch.status", 0
METHOD_EPOCH            BYTE "hotpatch.epoch", 0

; Response templates
RESPONSE_SUCCESS        BYTE '{"jsonrpc":"2.0","result":"ok","id":0}', 0
RESPONSE_ERROR          BYTE '{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"},"id":0}', 0
RESPONSE_EPOCH          BYTE '{"jsonrpc":"2.0","result":{"epoch":0,"active":0},"id":0}', 0

; Global pipe handle
g_PipeHandle            QWORD 0
g_ServerRunning         BYTE  0
g_ThreadHandle          QWORD 0

; Request buffer (4KB aligned)
g_RequestBuffer         BYTE  PIPE_BUFFER_SIZE DUP (0)
g_ResponseBuffer        BYTE  PIPE_BUFFER_SIZE DUP (0)

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; RawrXD_PipeServer_Init
; Initialize and start the named pipe server
; Output: rax = 0 (success), non-zero (error code)
; =============================================================================
RawrXD_PipeServer_Init PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    .endprolog
    
    ; Check if already running
    mov al, g_ServerRunning
    test al, al
    jnz @already_running
    
    ; Create named pipe
    ; CreateNamedPipeA(
    ;   lpName = PIPE_NAME,
    ;   dwOpenMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
    ;   dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
    ;   nMaxInstances = PIPE_MAX_INSTANCES,
    ;   nOutBufferSize = PIPE_BUFFER_SIZE,
    ;   nInBufferSize = PIPE_BUFFER_SIZE,
    ;   nDefaultTimeOut = 0,
    ;   lpSecurityAttributes = NULL
    ; )
    
    xor r9d, r9d                    ; nDefaultTimeOut = 0
    mov r8d, PIPE_MAX_INSTANCES     ; nMaxInstances
    mov edx, PIPE_BUFFER_SIZE       ; nOutBufferSize
    mov ecx, PIPE_BUFFER_SIZE       ; nInBufferSize
    
    sub rsp, 48                     ; Shadow space + alignment
    
    mov QWORD PTR [rsp+32], 0       ; lpSecurityAttributes = NULL
    mov r9d, ecx                    ; nInBufferSize
    mov r8d, edx                    ; nOutBufferSize
    mov edx, 3                      ; PIPE_MAX_INSTANCES
    
    ; dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT = 0x00000000
    mov ecx, 0x00000003             ; PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
    
    lea rdx, PIPE_NAME
    xor ecx, ecx                    ; Will be set to proper value
    
    ; Actually: let's use the stack properly
    mov rcx, OFFSET PIPE_NAME       ; lpName
    mov edx, 0x00000003             ; PIPE_ACCESS_DUPLEX (0x00000003)
    xor r8d, r8d                   ; dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
    mov r9d, PIPE_MAX_INSTANCES     ; nMaxInstances
    
    mov DWORD PTR [rsp+32], PIPE_BUFFER_SIZE    ; nOutBufferSize
    mov DWORD PTR [rsp+40], PIPE_BUFFER_SIZE    ; nInBufferSize
    mov DWORD PTR [rsp+48], 0                   ; nDefaultTimeOut
    mov QWORD PTR [rsp+56], 0                   ; lpSecurityAttributes
    
    call CreateNamedPipeA
    
    add rsp, 48
    
    cmp rax, INVALID_HANDLE_VALUE
    je @create_failed
    
    mov g_PipeHandle, rax
    mov g_ServerRunning, 1
    
    ; Create server thread
    sub rsp, 40
    mov rcx, 0                      ; lpThreadAttributes
    mov rdx, 0                      ; dwStackSize
    mov r8, OFFSET RawrXD_PipeServer_Thread  ; lpStartAddress
    mov r9, 0                       ; lpParameter
    mov QWORD PTR [rsp+32], 0       ; dwCreationFlags
    mov QWORD PTR [rsp+40], 0       ; lpThreadId
    call CreateThread
    add rsp, 40
    
    test rax, rax
    jz @thread_failed
    
    mov g_ThreadHandle, rax
    
    xor rax, rax                    ; Success
    jmp @exit
    
@already_running:
    mov rax, 1                      ; Already running
    jmp @exit
    
@create_failed:
    mov rax, 2                      ; CreateNamedPipe failed
    jmp @exit
    
@thread_failed:
    mov rcx, g_PipeHandle
    call CloseHandle
    mov g_PipeHandle, 0
    mov rax, 3                      ; CreateThread failed
    
@exit:
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_PipeServer_Init ENDP

; =============================================================================
; RawrXD_PipeServer_Thread
; Main server thread - handles client connections
; =============================================================================
RawrXD_PipeServer_Thread PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    .endprolog
    
@connection_loop:
    ; Wait for client connection
    mov rcx, g_PipeHandle
    call ConnectNamedPipe
    
    ; Handle connection
    call RawrXD_PipeServer_HandleClient
    
    ; Disconnect and wait for next client
    mov rcx, g_PipeHandle
    call DisconnectNamedPipe
    
    ; Check if should continue
    mov al, g_ServerRunning
    test al, al
    jnz @connection_loop
    
    ; Exit thread
    xor ecx, ecx
    call ExitThread
    
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_PipeServer_Thread ENDP

; =============================================================================
; RawrXD_PipeServer_HandleClient
; Handle a single client connection
; =============================================================================
RawrXD_PipeServer_HandleClient PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    sub rsp, 32
    .endprolog
    
    ; Read request from pipe
    mov rcx, g_PipeHandle
    lea rdx, g_RequestBuffer
    mov r8d, PIPE_BUFFER_SIZE
    lea r9, [rsp+24]                ; lpNumberOfBytesRead
    mov QWORD PTR [rsp+48], 0       ; lpOverlapped = NULL
    call ReadFile
    
    test rax, rax
    jz @read_failed
    
    ; Parse and handle the request
    lea rcx, g_RequestBuffer
    call RawrXD_PipeServer_ProcessRequest
    
    ; Write response
    mov rcx, g_PipeHandle
    lea rdx, g_ResponseBuffer
    ; r8 = response length (set by ProcessRequest)
    lea r9, [rsp+24]                ; lpNumberOfBytesWritten
    mov QWORD PTR [rsp+48], 0       ; lpOverlapped = NULL
    call WriteFile
    
@read_failed:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_PipeServer_HandleClient ENDP

; =============================================================================
; RawrXD_PipeServer_ProcessRequest
; Parse JSON-RPC request and dispatch to appropriate handler
; Input: rcx = pointer to request buffer
; =============================================================================
RawrXD_PipeServer_ProcessRequest PROC FRAME
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    .endprolog
    
    ; TODO: Parse JSON-RPC request
    ; For now, just echo back a success response
    
    lea rdi, g_ResponseBuffer
    lea rsi, RESPONSE_SUCCESS
    mov rcx, OFFSET RESPONSE_SUCCESS
    call lstrlenA
    mov rcx, rax
    rep movsb
    
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
RawrXD_PipeServer_ProcessRequest ENDP

; =============================================================================
; RawrXD_PipeServer_Shutdown
; Shutdown the named pipe server
; =============================================================================
RawrXD_PipeServer_Shutdown PROC FRAME
    push rbp
    mov rbp, rsp
    .endprolog
    
    mov g_ServerRunning, 0
    
    ; Close pipe handle (this will unblock ConnectNamedPipe)
    mov rcx, g_PipeHandle
    test rcx, rcx
    jz @no_pipe
    call CloseHandle
    mov g_PipeHandle, 0
    
@no_pipe:
    xor rax, rax
    pop rbp
    ret
RawrXD_PipeServer_Shutdown ENDP

END