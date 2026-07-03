; ============================================================================
; RawrXD Named Pipe Bytecode Injection Server - Simplified
; MASM64 implementation for hotpatch router IPC
; ============================================================================

; =============================================================================
; External Imports
; =============================================================================
EXTERN CreateNamedPipeA:PROC
EXTERN ConnectNamedPipe:PROC
EXTERN DisconnectNamedPipe:PROC
EXTERN FlushFileBuffers:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN GetLastError:PROC
EXTERN CloseHandle:PROC
EXTERN RawrXD_ProcessPipePayload:PROC
EXTERN RawrXD_GetResponseBuffer:PROC
EXTERN RawrXD_GetPipeSecurityAttributes:PROC

; =============================================================================
; Data Section
; =============================================================================
.data

; Pipe configuration
PIPE_NAME               BYTE  '\\.\pipe\RawrXD_Inference', 0
PIPE_BUFFER_SIZE        EQU 4096

; Constants
INVALID_HANDLE_VALUE    EQU -1
ERROR_PIPE_CONNECTED    EQU 535

; Global state
g_PipeHandle            QWORD 0
g_ServerRunning         BYTE  0

; Buffers
g_RequestBuffer         BYTE  PIPE_BUFFER_SIZE DUP (0)
g_ResponseBuffer        BYTE  '{','"','s','t','a','t','u','s','"',':','"','o','k','"','}',10

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; RawrXD_PipeServer_Init
; Initialize the named pipe server
; Output: rax = 0 (success), 1 (error)
; =============================================================================
RawrXD_PipeServer_Init PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 64
    
    ; Check if already running
    mov al, g_ServerRunning
    test al, al
    jnz init_already_running
    
    ; Create named pipe
    ; rcx = lpName
    ; edx = dwOpenMode (PIPE_ACCESS_DUPLEX = 0x00000003)
    mov esi, DWORD PTR [rsp+48]    ; Preserve the written byte count before FlushFileBuffers/DisconnectNamedPipe.
    ; r9d = nMaxInstances (2) - 2 instances to overlap connect/disconnect, eliminating race window
    ; [rsp+32] = nOutBufferSize
    ; [rsp+40] = nInBufferSize
    ; [rsp+48] = nDefaultTimeOut
    ; [rsp+56] = lpSecurityAttributes
    
    ; Get security attributes from C++ callback (SDDL protected)
    call RawrXD_GetPipeSecurityAttributes
    mov r12, rax                    ; r12 = security attributes (may be NULL)
    
    mov rcx, OFFSET PIPE_NAME
    mov edx, 3                      ; PIPE_ACCESS_DUPLEX
    xor r8d, r8d                    ; PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
    mov r9d, 2                      ; nMaxInstances = 2 (allows overlapping connect/disconnect)
    
    mov DWORD PTR [rsp+32], PIPE_BUFFER_SIZE
    mov DWORD PTR [rsp+40], PIPE_BUFFER_SIZE
    mov DWORD PTR [rsp+48], 0       ; nDefaultTimeOut
    mov QWORD PTR [rsp+56], r12     ; lpSecurityAttributes (SDDL protected)
    
    call CreateNamedPipeA
    
    cmp rax, INVALID_HANDLE_VALUE
    je init_failed
    
    mov g_PipeHandle, rax
    mov g_ServerRunning, 1
    
    xor rax, rax                    ; Success
    jmp init_exit
    
init_already_running:
    mov rax, 1
    jmp init_exit
    
init_failed:
    mov rax, 1
    
init_exit:
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    ret
RawrXD_PipeServer_Init ENDP

; =============================================================================
; RawrXD_PipeServer_RunOnce
; Accept one connection and handle it
; Output: rax = 0 (success), 1 (error)
; =============================================================================
RawrXD_PipeServer_RunOnce PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 64
    
    ; Wait for client connection
    mov rcx, g_PipeHandle
    xor rdx, rdx                    ; lpOverlapped = NULL (blocking)
    call ConnectNamedPipe
    test eax, eax
    jnz runonce_connected
    call GetLastError
    cmp eax, ERROR_PIPE_CONNECTED
    je runonce_connected
    or eax, 10000000h               ; Connect error | Win32 code
    jmp runonce_exit

runonce_connected:
    
    ; Read request
    mov rcx, g_PipeHandle
    lea rdx, g_RequestBuffer
    mov r8d, PIPE_BUFFER_SIZE
    lea r9, [rsp+40]                ; lpNumberOfBytesRead
    mov QWORD PTR [rsp+32], 0       ; lpOverlapped (5th arg)
    call ReadFile
    test eax, eax
    jnz runonce_read_ok
    mov rcx, g_PipeHandle
    call DisconnectNamedPipe
    call GetLastError
    or eax, 20000000h               ; Read error | Win32 code
    jmp runonce_exit

runonce_read_ok:
    
    ; Preserve the byte count before the next Win32 call can touch stack scratch.
    mov ebx, DWORD PTR [rsp+40]

    ; Call C++ callback to process the payload
    ; rcx = request buffer, rdx = request length
    lea rcx, g_RequestBuffer
    mov edx, ebx
    call RawrXD_ProcessPipePayload
    ; rax = response length
    mov edi, eax                    ; edi = response length
    
    ; Get response buffer pointer
    call RawrXD_GetResponseBuffer
    ; rax = response buffer pointer
    mov rsi, rax                    ; rsi = response buffer

    ; Write response back to client
    mov rcx, g_PipeHandle
    mov rdx, rsi                    ; Response buffer
    mov r8d, edi                    ; Response length
    lea r9, [rsp+48]                ; lpNumberOfBytesWritten
    mov QWORD PTR [rsp+32], 0       ; lpOverlapped (5th arg)
    call WriteFile
    test eax, eax
    jnz runonce_write_ok
    mov rcx, g_PipeHandle
    call DisconnectNamedPipe
    call GetLastError
    or eax, 30000000h               ; Write error | Win32 code
    jmp runonce_exit

runonce_write_ok:
    
    ; Preserve the written byte count before FlushFileBuffers/DisconnectNamedPipe.
    mov esi, DWORD PTR [rsp+48]

    ; Flush write buffer to client BEFORE disconnecting
    ; Without this, DisconnectNamedPipe can discard unflushed bytes
    ; causing the client to receive 0 bytes even though WriteFile succeeded.
    mov rcx, g_PipeHandle
    call FlushFileBuffers
    
    ; Disconnect
    mov rcx, g_PipeHandle
    call DisconnectNamedPipe
    
    mov eax, esi                    ; Success: bytes written to client
    
runonce_exit:
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    ret
RawrXD_PipeServer_RunOnce ENDP

; =============================================================================
; RawrXD_PipeServer_Shutdown
; Shutdown the named pipe server
; =============================================================================
RawrXD_PipeServer_Shutdown PROC
    push rbx
    
    mov g_ServerRunning, 0
    
    mov rcx, g_PipeHandle
    test rcx, rcx
    jz shutdown_exit
    call CloseHandle
    mov g_PipeHandle, 0
    
shutdown_exit:
    xor rax, rax
    pop rbx
    ret
RawrXD_PipeServer_Shutdown ENDP

END