; Simple Named Pipe Bytecode Injection Server for Testing
; Assembles with: ml64.exe /c /Zi /Zd /Fo pipe_server.obj pipe_server.asm
; Links with: link.exe /SUBSYSTEM:CONSOLE /OUT:pipe_server.exe pipe_server.obj kernel32.lib

; ============================================================================
; Imports
; ============================================================================
EXTERN CreateNamedPipeA:PROC
EXTERN ConnectNamedPipe:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN GetStdHandle:PROC
EXTERN DisconnectNamedPipe:PROC
EXTERN CloseHandle:PROC
EXTERN ExitProcess:PROC
EXTERN GetLastError:PROC
EXTERN Sleep:PROC

; ============================================================================
; Data Section
; ============================================================================
.data

; Pipe configuration
pipeName        BYTE "\\\\.\\pipe\\RawrXD_Inference", 0
pipeBufferSize  EQU 4096

; Response messages
responseOk      BYTE '{"status":"ok","epoch":1}', 13, 10, 0
responseLen     EQU $ - responseOk - 1

errorMsg        BYTE "[SERVER] Error occurred", 13, 10, 0
errorLen        EQU $ - errorMsg - 1

connectedMsg    BYTE "[SERVER] Client connected", 13, 10, 0
connectedLen    EQU $ - connectedMsg - 1

waitingMsg      BYTE "[SERVER] Waiting for connection...", 13, 10, 0
waitingLen      EQU $ - waitingMsg - 1

; Buffer for incoming data
align 16
readBuffer      BYTE pipeBufferSize DUP(0)
bytesRead       DWORD 0
bytesWritten    DWORD 0
hPipe           QWORD 0
hStdOut         QWORD 0

; ============================================================================
; Code Section
; ============================================================================
.code

; ============================================================================
; Entry Point
; ============================================================================
main PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 40
    .endprolog
    
    ; Get stdout handle for logging
    mov rcx, -11              ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov hStdOut, rax
    
    ; Print waiting message
    mov rcx, hStdOut
    lea rdx, waitingMsg
    mov r8d, waitingLen
    lea r9, bytesWritten
    mov QWORD PTR [rsp+32], 0
    call WriteFile
    
    ; Create named pipe
    ; CreateNamedPipeA(
    ;   lpName = pipeName,
    ;   dwOpenMode = PIPE_ACCESS_DUPLEX,
    ;   dwPipeMode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
    ;   nMaxInstances = 1,
    ;   nOutBufferSize = pipeBufferSize,
    ;   nInBufferSize = pipeBufferSize,
    ;   nDefaultTimeOut = 0,
    ;   lpSecurityAttributes = NULL
    ; )
    lea rcx, pipeName
    mov edx, 3                ; PIPE_ACCESS_DUPLEX
    mov r8d, 0                ; PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
    mov r9d, 1                ; nMaxInstances
    mov DWORD PTR [rsp+32], pipeBufferSize
    mov DWORD PTR [rsp+40], pipeBufferSize
    mov DWORD PTR [rsp+48], 0
    mov QWORD PTR [rsp+56], 0
    call CreateNamedPipeA
    
    cmp rax, -1
    je error_exit
    mov hPipe, rax
    
    ; Wait for client connection
    mov rcx, hPipe
    call ConnectNamedPipe
    
    ; Print connected message
    mov rcx, hStdOut
    lea rdx, connectedMsg
    mov r8d, connectedLen
    lea r9, bytesWritten
    mov QWORD PTR [rsp+32], 0
    call WriteFile
    
    ; Read request from client
    mov rcx, hPipe
    lea rdx, readBuffer
    mov r8d, pipeBufferSize
    lea r9, bytesRead
    mov QWORD PTR [rsp+32], 0
    call ReadFile
    
    test rax, rax
    jz error_disconnect
    
    ; Echo back what we received (for debugging)
    mov rcx, hStdOut
    lea rdx, readBuffer
    mov r8d, bytesRead
    lea r9, bytesWritten
    mov QWORD PTR [rsp+32], 0
    call WriteFile
    
    ; Send OK response
    mov rcx, hPipe
    lea rdx, responseOk
    mov r8d, responseLen
    lea r9, bytesWritten
    mov QWORD PTR [rsp+32], 0
    call WriteFile
    
error_disconnect:
    ; Disconnect and close pipe
    mov rcx, hPipe
    call DisconnectNamedPipe
    
    mov rcx, hPipe
    call CloseHandle
    
    ; Exit successfully
    xor rcx, rcx
    call ExitProcess
    
error_exit:
    ; Print error
    mov rcx, hStdOut
    lea rdx, errorMsg
    mov r8d, errorLen
    lea r9, bytesWritten
    mov QWORD PTR [rsp+32], 0
    call WriteFile
    
    mov rcx, 1
    call ExitProcess

main ENDP

END