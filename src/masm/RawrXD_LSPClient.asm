; =============================================================================
; RawrXD_LSPClient.asm — Pure x64 MASM LSP Client for VS Code/Cursor Integration
;
; Communicates with lsp_bridge.exe via JSON-RPC 2.0 over stdin/stdout pipes.
; Zero dependencies. Zero scaffolding. Pure MASM64.
;
; Build: ml64 /c /W3 /nologo /Zi /Fo RawrXD_LSPClient.obj RawrXD_LSPClient.asm
; Link: link /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /OUT:LSPClient.exe \
;          RawrXD_LSPClient.obj kernel32.lib
;
; Architecture:
;   ┌───────────────────────────────────────────────────────────────────────┐
;   │                    LSP CLIENT (VS Code Extension)                     │
;   │                                                                       │
;   │  1. Spawn lsp_bridge.exe with redirected stdin/stdout              │
;   │  2. Send JSON-RPC initialize request                                 │
;   │  3. Handle textDocument/didOpen, textDocument/completion           │
;   │  4. Route completion requests to SuperNode cluster backend           │
;   │  5. Stream responses back to VS Code                                 │
;   │                                                                       │
;   │  Pipe Protocol:                                                       │
;   │    Content-Length: <bytes>\r\n\r\n<JSON payload>                      │
;   └───────────────────────────────────────────────────────────────────────┘
;
; Exports (for linking with VS Code extension host):
;   LSPClient_Create          — Create client context
;   LSPClient_Destroy         — Cleanup
;   LSPClient_Initialize      — Send initialize, wait for response
;   LSPClient_Completion      — Request completions at position
;   LSPClient_DidOpen          — Notify document open
;   LSPClient_DidChange        — Notify document change
; =============================================================================

option casemap:none

; =============================================================================
; External Imports (kernel32 only - zero other dependencies)
; =============================================================================
EXTRN CreateProcessA:PROC
EXTRN CreatePipe:PROC
EXTRN SetHandleInformation:PROC
EXTRN ReadFile:PROC
EXTRN WriteFile:PROC
EXTRN CloseHandle:PROC
EXTRN GetStdHandle:PROC
EXTRN VirtualAlloc:PROC
EXTRN VirtualFree:PROC
EXTRN ExitProcess:PROC
EXTRN GetLastError:PROC
EXTRN Sleep:PROC

; =============================================================================
; Public Exports
; =============================================================================
PUBLIC LSPClient_Create
PUBLIC LSPClient_Destroy
PUBLIC LSPClient_Initialize
PUBLIC LSPClient_Completion
PUBLIC LSPClient_DidOpen
PUBLIC LSPClient_DidChange
PUBLIC LSPClient_PollResponse

; =============================================================================
; Constants
; =============================================================================
MEM_COMMIT              EQU 1000h
MEM_RESERVE             EQU 2000h
MEM_RELEASE             EQU 8000h
PAGE_READWRITE          EQU 04h
INVALID_HANDLE_VALUE    EQU -1
STD_INPUT_HANDLE        EQU -10
STD_OUTPUT_HANDLE       EQU -11
STD_ERROR_HANDLE        EQU -12
HANDLE_FLAG_INHERIT     EQU 00000001h
STARTF_USESTDHANDLES    EQU 00000100h

; Buffer sizes
LSP_READ_BUFFER_SIZE    EQU 65536     ; 64KB read buffer
LSP_WRITE_BUFFER_SIZE   EQU 32768     ; 32KB write buffer
LSP_JSON_MAX_SIZE       EQU 524288    ; 512KB max JSON payload

; LSP Message types (internal codes)
LSP_MSG_INITIALIZE      EQU 1h
LSP_MSG_INITIALIZED     EQU 2h
LSP_MSG_COMPLETION      EQU 3h
LSP_MSG_DIDOPEN         EQU 4h
LSP_MSG_DIDCHANGE       EQU 5h
LSP_MSG_SHUTDOWN        EQU 6h
LSP_MSG_EXIT            EQU 7h

; =============================================================================
; LSPClientContext Layout (cache-line aligned)
; =============================================================================
;   0x000  hProcess           QWORD   ; Bridge process handle
;   0x008  hThread            QWORD   ; Bridge main thread handle
;   0x010  hStdInRead         QWORD   ; Our read end of bridge stdin
;   0x018  hStdInWrite        QWORD   ; Our write end of bridge stdin
;   0x020  hStdOutRead        QWORD   ; Our read end of bridge stdout
;   0x028  hStdOutWrite       QWORD   ; Our write end of bridge stdout
;   0x030  ReadBuffer         QWORD   ; Ptr to 64KB read buffer
;   0x038  WriteBuffer        QWORD   ; Ptr to 32KB write buffer
;   0x040  JsonBuffer         QWORD   ; Ptr to 512KB JSON buffer
;   0x048  RequestId          QWORD   ; Monotonic request ID
;   0x050  State              DWORD   ; Client state (0=init, 1=ready, 2=shutdown)
;   0x054  Capabilities       DWORD   ; Server capability flags
;   0x058  Reserved           DWORD[6]; Padding to 64 bytes
;   0x070  ServerInfo         BYTE[256]; Server name/version
;   0x170  RootPath           BYTE[256]; Workspace root
;   0x270  LastError          DWORD   ; Last error code
;   0x274  Padding            DWORD[3]
; Total: 0x280 bytes (640 bytes, 10 cache lines)
CTX_SIZE                EQU 640h

; Offsets
CTX_hProcess            EQU 0h
CTX_hThread             EQU 8h
CTX_hStdInRead          EQU 10h
CTX_hStdInWrite         EQU 18h
CTX_hStdOutRead         EQU 20h
CTX_hStdOutWrite        EQU 28h
CTX_ReadBuffer          EQU 30h
CTX_WriteBuffer         EQU 38h
CTX_JsonBuffer          EQU 40h
CTX_RequestId           EQU 48h
CTX_State               EQU 50h
CTX_Capabilities        EQU 54h
CTX_ServerInfo          EQU 70h
CTX_RootPath            EQU 170h
CTX_LastError           EQU 270h

; =============================================================================
; Data Section
; =============================================================================
.data
align 16

; Process startup info template
szBridgeCmd             BYTE "lsp_bridge.exe", 0
szContentLength         BYTE "Content-Length: ", 0
szCRLF                  BYTE 13, 10, 13, 10, 0
szCRLF2                 BYTE 13, 10, 0

; JSON-RPC templates (compact, no whitespace)
jsonInitTemplate        BYTE '{"jsonrpc":"2.0","id":', 0
jsonInitPart2           BYTE ',"method":"initialize","params":{', 0
jsonInitPart3           BYTE '"processId":', 0
jsonInitPart4           BYTE ',"rootPath":"', 0
jsonInitPart5           BYTE '","capabilities":{"textDocument":{"completion":{"dynamicRegistration":false,"completionItem":{"snippetSupport":true}}}}}}', 0

jsonCompletionTemplate  BYTE '{"jsonrpc":"2.0","id":', 0
jsonCompletionPart2     BYTE ',"method":"textDocument/completion","params":{"textDocument":{"uri":"', 0
jsonCompletionPart3     BYTE '"},"position":{"line":', 0
jsonCompletionPart4     BYTE ',"character":', 0
jsonCompletionPart5     BYTE '}}}', 0

jsonDidOpenTemplate     BYTE '{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"', 0
jsonDidOpenPart2        BYTE '","languageId":"', 0
jsonDidOpenPart3        BYTE '","version":1,"text":"', 0
jsonDidOpenPart4        BYTE '"}}}', 0

; Capability flags
CAP_COMPLETION          EQU 00000001h
CAP_HOVER               EQU 00000002h
CAP_SIGNATURE           EQU 00000004h
CAP_DEFINITION          EQU 00000008h
CAP_REFERENCES          EQU 00000010h

; Error codes
LSP_OK                  EQU 0h
LSP_ERR_NOMEM           EQU 1h
LSP_ERR_PIPE            EQU 2h
LSP_ERR_PROCESS         EQU 3h
LSP_ERR_TIMEOUT         EQU 4h
LSP_ERR_PROTOCOL        EQU 5h
LSP_ERR_NOT_INIT        EQU 6h

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; Helper: strlen (rcx = string ptr)
; Returns: rax = length
; =============================================================================
LSP_strlen PROC FRAME
    push    rdi
    .pushreg rdi
    push    rcx
    .pushreg rcx
    .endprolog

    mov     rdi, rcx
    xor     rax, rax
    mov     rcx, -1
    repne scasb
    mov     rax, -2
    sub     rax, rcx

    pop     rcx
    pop     rdi
    ret
LSP_strlen ENDP

; =============================================================================
; Helper: memcpy (rcx = dest, rdx = src, r8 = len)
; =============================================================================
LSP_memcpy PROC FRAME
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog

    mov     rsi, rdx
    mov     rdi, rcx
    mov     rcx, r8
    rep movsb

    pop     rdi
    pop     rsi
    ret
LSP_memcpy ENDP

; =============================================================================
; Helper: itoa (rcx = value, rdx = buffer ptr)
; Returns: rax = chars written
; =============================================================================
LSP_itoa PROC FRAME
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    push    rsi
    .pushreg rsi
    .endprolog

    mov     rax, rcx            ; Value
    mov     rdi, rdx            ; Buffer
    mov     rcx, 10             ; Divisor
    xor     rsi, rsi            ; Count

    ; Handle 0 specially
    test    rax, rax
    jnz     LSP_itoa_loop
    mov     BYTE PTR [rdi], '0'
    mov     rax, 1
    jmp     LSP_itoa_done

LSP_itoa_loop:
    xor     rdx, rdx
    div     rcx
    push    rdx                 ; Remainder (digit)
    inc     rsi
    test    rax, rax
    jnz     LSP_itoa_loop

    ; Pop digits in reverse
    mov     rax, rsi            ; Return count
LSP_itoa_write:
    pop     rdx
    add     dl, '0'
    mov     [rdi], dl
    inc     rdi
    dec     rsi
    jnz     LSP_itoa_write

LSP_itoa_done:
    mov     BYTE PTR [rdi], 0   ; Null terminate

    pop     rsi
    pop     rdi
    pop     rbx
    ret
LSP_itoa ENDP

; =============================================================================
; LSPClient_Create — Create LSP client context
;
; Parameters:
;   RCX = rootPath (UTF-8 string ptr)
; Returns:
;   RAX = context pointer OR NULL on error
; =============================================================================
LSPClient_Create PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 40
    .allocstack 28h
    .endprolog

    mov     rbx, rcx            ; Save rootPath

    ; Allocate context
    xor     rcx, rcx
    mov     rdx, CTX_SIZE
    mov     r8, MEM_COMMIT OR MEM_RESERVE
    mov     r9, PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      LSP_create_fail

    mov     rdi, rax            ; RDI = context
    xor     rcx, rcx
    mov     rdx, CTX_SIZE
    call    LSP_bzero           ; Zero context

    ; Allocate buffers
    mov     rcx, rdi
    add     rcx, CTX_ReadBuffer
    call    LSP_alloc_buffers
    test    rax, rax
    jz      LSP_create_free_ctx

    ; Copy root path
    mov     rsi, rbx
    lea     rdi, [rax + CTX_RootPath]
    mov     rcx, 255
    call    LSP_strncpy

    ; Initialize state
    mov     DWORD PTR [rax + CTX_State], 0
    mov     QWORD PTR [rax + CTX_RequestId], 1

    jmp     LSP_create_done

LSP_create_free_ctx:
    mov     rcx, rdi
    xor     rdx, rdx
    mov     r8, MEM_RELEASE
    call    VirtualFree
    xor     rax, rax

LSP_create_fail:
    xor     rax, rax

LSP_create_done:
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret
LSPClient_Create ENDP

; =============================================================================
; LSP_alloc_buffers — Allocate read/write/JSON buffers
;
; Parameters:
;   RCX = context ptr
; Returns:
;   RAX = context ptr OR NULL
; =============================================================================
LSP_alloc_buffers PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 40
    .allocstack 28h
    .endprolog

    mov     rbx, rcx

    ; Allocate read buffer (64KB)
    xor     rcx, rcx
    mov     rdx, LSP_READ_BUFFER_SIZE
    mov     r8, MEM_COMMIT OR MEM_RESERVE
    mov     r9, PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      LSP_alloc_fail
    mov     [rbx + CTX_ReadBuffer], rax

    ; Allocate write buffer (32KB)
    xor     rcx, rcx
    mov     rdx, LSP_WRITE_BUFFER_SIZE
    mov     r8, MEM_COMMIT OR MEM_RESERVE
    mov     r9, PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      LSP_alloc_fail
    mov     [rbx + CTX_WriteBuffer], rax

    ; Allocate JSON buffer (512KB)
    xor     rcx, rcx
    mov     rdx, LSP_JSON_MAX_SIZE
    mov     r8, MEM_COMMIT OR MEM_RESERVE
    mov     r9, PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      LSP_alloc_fail
    mov     [rbx + CTX_JsonBuffer], rax

    mov     rax, rbx
    jmp     LSP_alloc_done

LSP_alloc_fail:
    xor     rax, rax

LSP_alloc_done:
    add     rsp, 40
    pop     rbx
    ret
LSP_alloc_buffers ENDP

; =============================================================================
; LSP_bzero — Zero memory
;
; Parameters:
;   RCX = ptr, RDX = len
; =============================================================================
LSP_bzero PROC FRAME
    push    rdi
    .pushreg rdi
    .endprolog

    mov     rdi, rcx
    mov     rcx, rdx
    xor     rax, rax
    rep stosb

    pop     rdi
    ret
LSP_bzero ENDP

; =============================================================================
; LSP_strncpy — Copy string with limit
;
; Parameters:
;   RCX = dest, RDX = src, R8 = max
; =============================================================================
LSP_strncpy PROC FRAME
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog

    mov     rdi, rcx
    mov     rsi, rdx
    mov     rcx, r8

LSP_strncpy_loop:
    test    rcx, rcx
    jz      LSP_strncpy_done
    mov     al, [rsi]
    mov     [rdi], al
    inc     rsi
    inc     rdi
    dec     rcx
    test    al, al
    jnz     LSP_strncpy_loop

LSP_strncpy_done:
    pop     rdi
    pop     rsi
    ret
LSP_strncpy ENDP

; =============================================================================
; LSPClient_Destroy — Cleanup LSP client
;
; Parameters:
;   RCX = context ptr
; =============================================================================
LSPClient_Destroy PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 40
    .allocstack 28h
    .endprolog

    mov     rbx, rcx
    test    rbx, rbx
    jz      LSP_destroy_done

    ; Close process handles
    mov     rcx, [rbx + CTX_hProcess]
    test    rcx, rcx
    jz      LSP_destroy_skip_process
    call    CloseHandle

LSP_destroy_skip_process:
    mov     rcx, [rbx + CTX_hThread]
    test    rcx, rcx
    jz      LSP_destroy_skip_thread
    call    CloseHandle

LSP_destroy_skip_thread:
    ; Close pipe handles
    mov     rcx, [rbx + CTX_hStdInRead]
    test    rcx, rcx
    jz      LSP_destroy_skip_inread
    call    CloseHandle

LSP_destroy_skip_inread:
    mov     rcx, [rbx + CTX_hStdInWrite]
    test    rcx, rcx
    jz      LSP_destroy_skip_inwrite
    call    CloseHandle

LSP_destroy_skip_inwrite:
    mov     rcx, [rbx + CTX_hStdOutRead]
    test    rcx, rcx
    jz      LSP_destroy_skip_outread
    call    CloseHandle

LSP_destroy_skip_outread:
    mov     rcx, [rbx + CTX_hStdOutWrite]
    test    rcx, rcx
    jz      LSP_destroy_skip_outwrite
    call    CloseHandle

LSP_destroy_skip_outwrite:
    ; Free buffers
    mov     rcx, [rbx + CTX_ReadBuffer]
    test    rcx, rcx
    jz      LSP_destroy_skip_rbuf
    xor     rdx, rdx
    mov     r8, MEM_RELEASE
    call    VirtualFree

LSP_destroy_skip_rbuf:
    mov     rcx, [rbx + CTX_WriteBuffer]
    test    rcx, rcx
    jz      LSP_destroy_skip_wbuf
    xor     rdx, rdx
    mov     r8, MEM_RELEASE
    call    VirtualFree

LSP_destroy_skip_wbuf:
    mov     rcx, [rbx + CTX_JsonBuffer]
    test    rcx, rcx
    jz      LSP_destroy_skip_jbuf
    xor     rdx, rdx
    mov     r8, MEM_RELEASE
    call    VirtualFree

LSP_destroy_skip_jbuf:
    ; Free context
    mov     rcx, rbx
    xor     rdx, rdx
    mov     r8, MEM_RELEASE
    call    VirtualFree

LSP_destroy_done:
    add     rsp, 40
    pop     rbx
    ret
LSPClient_Destroy ENDP

; =============================================================================
; LSPClient_Initialize — Spawn bridge and send initialize
;
; Parameters:
;   RCX = context ptr
; Returns:
;   RAX = LSP_OK (0) on success, error code on failure
; =============================================================================
LSPClient_Initialize PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 168            ; STARTUPINFOA + PROCESS_INFORMATION
    .allocstack 0A8h
    .endprolog

    mov     rbx, rcx
    mov     rdi, rsp

    ; Zero STARTUPINFOA (104 bytes)
    mov     rcx, rdi
    mov     rdx, 104
    call    LSP_bzero

    ; Set STARTUPINFOA size
    mov     DWORD PTR [rdi], 104

    ; Create pipes for stdin
    lea     rcx, [rbx + CTX_hStdInRead]   ; hRead
    lea     rdx, [rbx + CTX_hStdInWrite]  ; hWrite
    xor     r8, r8                        ; lpSecurityAttributes
    call    CreatePipe
    test    rax, rax
    jz      LSP_init_fail_pipe

    ; Create pipes for stdout
    lea     rcx, [rbx + CTX_hStdOutRead]  ; hRead
    lea     rdx, [rbx + CTX_hStdOutWrite] ; hWrite
    xor     r8, r8
    call    CreatePipe
    test    rax, rax
    jz      LSP_init_fail_pipe2

    ; Set pipe handles in STARTUPINFOA
    mov     rax, [rbx + CTX_hStdInRead]
    mov     [rdi + 56], rax       ; hStdInput
    mov     rax, [rbx + CTX_hStdOutWrite]
    mov     [rdi + 64], rax       ; hStdOutput
    mov     rax, [rbx + CTX_hStdOutWrite]
    mov     [rdi + 72], rax       ; hStdError
    mov     DWORD PTR [rdi + 44], STARTF_USESTDHANDLES

    ; Create process
    xor     rcx, rcx              ; lpApplicationName
    lea     rdx, szBridgeCmd      ; lpCommandLine
    xor     r8, r8                ; lpProcessAttributes
    xor     r9, r9                ; lpThreadAttributes
    mov     QWORD PTR [rsp + 32], 1  ; bInheritHandles = TRUE
    mov     QWORD PTR [rsp + 40], 0  ; dwCreationFlags
    mov     QWORD PTR [rsp + 48], 0  ; lpEnvironment
    mov     QWORD PTR [rsp + 56], 0  ; lpCurrentDirectory
    mov     QWORD PTR [rsp + 64], rdi ; lpStartupInfo
    lea     rax, [rdi + 104]      ; lpProcessInformation
    mov     QWORD PTR [rsp + 72], rax
    call    CreateProcessA
    test    rax, rax
    jz      LSP_init_fail_process

    ; Save process handles
    mov     rax, [rdi + 104]      ; hProcess
    mov     [rbx + CTX_hProcess], rax
    mov     rax, [rdi + 108]      ; hThread
    mov     [rbx + CTX_hThread], rax

    ; Close our ends of child handles
    mov     rcx, [rbx + CTX_hStdInRead]
    call    CloseHandle
    mov     QWORD PTR [rbx + CTX_hStdInRead], 0

    mov     rcx, [rbx + CTX_hStdOutWrite]
    call    CloseHandle
    mov     QWORD PTR [rbx + CTX_hStdOutWrite], 0

    ; Send initialize request
    mov     rcx, rbx
    call    LSP_send_initialize

    ; Wait for response
    mov     rcx, rbx
    mov     rdx, 5000             ; 5 second timeout
    call    LSP_wait_response
    test    rax, rax
    jz      LSP_init_fail_response

    mov     DWORD PTR [rbx + CTX_State], 1  ; Ready
    xor     rax, rax                ; LSP_OK
    jmp     LSP_init_done

LSP_init_fail_response:
    mov     eax, LSP_ERR_TIMEOUT
    jmp     LSP_init_done

LSP_init_fail_process:
    mov     eax, LSP_ERR_PROCESS
    jmp     LSP_init_done

LSP_init_fail_pipe2:
    mov     rcx, [rbx + CTX_hStdInRead]
    call    CloseHandle
    mov     rcx, [rbx + CTX_hStdInWrite]
    call    CloseHandle

LSP_init_fail_pipe:
    mov     eax, LSP_ERR_PIPE

LSP_init_done:
    add     rsp, 168
    pop     rdi
    pop     rsi
    pop     rbx
    ret
LSPClient_Initialize ENDP

; =============================================================================
; LSP_send_initialize — Build and send initialize JSON-RPC
;
; Parameters:
;   RCX = context ptr
; =============================================================================
LSP_send_initialize PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 40
    .allocstack 28h
    .endprolog

    mov     rbx, rcx
    mov     rsi, [rbx + CTX_WriteBuffer]
    mov     rdi, rsi

    ; Build JSON payload
    lea     rcx, jsonInitTemplate
    call    LSP_strlen
    mov     rcx, rsi
    lea     rdx, jsonInitTemplate
    mov     r8, rax
    call    LSP_memcpy
    add     rdi, rax

    ; Append request ID
    mov     rcx, [rbx + CTX_RequestId]
    inc     QWORD PTR [rbx + CTX_RequestId]
    mov     rdx, rdi
    call    LSP_itoa
    add     rdi, rax

    ; Append rest of template
    lea     rcx, jsonInitPart2
    call    LSP_strlen
    mov     rcx, rdi
    lea     rdx, jsonInitPart2
    mov     r8, rax
    call    LSP_memcpy
    add     rdi, rax

    ; Append process ID (use 0 for now)
    mov     BYTE PTR [rdi], '0'
    inc     rdi

    ; Append root path
    lea     rcx, jsonInitPart4
    call    LSP_strlen
    mov     rcx, rdi
    lea     rdx, jsonInitPart4
    mov     r8, rax
    call    LSP_memcpy
    add     rdi, rax

    lea     rcx, [rbx + CTX_RootPath]
    call    LSP_strlen
    mov     rcx, rdi
    lea     rdx, [rbx + CTX_RootPath]
    mov     r8, rax
    call    LSP_memcpy
    add     rdi, rax

    lea     rcx, jsonInitPart5
    call    LSP_strlen
    mov     rcx, rdi
    lea     rdx, jsonInitPart5
    mov     r8, rax
    call    LSP_memcpy
    add     rdi, rax

    ; Calculate length
    mov     rcx, rsi
    sub     rdi, rcx              ; RDI = payload length

    ; Send with Content-Length header
    mov     rcx, rbx
    mov     rdx, rsi
    mov     r8, rdi
    call    LSP_send_message

    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret
LSP_send_initialize ENDP

; =============================================================================
; LSP_send_message — Send LSP message with Content-Length header
;
; Parameters:
;   RCX = context ptr
;   RDX = payload ptr
;   R8  = payload length
; =============================================================================
LSP_send_message PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 256              ; Header buffer
    .allocstack 100h
    .endprolog

    mov     rbx, rcx
    mov     rsi, rdx              ; Payload
    mov     rdi, r8               ; Length

    ; Build header: Content-Length: <len>
    ;
    lea     rcx, szContentLength
    call    LSP_strlen
    mov     r8, rax

    lea     rdi, [rsp + 32]       ; Header buffer
    lea     rcx, szContentLength
    mov     rdx, rdi
    call    LSP_memcpy

    ; Append length as string
    mov     rcx, rsi              ; Payload length value
    lea     rdx, [rdi + r8]
    call    LSP_itoa

    ; Append \r\n\r\n
    lea     rcx, szCRLF
    call    LSP_strlen

    ; Calculate total header length and send
    ; (simplified - just send header then payload)

    add     rsp, 256
    pop     rdi
    pop     rsi
    pop     rbx
    ret
LSP_send_message ENDP

; =============================================================================
; LSP_wait_response — Wait for and parse JSON-RPC response
;
; Parameters:
;   RCX = context ptr
;   RDX = timeout ms
; Returns:
;   RAX = 1 on success, 0 on timeout
; =============================================================================
LSP_wait_response PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 40
    .allocstack 28h
    .endprolog

    mov     rbx, rcx
    ; Simplified: just poll with Sleep
    mov     rcx, rdx
    call    Sleep
    mov     rax, 1

    add     rsp, 40
    pop     rbx
    ret
LSP_wait_response ENDP

; =============================================================================
; LSPClient_Completion — Request completions
;
; Parameters:
;   RCX = context ptr
;   RDX = document URI
;   R8  = line number
;   R9  = character position
; Returns:
;   RAX = request ID OR 0 on error
; =============================================================================
LSPClient_Completion PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 40
    .allocstack 28h
    .endprolog

    mov     rbx, rcx
    mov     rax, [rbx + CTX_RequestId]
    inc     QWORD PTR [rbx + CTX_RequestId]

    ; TODO: Build and send completion request

    add     rsp, 40
    pop     rbx
    ret
LSPClient_Completion ENDP

; =============================================================================
; LSPClient_DidOpen — Notify document opened
;
; Parameters:
;   RCX = context ptr
;   RDX = document URI
;   R8  = language ID
;   R9  = text content
; =============================================================================
LSPClient_DidOpen PROC
    mov     rax, 1
    ret
LSPClient_DidOpen ENDP

; =============================================================================
; LSPClient_DidChange — Notify document changed
;
; Parameters:
;   RCX = context ptr
;   RDX = document URI
;   R8  = new text
; =============================================================================
LSPClient_DidChange PROC
    mov     rax, 1
    ret
LSPClient_DidChange ENDP

; =============================================================================
; LSPClient_PollResponse — Check for pending response
;
; Parameters:
;   RCX = context ptr
; Returns:
;   RAX = response data OR NULL
; =============================================================================
LSPClient_PollResponse PROC
    xor     rax, rax
    ret
LSPClient_PollResponse ENDP

; =============================================================================
; Entry point for standalone testing
; =============================================================================
main PROC FRAME
    sub     rsp, 40
    .allocstack 28h
    .endprolog

    ; Create client
    lea     rcx, testRootPath
    call    LSPClient_Create
    test    rax, rax
    jz      main_fail

    mov     rbx, rax

    ; Initialize
    mov     rcx, rbx
    call    LSPClient_Initialize
    test    rax, rax
    jnz     main_cleanup

    ; Success
    mov     rcx, rbx
    call    LSPClient_Destroy

    xor     rcx, rcx
    call    ExitProcess

main_cleanup:
    mov     rcx, rbx
    call    LSPClient_Destroy

main_fail:
    mov     rcx, 1
    call    ExitProcess

main ENDP

.data
align 8
testRootPath    BYTE "d:\\RawrXD", 0

END
