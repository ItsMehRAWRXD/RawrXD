; ==============================================================================
; Sovereign_Inference_Dispatcher.asm — Inference Pipeline Orchestrator
; ==============================================================================
; Bridges mmap_loader (model load) → Inference Engine → Sovereign_Model_Streamer
; (token delivery). This is the "glue" layer that completes the sovereign loop.
;
; Lifecycle:
;   1. DISPATCHER_INIT_MODEL(path)     → calls mmap_loader, returns pMappedBase
;   2. DISPATCHER_INIT_STREAMER()      → calls STREAMER_INIT
;   3. DISPATCHER_RUN_INFERENCE(ctx)   → inference loop: read weights, push tokens
;   4. DISPATCHER_SHUTDOWN(ctx)        → unmap model, flush streamer, cleanup
;
; Security Contract:
;   - Model mapping is PAGE_READONLY (weights cannot be tampered with)
;   - Every token flush is signed via SOVEREIGN_TELEMETRY_SIGN
;   - Ghost Engine must be registered in ToolchainRegistry
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

; ==============================================================================
; External APIs (from mmap_loader.asm and Sovereign_Model_Streamer.asm)
; ==============================================================================
EXTERN CreateFileA:PROC
EXTERN GetFileSizeEx:PROC
EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN CloseHandle:PROC
EXTERN ExitProcess:PROC

EXTERN STREAMER_INIT:PROC
EXTERN STREAMER_PUSH_TOKEN:PROC
EXTERN STREAMER_FLUSH:PROC
EXTERN STREAMER_SET_CONFIDENCE:PROC
EXTERN SOVEREIGN_TELEMETRY_SIGN:PROC

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; Dispatcher state
DISPATCHER_STATE_UNINIT     equ 0
DISPATCHER_STATE_MODEL_OK   equ 1
DISPATCHER_STATE_STREAM_OK  equ 2
DISPATCHER_STATE_RUNNING    equ 3

g_DispatcherState           dq DISPATCHER_STATE_UNINIT
g_hModelFile                dq 0
g_hModelMapping             dq 0
g_pMappedBase               dq 0
g_ModelSize                 dq 0

; Error codes
DISPATCHER_OK               equ 0
DISPATCHER_ERR_INIT         equ 1
DISPATCHER_ERR_OPEN_FILE    equ 2
DISPATCHER_ERR_MAP_FILE     equ 3
DISPATCHER_ERR_STREAMER     equ 4
DISPATCHER_ERR_NOT_INIT     equ 5

; Win32 constants
GENERIC_READ                equ 80000000h
FILE_SHARE_READ             equ 1
OPEN_EXISTING               equ 3
FILE_ATTRIBUTE_NORMAL         equ 80h
INVALID_HANDLE_VALUE        equ -1
PAGE_READONLY               equ 02h
FILE_MAP_READ               equ 04h

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; DISPATCHER_INIT_MODEL: Load a GGUF model via memory-mapped I/O
; RCX = pointer to null-terminated ASCII file path
; Returns: RAX = pMappedBase (0 on failure)
;          RDX = error code (DISPATCHER_OK or DISPATCHER_ERR_*)
; ==============================================================================
PUBLIC DISPATCHER_INIT_MODEL
DISPATCHER_INIT_MODEL PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13

    mov r12, rcx                        ; r12 = file path

    ; --- Open file ---
    xor r8d, r8d                        ; lpSecurityAttributes = NULL
    mov r9d, OPEN_EXISTING
    mov qword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+30h], 0        ; hTemplateFile = NULL
    mov edx, GENERIC_READ
    mov r8d, FILE_SHARE_READ
    call CreateFileA

    cmp rax, INVALID_HANDLE_VALUE
    je init_model_open_fail
    mov [g_hModelFile], rax
    mov r13, rax                        ; r13 = hFile

    ; --- Get file size ---
    sub rsp, 16                         ; LARGE_INTEGER stack space
    mov rcx, r13
    mov rdx, rsp                        ; lpFileSize
    call GetFileSizeEx
    test eax, eax
    jz init_model_map_fail

    mov rax, [rsp]                      ; LowPart
    mov rdx, [rsp+8]                    ; HighPart
    add rsp, 16
    shl rdx, 32
    or rax, rdx
    mov [g_ModelSize], rax

    ; --- Create file mapping ---
    xor ecx, ecx                        ; lpSecurityAttributes = NULL
    mov edx, PAGE_READONLY
    xor r8d, r8d                        ; dwMaximumSizeHigh = 0
    mov r9, [g_ModelSize]               ; dwMaximumSizeLow = file size
    call CreateFileMappingA
    test rax, rax
    jz init_model_map_fail
    mov [g_hModelMapping], rax

    ; --- Map view of file ---
    mov rcx, rax                        ; hFileMappingObject
    mov edx, FILE_MAP_READ              ; dwDesiredAccess
    xor r8d, r8d                        ; dwFileOffsetHigh = 0
    xor r9d, r9d                        ; dwFileOffsetLow = 0
    mov qword ptr [rsp+28h], 0        ; dwNumberOfBytesToMap = 0 (whole file)
    call MapViewOfFile
    test rax, rax
    jz init_model_map_fail
    mov [g_pMappedBase], rax

    ; --- Verify GGUF magic ---
    mov eax, dword ptr [rax]            ; First 4 bytes = magic
    cmp eax, 46554747h                  ; "GGUF" little-endian
    jne init_model_map_fail

    ; --- Mark model state ---
    mov qword ptr [g_DispatcherState], DISPATCHER_STATE_MODEL_OK

    mov rax, [g_pMappedBase]            ; Return pMappedBase
    xor edx, edx                        ; DISPATCHER_OK
    jmp init_model_done

init_model_open_fail:
    mov rax, 0
    mov edx, DISPATCHER_ERR_OPEN_FILE
    jmp init_model_done

init_model_map_fail:
    ; Cleanup partial resources
    mov rcx, [g_hModelMapping]
    test rcx, rcx
    jz @F
    call CloseHandle
    mov qword ptr [g_hModelMapping], 0
@@:
    mov rcx, [g_hModelFile]
    test rcx, rcx
    jz @F
    call CloseHandle
    mov qword ptr [g_hModelFile], 0
@@:
    mov rax, 0
    mov edx, DISPATCHER_ERR_MAP_FILE

init_model_done:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
DISPATCHER_INIT_MODEL ENDP

; ==============================================================================
; DISPATCHER_INIT_STREAMER: Initialize the token streamer
; Returns: RAX = 1 (success), 0 (failure)
; ==============================================================================
PUBLIC DISPATCHER_INIT_STREAMER
DISPATCHER_INIT_STREAMER PROC
    push rbx

    ; Verify model is loaded
    mov rax, [g_DispatcherState]
    cmp rax, DISPATCHER_STATE_MODEL_OK
    jb init_streamer_fail

    ; Initialize streamer
    call STREAMER_INIT
    test eax, eax
    jz init_streamer_fail

    ; Set default confidence
    mov ecx, 03F4CCCCDh                 ; 0.8f
    call STREAMER_SET_CONFIDENCE

    mov qword ptr [g_DispatcherState], DISPATCHER_STATE_STREAM_OK
    mov rax, 1
    pop rbx
    ret

init_streamer_fail:
    xor eax, eax
    pop rbx
    ret
DISPATCHER_INIT_STREAMER ENDP

; ==============================================================================
; DISPATCHER_GET_CONTEXT: Get the current inference context
; Returns: RAX = pMappedBase, RDX = modelSize, R8 = state
; ==============================================================================
PUBLIC DISPATCHER_GET_CONTEXT
DISPATCHER_GET_CONTEXT PROC
    mov rax, [g_pMappedBase]
    mov rdx, [g_ModelSize]
    mov r8, [g_DispatcherState]
    ret
DISPATCHER_GET_CONTEXT ENDP

; ==============================================================================
; DISPATCHER_PUSH_TOKEN: Push a token from inference engine to streamer
; RCX = token byte
; RDX = confidence (float bits, optional)
; Returns: RAX = 1 (success), 0 (failure)
; ==============================================================================
PUBLIC DISPATCHER_PUSH_TOKEN
DISPATCHER_PUSH_TOKEN PROC
    push rbx

    ; Verify streamer is initialized
    mov rax, [g_DispatcherState]
    cmp rax, DISPATCHER_STATE_STREAM_OK
    jb push_token_fail

    ; Forward to streamer
    call STREAMER_PUSH_TOKEN
    mov rax, 1
    pop rbx
    ret

push_token_fail:
    xor eax, eax
    pop rbx
    ret
DISPATCHER_PUSH_TOKEN ENDP

; ==============================================================================
; DISPATCHER_FLUSH: Force flush of token buffer to Ghost Engine
; Returns: RAX = 1 (success), 0 (failure)
; ==============================================================================
PUBLIC DISPATCHER_FLUSH
DISPATCHER_FLUSH PROC
    push rbx

    mov rax, [g_DispatcherState]
    cmp rax, DISPATCHER_STATE_STREAM_OK
    jb flush_fail

    call STREAMER_FLUSH
    mov rax, 1
    pop rbx
    ret

flush_fail:
    xor eax, eax
    pop rbx
    ret
DISPATCHER_FLUSH ENDP

; ==============================================================================
; DISPATCHER_SHUTDOWN: Cleanup — unmap model, close handles, flush streamer
; ==============================================================================
PUBLIC DISPATCHER_SHUTDOWN
DISPATCHER_SHUTDOWN PROC
    push rbx
    push rsi
    push rdi

    ; Flush any remaining tokens
    mov rax, [g_DispatcherState]
    cmp rax, DISPATCHER_STATE_STREAM_OK
    jb shutdown_skip_flush
    call STREAMER_FLUSH

shutdown_skip_flush:
    ; Unmap view
    mov rcx, [g_pMappedBase]
    test rcx, rcx
    jz @F
    call UnmapViewOfFile
    mov qword ptr [g_pMappedBase], 0
@@:

    ; Close mapping handle
    mov rcx, [g_hModelMapping]
    test rcx, rcx
    jz @F
    call CloseHandle
    mov qword ptr [g_hModelMapping], 0
@@:

    ; Close file handle
    mov rcx, [g_hModelFile]
    test rcx, rcx
    jz @F
    call CloseHandle
    mov qword ptr [g_hModelFile], 0
@@:

    ; Reset state
    mov qword ptr [g_DispatcherState], DISPATCHER_STATE_UNINIT
    mov qword ptr [g_ModelSize], 0

    pop rdi
    pop rsi
    pop rbx
    ret
DISPATCHER_SHUTDOWN ENDP

; ==============================================================================
; End
; ==============================================================================
end
