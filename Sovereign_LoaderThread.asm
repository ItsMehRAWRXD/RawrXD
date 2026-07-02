; ==============================================================================
; Sovereign_LoaderThread.asm — Background GGUF Loader with Progress Reporting
; ==============================================================================
; Priority: THREAD_PRIORITY_BELOW_NORMAL
; Posts WM_USER+200 (progress), WM_USER+201 (complete), WM_USER+202 (failed)
; Zero CRT dependency. Pure Win32 ABI.
; ==============================================================================

option casemap:none
option prologue:none
option epilogue:none

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN CreateThread          : PROC
EXTERN SetThreadPriority     : PROC
EXTERN GetCurrentThread      : PROC
EXTERN WaitForSingleObject   : PROC
EXTERN PostMessageA          : PROC
EXTERN CloseHandle           : PROC
EXTERN ExitThread            : PROC
EXTERN GetProcessHeap        : PROC
EXTERN HeapAlloc             : PROC
EXTERN HeapFree              : PROC
EXTERN GhostBuffer_WriteEvent_Safe : PROC
EXTERN Sovereign_LoadModel_Safe : PROC
EXTERN Sovereign_GetLastLoadException : PROC

; ==============================================================================
; Exported from Sovereign_SDK.dll (resolved at runtime or linked directly)
; ==============================================================================
EXTERN SOVEREIGN_LOAD_MODEL  : PROC

; ==============================================================================
; Constants
; ==============================================================================
WM_USER                     equ 0400h
SOVEREIGN_LOAD_PROGRESS     equ WM_USER + 200
SOVEREIGN_LOAD_COMPLETE     equ WM_USER + 201
SOVEREIGN_LOAD_FAILED       equ WM_USER + 202

THREAD_PRIORITY_BELOW_NORMAL equ 15
INFINITE                    equ 0FFFFFFFFh

GHOST_LOAD_START            equ 01h
GHOST_LOAD_PROGRESS_EVT     equ 02h
GHOST_LOAD_COMPLETE_EVT     equ 03h
GHOST_LOAD_FAILED_EVT       equ 04h

LOAD_RESULT_SUCCESS         equ 0
LOAD_RESULT_PENDING         equ 1
LOAD_RESULT_ERROR_HARDWARE_TIMEOUT equ -4
LOAD_RESULT_ERROR_UNKNOWN   equ -99

; ==============================================================================
; LoaderContext structure (passed to thread proc via RCX)
; ==============================================================================
LOADER_CONTEXT STRUCT
    hwndIDE         dq ?        ; +0   IDE window handle
    pModelPath      dq ?        ; +8   UTF-8 path to .gguf
    expectedSize    dq ?        ; +16  Expected file size (for % calc)
    hEventCancel    dq ?        ; +24  Manual-reset event handle
    hModule         dq ?        ; +32  Sovereign_SDK.dll base
LOADER_CONTEXT ENDS

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; Atomic state flags (DWORD for Interlocked ops if needed later)
g_bLoading          dd 0          ; 1 = load in progress
PUBLIC g_LastLoadResult
g_LastLoadResult    dd LOAD_RESULT_SUCCESS
PUBLIC g_LastLoadWin32Error
g_LastLoadWin32Error dd 0
g_hLoaderThread     dq 0          ; Thread handle for cleanup
g_hModelHandle      dq 0          ; Result from SOVEREIGN_LOAD_MODEL
g_hProcessHeap      dq 0          ; Cached process heap handle

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; Sovereign_StartLoad — Allocate context and kick background loader
; RCX = HWND of the main IDE window
; RDX = Pointer to null-terminated UTF-8 GGUF path
; R8  = Expected model size in bytes
; Returns: RAX = Thread Handle (or 0 on failure)
; ==============================================================================
PUBLIC Sovereign_StartLoad
Sovereign_StartLoad PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 38h                    ; shadow + stack args (+ align) for CreateThread

    mov rbx, rcx                    ; RBX = hwndIDE
    mov rsi, rdx                    ; RSI = pModelPath
    mov rdi, r8                     ; RDI = expectedSize

    ; Ensure cached process heap handle
    mov rax, [g_hProcessHeap]
    test rax, rax
    jnz @@heap_ready
    call GetProcessHeap
    mov [g_hProcessHeap], rax

@@heap_ready:
    ; Allocate LoaderContext (40 bytes = SIZEOF LOADER_CONTEXT)
    mov rcx, [g_hProcessHeap]
    mov edx, 8                      ; HEAP_ZERO_MEMORY
    mov r8, SIZEOF LOADER_CONTEXT
    call HeapAlloc
    test rax, rax
    jz @@dispatch_failed

    mov r12, rax                    ; R12 = pLoaderContext

    ; Populate context
    mov [r12 + LOADER_CONTEXT.hwndIDE], rbx
    mov [r12 + LOADER_CONTEXT.pModelPath], rsi
    mov [r12 + LOADER_CONTEXT.expectedSize], rdi
    mov qword ptr [r12 + LOADER_CONTEXT.hEventCancel], 0
    mov qword ptr [r12 + LOADER_CONTEXT.hModule], 0

    ; Mark loading state before thread launch and clear stale model handle
    mov DWORD PTR [g_bLoading], 1
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_PENDING
    mov DWORD PTR [g_LastLoadWin32Error], 0
    mov qword ptr [g_hModelHandle], 0

    ; Kick the background thread (CreateThread takes ownership of context)
    xor ecx, ecx                    ; lpThreadAttributes = NULL
    xor edx, edx                    ; dwStackSize = default
    lea r8, [LoaderThreadProc]      ; lpStartAddress
    mov r9, r12                     ; lpParameter = pLoaderContext
    mov qword ptr [rsp+20h], 0      ; dwCreationFlags = 0 (run immediately)
    mov qword ptr [rsp+28h], 0      ; lpThreadId = NULL
    call CreateThread
    test rax, rax
    jz @@start_failed

    ; Store thread handle globally
    mov [g_hLoaderThread], rax

    ; Set priority to below-normal so UI never stutters
    mov rcx, rax
    mov edx, THREAD_PRIORITY_BELOW_NORMAL
    call SetThreadPriority

    ; Return thread handle so IDE can track it
    mov rax, [g_hLoaderThread]
    jmp @@exit

@@start_failed:
    ; Thread creation failed — free the context
    mov rcx, [g_hProcessHeap]
    mov edx, 0
    mov r8, r12
    call HeapFree

    mov DWORD PTR [g_bLoading], 0
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_UNKNOWN

@@dispatch_failed:
    xor eax, eax

@@exit:
    add rsp, 38h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_StartLoad ENDP

; ==============================================================================
; LoaderThreadProc — Background worker
; RCX = LoaderContext ptr
; ==============================================================================
LoaderThreadProc PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 28h                    ; 32-byte shadow + 8-byte align fix
                                    ; (6 pushes = 48, +40 = 88, 88 mod 16 = 8, callsite aligned)

    mov rbx, rcx                    ; RBX = LOADER_CONTEXT (preserved)

    ; --- Post "loading started" (0%) ---
    mov rcx, [rbx + LOADER_CONTEXT.hwndIDE]
    mov edx, SOVEREIGN_LOAD_PROGRESS
    xor r8, r8                      ; wParam = 0%
    xor r9, r9                      ; lParam = 0 bytes
    call PostMessageA

    ; --- Emit telemetry: load start + 0% progress ---
    mov cl, GHOST_LOAD_START
    xor rdx, rdx
    call GhostBuffer_WriteEvent_Safe

    mov cl, GHOST_LOAD_PROGRESS_EVT
    xor rdx, rdx
    call GhostBuffer_WriteEvent_Safe

    ; --- Call safe wrapper around SOVEREIGN_LOAD_MODEL ---
    mov rcx, [rbx + LOADER_CONTEXT.pModelPath]
    call Sovereign_LoadModel_Safe
    ; RAX = model handle or 0

    ; Store result globally
    mov [g_hModelHandle], rax

    test rax, rax
    jz @@load_failed

    ; --- Post "loading complete" ---
    mov rcx, [rbx + LOADER_CONTEXT.hwndIDE]
    mov edx, SOVEREIGN_LOAD_COMPLETE
    mov r8, rax                     ; wParam = model handle
    mov r9, [rbx + LOADER_CONTEXT.expectedSize]
    call PostMessageA

    ; --- Emit telemetry: load complete (payload=model handle) ---
    mov cl, GHOST_LOAD_COMPLETE_EVT
    mov rdx, [g_hModelHandle]
    call GhostBuffer_WriteEvent_Safe

    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_SUCCESS

    mov eax, 1
    jmp @@exit

@@load_failed:
    call Sovereign_GetLastLoadException
    test eax, eax
    jz @@no_exception
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_HARDWARE_TIMEOUT
@@no_exception:

    ; --- Post "loading failed" ---
    mov rcx, [rbx + LOADER_CONTEXT.hwndIDE]
    mov edx, SOVEREIGN_LOAD_FAILED
    xor r8, r8
    xor r9, r9
    call PostMessageA

    ; --- Emit telemetry: load failed (payload=0xBAD) ---
    mov cl, GHOST_LOAD_FAILED_EVT
    mov rdx, 0BADh
    call GhostBuffer_WriteEvent_Safe

    cmp DWORD PTR [g_LastLoadResult], LOAD_RESULT_PENDING
    jne @@result_already_set
    mov DWORD PTR [g_LastLoadResult], LOAD_RESULT_ERROR_UNKNOWN
@@result_already_set:

    xor eax, eax

@@exit:
    ; Clear loading flag
    mov DWORD PTR [g_bLoading], 0

    ; Free the LoaderContext (thread owns it now)
    mov rcx, [g_hProcessHeap]
    test rcx, rcx
    jz @@skip_free
    mov edx, 0
    mov r8, rbx
    call HeapFree
@@skip_free:

    ; Thread exit code in EAX
    mov rcx, rax
    call ExitThread                 ; Does not return

    ; Never reached
    add rsp, 28h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
LoaderThreadProc ENDP

; ==============================================================================
; Sovereign_CancelLoad — Signal cancellation and wait for thread
; Returns: RAX = 1 if cancelled, 0 if no load in progress
; ==============================================================================
PUBLIC Sovereign_CancelLoad
Sovereign_CancelLoad PROC
    push rbx
    sub rsp, 20h                    ; 32-byte shadow (already aligned after 1 push)

    mov rbx, [g_hLoaderThread]
    test rbx, rbx
    jz @@not_loading

    ; Wait for thread to finish (max 30 seconds)
    mov rcx, rbx
    mov edx, 30000                  ; 30s timeout
    call WaitForSingleObject

    ; Close thread handle
    mov rcx, rbx
    call CloseHandle
    mov qword ptr [g_hLoaderThread], 0
    mov DWORD PTR [g_bLoading], 0

    mov eax, 1
    jmp @@exit

@@not_loading:
    xor eax, eax

@@exit:
    add rsp, 20h
    pop rbx
    ret
Sovereign_CancelLoad ENDP

; ==============================================================================
; Sovereign_IsLoading — Check if background load is active
; Returns: RAX = 1 if loading, 0 if idle
; ==============================================================================
PUBLIC Sovereign_IsLoading
Sovereign_IsLoading PROC
    mov eax, [g_bLoading]
    ret
Sovereign_IsLoading ENDP

; ==============================================================================
; Sovereign_GetModelHandle — Get result of last load
; Returns: RAX = handle or 0
; ==============================================================================
PUBLIC Sovereign_GetModelHandle
Sovereign_GetModelHandle PROC
    mov rax, [g_hModelHandle]
    ret
Sovereign_GetModelHandle ENDP

; ==============================================================================
; Sovereign_GetLastLoadResult — Get result code for the most recent load attempt
; Returns: EAX = LoadResult enum value
; ==============================================================================
PUBLIC Sovereign_GetLastLoadResult
Sovereign_GetLastLoadResult PROC
    mov eax, [g_LastLoadResult]
    ret
Sovereign_GetLastLoadResult ENDP

; ==============================================================================
; Sovereign_GetLastLoadWin32Error — Get Win32 GetLastError() from last load fail
; Returns: EAX = Win32 error code (0 if unavailable/not set)
; ==============================================================================
PUBLIC Sovereign_GetLastLoadWin32Error
Sovereign_GetLastLoadWin32Error PROC
    mov eax, [g_LastLoadWin32Error]
    ret
Sovereign_GetLastLoadWin32Error ENDP

end
