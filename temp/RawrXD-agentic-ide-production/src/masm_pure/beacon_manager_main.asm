;============================================================================
; BEACON_MANAGER_MAIN.ASM - Pure MASM model lifecycle controller
; Single entry point, no C++ dependencies
;============================================================================
.686P
.XMM
.model flat, c
OPTION CASEMAP:NONE

; Windows APIs (direct imports, no CRT)
extrn CreateEventA: proc
extrn SetEvent: proc
extrn ResetEvent: proc
extrn WaitForSingleObject: proc
extrn CreateThread: proc
extrn Sleep: proc
extrn GetTickCount64: proc
extrn VirtualAlloc: proc
extrn VirtualFree: proc
extrn OutputDebugStringA: proc

; Internal forward declarations
public Beacon_InitializeSystem
public Beacon_ShutdownSystem
public Beacon_CreateForModel
public Beacon_LoadModelAsync
public Beacon_UnloadModelAsync
public Beacon_Touch
public Beacon_GetStatus
public Beacon_WaitLoadComplete
public Beacon_PollNonBlocking

; Beacon structure (24 bytes, cache-aligned)
Beacon STRUCT
    hEvent              dq ?        ; Signal handle
    modelId             dd ?        ; 4-byte model ID
    state               dd ?        ; 0=unloaded,1=loading,2=loaded,3=evicting
    lastAccessTime      dq ?        ; 64-bit timestamp
    modelPtr            dq ?        ; Pointer to loaded model
    lockCount           dd ?        ; Reference count
    padding             dd ?        ; Alignment
Beacon ENDS

; Globals
.data
g_beaconArray           dq 0        ; Array of Beacon*
g_beaconCount           dq 0
g_hMasterLoadEvent      dq 0
g_hLoaderThread         dq 0
g_hIdleThread           dq 0
g_bShutdown             db 0

; Constants
MAX_MODELS       equ 1000
BEACON_SIZE      equ 24
LOADING          equ 1
LOADED           equ 2
UNLOADED         equ 0
EVICTING         equ 3
WAIT_OBJECT_0    equ 0
WAIT_TIMEOUT     equ 258
MEM_COMMIT       equ 00001000h
MEM_RESERVE      equ 00002000h
MEM_RELEASE      equ 00008000h
PAGE_READWRITE   equ 04h

.code

;----------------------------------------------------------------------------
; Beacon_InitializeSystem - Call once at IDE startup
; Returns: 0=success, -1=failure
;----------------------------------------------------------------------------
align 16
Beacon_InitializeSystem proc
    push rbp
    mov rbp, rsp
    
    ; Allocate beacon array: 1000 * 24 bytes = 24KB
    mov ecx, MAX_MODELS * BEACON_SIZE
    mov edx, MEM_COMMIT or MEM_RESERVE
    mov r8d, PAGE_READWRITE
    xor r9d, r9d
    call VirtualAlloc
    test rax, rax
    jz @init_failed
    
    mov g_beaconArray, rax
    mov g_beaconCount, 0
    
    ; Create master event
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call CreateEventA
    mov g_hMasterLoadEvent, rax
    
    ; Spawn loader thread
    xor ecx, ecx
    xor edx, edx
    lea r8, LoaderThreadMain
    xor r9d, r9d
    push 0
    push 0
    call CreateThread
    add rsp, 16
    mov g_hLoaderThread, rax
    
    ; Spawn idle detector
    xor ecx, ecx
    xor edx, edx
    lea r8, IdleDetectorThreadMain
    xor r9d, r9d
    push 0
    push 0
    call CreateThread
    add rsp, 16
    mov g_hIdleThread, rax
    
    xor eax, eax
    pop rbp
    ret
    
@init_failed:
    mov eax, -1
    pop rbp
    ret
Beacon_InitializeSystem endp

;----------------------------------------------------------------------------
; Beacon_CreateForModel - Create beacon for specific model
; rcx = model_id (32-bit)
; Returns: beacon pointer in rax (NULL on failure)
;----------------------------------------------------------------------------
align 8
Beacon_CreateForModel proc
    mov rax, g_beaconCount
    cmp rax, MAX_MODELS
    jge @create_failed
    
    mov r8, g_beaconArray
    imul rax, BEACON_SIZE
    add r8, rax
    
    push rcx
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    call CreateEventA
    pop rcx
    
    mov rdx, g_beaconCount
    mov r8, g_beaconArray
    imul rdx, BEACON_SIZE
    add r8, rdx
    
    mov [r8+Beacon.hEvent], rax
    mov [r8+Beacon.modelId], ecx
    mov dword ptr [r8+Beacon.state], UNLOADED
    mov qword ptr [r8+Beacon.lastAccessTime], 0
    mov qword ptr [r8+Beacon.modelPtr], 0
    mov dword ptr [r8+Beacon.lockCount], 0
    
    inc g_beaconCount
    
    mov rax, r8
    ret
    
@create_failed:
    xor rax, rax
    ret
Beacon_CreateForModel endp

;----------------------------------------------------------------------------
; Beacon_LoadModelAsync - Non-blocking load signal
; rcx = beacon pointer
;----------------------------------------------------------------------------
align 8
Beacon_LoadModelAsync proc
    cmp dword ptr [rcx+Beacon.state], UNLOADED
    jne @already_loading
    
    mov dword ptr [rcx+Beacon.state], LOADING
    
    push rcx
    mov rcx, g_hMasterLoadEvent
    call SetEvent
    pop rcx
    
@already_loading:
    ret
Beacon_LoadModelAsync endp

;----------------------------------------------------------------------------
; Beacon_Touch - Reset idle timer (called per token)
; rcx = beacon pointer
;----------------------------------------------------------------------------
align 8
Beacon_Touch proc
    push rcx
    call GetTickCount64
    pop rcx
    mov [rcx+Beacon.lastAccessTime], rax
    
    inc dword ptr [rcx+Beacon.lockCount]
    
    ret
Beacon_Touch endp

;----------------------------------------------------------------------------
; Beacon_GetStatus - Poll current state
; rcx = beacon pointer
; Returns: eax = state (0,1,2,3)
;----------------------------------------------------------------------------
align 8
Beacon_GetStatus proc
    mov eax, [rcx+Beacon.state]
    ret
Beacon_GetStatus endp

;----------------------------------------------------------------------------
; Beacon_WaitLoadComplete - Block until loaded
; rcx = beacon pointer
; rdx = timeout_ms (0 = infinite)
; Returns: 0=success, -1=timeout
;----------------------------------------------------------------------------
align 8
Beacon_WaitLoadComplete proc
    mov rcx, [rcx+Beacon.hEvent]
    call WaitForSingleObject
    
    cmp eax, WAIT_OBJECT_0
    jne @timeout
    
    xor eax, eax
    ret
    
@timeout:
    mov eax, -1
    ret
Beacon_WaitLoadComplete endp

;----------------------------------------------------------------------------
; Beacon_PollNonBlocking - Check without blocking
; rcx = beacon pointer
; Returns: eax = state
;----------------------------------------------------------------------------
align 8
Beacon_PollNonBlocking proc
    push rcx
    mov rcx, [rcx+Beacon.hEvent]
    xor edx, edx
    call WaitForSingleObject
    pop rcx
    
    cmp eax, WAIT_TIMEOUT
    je @still_loading
    
    mov eax, [rcx+Beacon.state]
    ret
    
@still_loading:
    mov eax, LOADING
    ret
Beacon_PollNonBlocking endp

;----------------------------------------------------------------------------
; Beacon_UnloadModelAsync - Signal unload
; rcx = beacon pointer
;----------------------------------------------------------------------------
align 8
Beacon_UnloadModelAsync proc
    mov dword ptr [rcx+Beacon.state], EVICTING
    
    push rcx
    mov rcx, g_hMasterLoadEvent
    call SetEvent
    pop rcx
    
    ret
Beacon_UnloadModelAsync endp

;----------------------------------------------------------------------------
; Beacon_ShutdownSystem - Call at IDE exit
;----------------------------------------------------------------------------
align 8
Beacon_ShutdownSystem proc
    mov g_bShutdown, 1
    
    mov rcx, g_hMasterLoadEvent
    call SetEvent
    
    mov rcx, g_hLoaderThread
    mov edx, 5000
    call WaitForSingleObject
    
    mov rcx, g_hIdleThread
    mov edx, 5000
    call WaitForSingleObject
    
    mov rcx, g_beaconArray
    mov edx, MEM_RELEASE
    xor r8d, r8d
    call VirtualFree
    
    ret
Beacon_ShutdownSystem endp

;----------------------------------------------------------------------------
; Internal: LoaderThreadMain - Background worker
;----------------------------------------------------------------------------
align 16
LoaderThreadMain proc
    push rbp
    mov rbp, rsp
    
@loader_loop:
    mov rcx, g_hMasterLoadEvent
    mov edx, -1
    call WaitForSingleObject
    
    cmp g_bShutdown, 1
    je @thread_exit
    
    mov rsi, g_beaconArray
    mov rcx, g_beaconCount
    
@scan_loop:
    test rcx, rcx
    jz @loader_loop
    
    mov eax, [rsi+Beacon.state]
    cmp eax, LOADING
    je @load_model
    
    cmp eax, EVICTING
    je @evict_model
    
    add rsi, BEACON_SIZE
    dec rcx
    jmp @scan_loop
    
@load_model:
    push rsi
    push rcx
    
    mov ecx, 100
    call Sleep
    
    pop rcx
    pop rsi
    
    mov qword ptr [rsi+Beacon.modelPtr], 0FFFFFFFFh
    mov dword ptr [rsi+Beacon.state], LOADED
    
    push rsi
    push rcx
    mov rcx, [rsi+Beacon.hEvent]
    call SetEvent
    pop rcx
    pop rsi
    
    add rsi, BEACON_SIZE
    dec rcx
    jmp @scan_loop
    
@evict_model:
    mov qword ptr [rsi+Beacon.modelPtr], 0
    mov dword ptr [rsi+Beacon.state], UNLOADED
    mov qword ptr [rsi+Beacon.lastAccessTime], 0
    mov dword ptr [rsi+Beacon.lockCount], 0
    
    add rsi, BEACON_SIZE
    dec rcx
    jmp @scan_loop
    
@thread_exit:
    pop rbp
    xor eax, eax
    ret
LoaderThreadMain endp

;----------------------------------------------------------------------------
; Internal: IdleDetectorThreadMain - Auto-evict idle models
;----------------------------------------------------------------------------
align 16
IdleDetectorThreadMain proc
@idle_loop:
    mov ecx, 5000
    call Sleep
    
    cmp g_bShutdown, 1
    je @idle_exit
    
    mov rsi, g_beaconArray
    mov rcx, g_beaconCount
    
@check_idle:
    test rcx, rcx
    jz @idle_loop
    
    cmp dword ptr [rsi+Beacon.state], LOADED
    jne @next_model
    
    push rsi
    push rcx
    call GetTickCount64
    pop rcx
    pop rsi
    
    sub rax, [rsi+Beacon.lastAccessTime]
    
    cmp rax, 30000
    jl @next_model
    
    cmp dword ptr [rsi+Beacon.lockCount], 0
    jne @next_model
    
    mov dword ptr [rsi+Beacon.state], EVICTING
    push rsi
    push rcx
    mov rcx, g_hMasterLoadEvent
    call SetEvent
    pop rcx
    pop rsi
    
@next_model:
    add rsi, BEACON_SIZE
    dec rcx
    jmp @check_idle
    
@idle_exit:
    xor eax, eax
    ret
IdleDetectorThreadMain endp

end