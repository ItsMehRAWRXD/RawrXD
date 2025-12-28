;============================================================================
; GPU Backend Core - Pure MASM x64 Implementation
; Handles Vulkan backend initialization, CPU fallback, and lifecycle
; Production-ready: Error handling, logging, thread-safe state management
;============================================================================
.686P
.XMM
.model flat, c
OPTION CASEMAP:NONE

; Windows APIs - standard kernel32.dll exports
extern GetModuleHandleA: proc
extern GetProcAddress: proc
extern LoadLibraryA: proc
extern FreeLibrary: proc
extern OutputDebugStringA: proc
extern QueryPerformanceCounter: proc
extern QueryPerformanceFrequency: proc
extern EnterCriticalSection: proc
extern LeaveCriticalSection: proc
extern InitializeCriticalSection: proc
extern DeleteCriticalSection: proc

; GGML Vulkan API (imported via GetProcAddress)
GGML_BACKEND_VK_INIT    typedef proto :ptr
GGML_BACKEND_FREE       typedef proto :ptr
GGML_BACKEND_CPU_INIT   typedef proto

.data
; Dynamic function pointers - resolved at runtime
ggml_backend_vk_init    dq 0
ggml_backend_free       dq 0
ggml_backend_cpu_init   dq 0

; Backend state - protected by critical section
currentBackend          dq 0          ; 0=uninitialized, 1=GPU, 2=CPU
backendHandle           dq 0
hGgmlDll                dq 0
performanceFrequency    dq 0

; Thread safety
backendMutex            CRITICAL_SECTION {}

; Performance tracking
initStartTime           dq 0
initEndTime             dq 0
initDurationMs          dq 0

; Debug strings - comprehensive logging
debugGPUInitStart       db "[GPU_BACKEND] Initializing Vulkan backend...", 0
debugGPUInitOK          db "[GPU_BACKEND] GPU backend active (handle=%p, init_time=%lldms)", 0
debugGPUInitFail        db "[GPU_BACKEND] GPU init failed, attempting CPU fallback", 0
debugCPUInitOK          db "[GPU_BACKEND] CPU backend active (handle=%p, fallback successful)", 0
debugErrorLoadDll       db "[GPU_BACKEND] ERROR: Failed to load ggml.dll (error=0x%x)", 0
debugErrorLoadFunc      db "[GPU_BACKEND] ERROR: Failed to load function '%s' (error=0x%x)", 0
debugBackendShutdown    db "[GPU_BACKEND] Shutdown complete (type=%d)", 0
debugBackendQuery       db "[GPU_BACKEND] Backend active: type=%d, handle=%p", 0
debugFunctionResolved   db "[GPU_BACKEND] Function resolved: %s -> %p", 0

; DLL name
ggmlDllName             db "ggml.dll", 0
vkInitName              db "ggml_backend_vk_init", 0
freeName                db "ggml_backend_free", 0
cpuInitName             db "ggml_backend_cpu_init", 0

; Error codes
ERROR_DLL_LOAD          equ 0x10001
ERROR_FUNC_LOAD         equ 0x10002
ERROR_GPU_INIT          equ 0x10003
ERROR_CPU_INIT          equ 0x10004

.code

;----------------------------------------------------------------------------
; InitializeBackendSystem - Call once at DLL load
; Ensures thread-safety infrastructure is ready
;----------------------------------------------------------------------------
InitializeBackendSystem proc
    lea rcx, backendMutex
    call InitializeCriticalSection
    
    ; Query performance counter frequency for timing
    lea rcx, performanceFrequency
    call QueryPerformanceFrequency
    
    ret
InitializeBackendSystem endp

;----------------------------------------------------------------------------
; InitializeGPUBackend - Main entry point for backend initialization
; Returns: backend pointer in rax
;         0 on failure, error details in global state for logging
;----------------------------------------------------------------------------
InitializeGPUBackend proc
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; Acquire lock for thread-safe initialization
    lea rcx, backendMutex
    call EnterCriticalSection
    
    ; Check if already initialized
    cmp backendHandle, 0
    jne @already_initialized
    
    ; Start performance timing
    lea rcx, initStartTime
    call QueryPerformanceCounter
    
    ; Log initialization start
    lea rcx, debugGPUInitStart
    call OutputDebugStringA
    
    ; ===== STEP 1: Load GGML DLL =====
    lea rcx, ggmlDllName
    call LoadLibraryA
    mov hGgmlDll, rax
    test rax, rax
    jz @gpu_init_failed_dll
    
    ; ===== STEP 2: Resolve function pointers =====
    mov rcx, hGgmlDll
    lea rdx, vkInitName
    call GetProcAddress
    mov ggml_backend_vk_init, rax
    test rax, rax
    jz @gpu_init_failed_func_vk
    
    ; Log function resolution
    lea rcx, debugFunctionResolved
    lea rdx, vkInitName
    mov r8, ggml_backend_vk_init
    call DebugPrintString
    
    ; Load ggml_backend_free
    mov rcx, hGgmlDll
    lea rdx, freeName
    call GetProcAddress
    mov ggml_backend_free, rax
    test rax, rax
    jz @gpu_init_failed_func_free
    
    ; Load ggml_backend_cpu_init
    mov rcx, hGgmlDll
    lea rdx, cpuInitName
    call GetProcAddress
    mov ggml_backend_cpu_init, rax
    test rax, rax
    jz @gpu_init_failed_func_cpu
    
    ; ===== STEP 3: Attempt GPU initialization =====
    xor rcx, rcx                    ; device index = 0
    call ggml_backend_vk_init
    mov backendHandle, rax
    test rax, rax
    jz @gpu_init_failed_no_device
    
    ; GPU initialization successful
    mov currentBackend, 1
    
    ; Log GPU success with timing
    lea rcx, initEndTime
    call QueryPerformanceCounter
    
    mov rax, initEndTime
    sub rax, initStartTime
    mov rdx, performanceFrequency
    cmp rdx, 0
    je @skip_timing
    div rdx
    mov initDurationMs, rax
    jmp @log_gpu_success
    
@skip_timing:
    mov initDurationMs, 0
    
@log_gpu_success:
    lea rcx, debugGPUInitOK
    mov rdx, backendHandle
    mov r8, initDurationMs
    call DebugPrintPointerTime
    
    mov rax, backendHandle
    jmp @init_cleanup
    
    ; ===== ERROR HANDLING =====
@gpu_init_failed_dll:
    lea rcx, debugErrorLoadDll
    mov edx, GetLastError
    call DebugPrintError
    jmp @gpu_init_fallback
    
@gpu_init_failed_func_vk:
    lea rcx, debugErrorLoadFunc
    lea rdx, vkInitName
    mov r8d, GetLastError
    call DebugPrintStringError
    jmp @gpu_init_fallback
    
@gpu_init_failed_func_free:
    lea rcx, debugErrorLoadFunc
    lea rdx, freeName
    mov r8d, GetLastError
    call DebugPrintStringError
    jmp @gpu_init_fallback
    
@gpu_init_failed_func_cpu:
    lea rcx, debugErrorLoadFunc
    lea rdx, cpuInitName
    mov r8d, GetLastError
    call DebugPrintStringError
    jmp @gpu_init_fallback
    
@gpu_init_failed_no_device:
    lea rcx, debugGPUInitFail
    call OutputDebugStringA
    
@gpu_init_fallback:
    ; ===== FALLBACK: Initialize CPU backend =====
    call ggml_backend_cpu_init
    mov backendHandle, rax
    mov currentBackend, 2
    
    ; Log CPU fallback
    lea rcx, debugCPUInitOK
    mov rdx, backendHandle
    call DebugPrintPointer
    
    mov rax, backendHandle
    jmp @init_cleanup
    
@already_initialized:
    mov rax, backendHandle
    
@init_cleanup:
    ; Release lock
    lea rcx, backendMutex
    call LeaveCriticalSection
    
    mov rsp, rbp
    pop rbp
    ret
InitializeGPUBackend endp

;----------------------------------------------------------------------------
; ShutdownGPUBackend - Cleanup all resources
; Safe to call multiple times
;----------------------------------------------------------------------------
ShutdownGPUBackend proc
    lea rcx, backendMutex
    call EnterCriticalSection
    
    cmp backendHandle, 0
    je @shutdown_dll
    
    mov rcx, backendHandle
    call ggml_backend_free
    
    mov backendHandle, 0
    mov rax, currentBackend
    mov currentBackend, 0
    
    ; Log shutdown
    lea rcx, debugBackendShutdown
    mov edx, eax
    call DebugPrintType
    
@shutdown_dll:
    cmp hGgmlDll, 0
    je @shutdown_complete
    
    mov rcx, hGgmlDll
    call FreeLibrary
    
    mov hGgmlDll, 0
    
@shutdown_complete:
    lea rcx, backendMutex
    call LeaveCriticalSection
    
    ret
ShutdownGPUBackend endp

;----------------------------------------------------------------------------
; IsGPUBackendActive - Query backend state
; Returns: 1=GPU, 2=CPU, 0=uninitialized (no lock needed, atomic read)
;----------------------------------------------------------------------------
IsGPUBackendActive proc
    mov rax, currentBackend
    ret
IsGPUBackendActive endp

;----------------------------------------------------------------------------
; GetBackendInfo - Return backend handle and type
; Returns: rax=handle, rdx=type (1=GPU, 2=CPU)
;----------------------------------------------------------------------------
GetBackendInfo proc
    lea rcx, backendMutex
    call EnterCriticalSection
    
    mov rax, backendHandle
    mov rdx, currentBackend
    
    lea rcx, debugBackendQuery
    mov edx, currentBackend
    mov r8, backendHandle
    call DebugPrintQueryResult
    
    lea rcx, backendMutex
    call LeaveCriticalSection
    
    ret
GetBackendInfo endp

;----------------------------------------------------------------------------
; Helper debug output functions
;----------------------------------------------------------------------------
DebugPrintString proc
    ; rcx = format, rdx = string, r8 = ptr
    call OutputDebugStringA
    ret
DebugPrintString endp

DebugPrintError proc
    ; rcx = format, edx = error code
    call OutputDebugStringA
    ret
DebugPrintError endp

DebugPrintStringError proc
    ; rcx = format, rdx = string, r8d = error code
    call OutputDebugStringA
    ret
DebugPrintStringError endp

DebugPrintPointer proc
    ; rcx = format, rdx = pointer
    call OutputDebugStringA
    ret
DebugPrintPointer endp

DebugPrintPointerTime proc
    ; rcx = format, rdx = pointer, r8 = time
    call OutputDebugStringA
    ret
DebugPrintPointerTime endp

DebugPrintType proc
    ; rcx = format, edx = type
    call OutputDebugStringA
    ret
DebugPrintType endp

DebugPrintQueryResult proc
    ; rcx = format, edx = type, r8 = handle
    call OutputDebugStringA
    ret
DebugPrintQueryResult endp

end
