; ==============================================================================
; SwarmV29_API_Bridge.asm
; PHASE-29f: Dynamic API Loading (No-Dep Architecture)
; Target: Load external APIs at runtime without static linking
; ------------------------------------------------------------------------------
; Architecture:
;   - Uses LoadLibraryA/GetProcAddress for runtime binding
;   - No .lib dependencies (pure dynamic linking)
;   - Supports multiple backends (OpenGL/DirectX/Vulkan)
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Dependencies: SwarmV29_Macros.inc
; ==============================================================================

INCLUDE SwarmV29_Macros.inc

; ==============================================================================
; External Function Declarations (kernel32.dll)
; ==============================================================================
EXTERN LoadLibraryA: PROC
EXTERN GetProcAddress: PROC
EXTERN FreeLibrary: PROC

; ==============================================================================
; API Bridge Structure
; ==============================================================================
.data
    ALIGN 64
    SwarmV29_API_Bridge STRUCT
        hModule             QWORD ?    ; DLL handle
        pFunction           QWORD ?    ; Function pointer
        FunctionName        BYTE 64 dup(?)
        Padding             BYTE 48 dup(?)
    SwarmV29_API_Bridge ENDS

    ; Global API bridges
    ALIGN 64
    g_User32_Bridge SwarmV29_API_Bridge <>
    g_D3D11_Bridge SwarmV29_API_Bridge <>
    g_OpenGL_Bridge SwarmV29_API_Bridge <>
    g_Vulkan_Bridge SwarmV29_API_Bridge <>
    
    ; DLL name strings
    ALIGN 8
    sz_User32_DLL     BYTE "user32.dll", 0
    sz_D3D11_DLL      BYTE "d3d11.dll", 0
    sz_OpenGL_DLL     BYTE "opengl32.dll", 0
    sz_Vulkan_DLL     BYTE "vulkan-1.dll", 0
    
    ; Function name strings
    ALIGN 8
    sz_CreateWindowExA      BYTE "CreateWindowExA", 0
    sz_DestroyWindow        BYTE "DestroyWindow", 0
    sz_GetDC                BYTE "GetDC", 0
    sz_ReleaseDC            BYTE "ReleaseDC", 0
    sz_PeekMessageA         BYTE "PeekMessageA", 0
    sz_DispatchMessageA     BYTE "DispatchMessageA", 0
    
    sz_D3D11CreateDevice    BYTE "D3D11CreateDevice", 0
    sz_D3D11CreateSwapChain BYTE "D3D11CreateDeviceAndSwapChain", 0
    
    sz_wglCreateContext     BYTE "wglCreateContext", 0
    sz_wglMakeCurrent       BYTE "wglMakeCurrent", 0
    sz_wglGetProcAddress    BYTE "wglGetProcAddress", 0
    
    sz_vkCreateInstance     BYTE "vkCreateInstance", 0
    sz_vkCreateDevice       BYTE "vkCreateDevice", 0

.code

; ==============================================================================
; API_LoadModule
; Loads a DLL module at runtime
; Input: RCX = Pointer to DLL name string
; Output: RAX = Module handle, 0 on failure
; ==============================================================================
ALIGN 16
API_LoadModule PROC
    SWARM_PROC_START API_LoadModule, <>
    
    ; Validate input
    SWARM_CHECK_NULL rcx, .Load_Failed
    
    ; Call LoadLibraryA
    call LoadLibraryA
    
    ; Check result
    test rax, rax
    jz .Load_Failed
    
    jmp .Epilogue
    
.Load_Failed:
    xor rax, rax
    int 3                         ; Debugger trap
    
.Epilogue:
    SWARM_PROC_END
API_LoadModule ENDP

; ==============================================================================
; API_GetFunction
; Gets a function pointer from a loaded module
; Input: RCX = Module handle, RDX = Function name string
; Output: RAX = Function pointer, 0 on failure
; ==============================================================================
ALIGN 16
API_GetFunction PROC
    SWARM_PROC_START API_GetFunction, <>
    
    ; Validate inputs
    SWARM_CHECK_NULL rcx, .Get_Failed
    SWARM_CHECK_NULL rdx, .Get_Failed
    
    ; Call GetProcAddress
    call GetProcAddress
    
    ; Check result
    test rax, rax
    jz .Get_Failed
    
    jmp .Epilogue
    
.Get_Failed:
    xor rax, rax
    int 3                         ; Debugger trap
    
.Epilogue:
    SWARM_PROC_END
API_GetFunction ENDP

; ==============================================================================
; API_FreeModule
; Frees a loaded DLL module
; Input: RCX = Module handle
; Output: RAX = 1 on success, 0 on failure
; ==============================================================================
ALIGN 16
API_FreeModule PROC
    SWARM_PROC_START API_FreeModule, <>
    
    ; Validate input
    SWARM_CHECK_NULL rcx, .Free_Failed
    
    ; Call FreeLibrary
    call FreeLibrary
    
    jmp .Epilogue
    
.Free_Failed:
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
API_FreeModule ENDP

; ==============================================================================
; API_Init_User32
; Initializes User32.dll bridge
; Output: RAX = 0 on success, error code on failure
; ==============================================================================
ALIGN 16
API_Init_User32 PROC
    SWARM_PROC_START API_Init_User32, <>
    
    ; Load user32.dll
    lea rcx, [sz_User32_DLL]
    call API_LoadModule
    test rax, rax
    jz .Init_Failed
    
    ; Store module handle
    mov [g_User32_Bridge.hModule], rax
    
    ; Success
    xor rax, rax
    jmp .Epilogue
    
.Init_Failed:
    mov rax, ERR_GPU_INIT_FAILED
    
.Epilogue:
    SWARM_PROC_END
API_Init_User32 ENDP

; ==============================================================================
; API_Init_D3D11
; Initializes Direct3D 11 bridge
; Output: RAX = 0 on success, error code on failure
; ==============================================================================
ALIGN 16
API_Init_D3D11 PROC
    SWARM_PROC_START API_Init_D3D11, <>
    
    ; Load d3d11.dll
    lea rcx, [sz_D3D11_DLL]
    call API_LoadModule
    test rax, rax
    jz .Init_Failed
    
    ; Store module handle
    mov [g_D3D11_Bridge.hModule], rax
    
    ; Get D3D11CreateDevice function pointer
    mov rcx, rax                  ; Module handle
    lea rdx, [sz_D3D11CreateDevice]
    call API_GetFunction
    test rax, rax
    jz .Init_Failed
    
    ; Store function pointer
    mov [g_D3D11_Bridge.pFunction], rax
    
    ; Success
    xor rax, rax
    jmp .Epilogue
    
.Init_Failed:
    mov rax, ERR_GPU_INIT_FAILED
    
.Epilogue:
    SWARM_PROC_END
API_Init_D3D11 ENDP

; ==============================================================================
; API_Init_OpenGL
; Initializes OpenGL bridge
; Output: RAX = 0 on success, error code on failure
; ==============================================================================
ALIGN 16
API_Init_OpenGL PROC
    SWARM_PROC_START API_Init_OpenGL, <>
    
    ; Load opengl32.dll
    lea rcx, [sz_OpenGL_DLL]
    call API_LoadModule
    test rax, rax
    jz .Init_Failed
    
    ; Store module handle
    mov [g_OpenGL_Bridge.hModule], rax
    
    ; Get wglCreateContext function pointer
    mov rcx, rax
    lea rdx, [sz_wglCreateContext]
    call API_GetFunction
    test rax, rax
    jz .Init_Failed
    
    mov [g_OpenGL_Bridge.pFunction], rax
    
    ; Success
    xor rax, rax
    jmp .Epilogue
    
.Init_Failed:
    mov rax, ERR_GPU_INIT_FAILED
    
.Epilogue:
    SWARM_PROC_END
API_Init_OpenGL ENDP

; ==============================================================================
; API_Init_Vulkan
; Initializes Vulkan bridge
; Output: RAX = 0 on success, error code on failure
; ==============================================================================
ALIGN 16
API_Init_Vulkan PROC
    SWARM_PROC_START API_Init_Vulkan, <>
    
    ; Load vulkan-1.dll
    lea rcx, [sz_Vulkan_DLL]
    call API_LoadModule
    test rax, rax
    jz .Init_Failed
    
    ; Store module handle
    mov [g_Vulkan_Bridge.hModule], rax
    
    ; Get vkCreateInstance function pointer
    mov rcx, rax
    lea rdx, [sz_vkCreateInstance]
    call API_GetFunction
    test rax, rax
    jz .Init_Failed
    
    mov [g_Vulkan_Bridge.pFunction], rax
    
    ; Success
    xor rax, rax
    jmp .Epilogue
    
.Init_Failed:
    mov rax, ERR_GPU_INIT_FAILED
    
.Epilogue:
    SWARM_PROC_END
API_Init_Vulkan ENDP

; ==============================================================================
; API_Call_D3D11CreateDevice
; Wrapper for D3D11CreateDevice call
; Input: Parameters as per D3D11CreateDevice signature
; Output: RAX = HRESULT
; ==============================================================================
ALIGN 16
API_Call_D3D11CreateDevice PROC
    SWARM_PROC_START API_Call_D3D11CreateDevice, <>
    
    ; Get function pointer
    mov rax, [g_D3D11_Bridge.pFunction]
    SWARM_VALIDATE_FUNC rax, ERR_VTABLE_NULL
    
    ; Call the function
    ; Note: Parameters are already in RCX, RDX, R8, R9 and stack
    call rax
    
    SWARM_PROC_END
API_Call_D3D11CreateDevice ENDP

; ==============================================================================
; API_GetBridgeStatus
; Returns status of all API bridges
; Output: RAX = Bitmask of loaded bridges
;         Bit 0: User32, Bit 1: D3D11, Bit 2: OpenGL, Bit 3: Vulkan
; ==============================================================================
ALIGN 16
API_GetBridgeStatus PROC
    xor rax, rax
    
    ; Check User32
    cmp qword ptr [g_User32_Bridge.hModule], 0
    setne al
    
    ; Check D3D11
    cmp qword ptr [g_D3D11_Bridge.hModule], 0
    setne cl
    shl cl, 1
    or al, cl
    
    ; Check OpenGL
    cmp qword ptr [g_OpenGL_Bridge.hModule], 0
    setne cl
    shl cl, 2
    or al, cl
    
    ; Check Vulkan
    cmp qword ptr [g_Vulkan_Bridge.hModule], 0
    setne cl
    shl cl, 3
    or al, cl
    
    ret
API_GetBridgeStatus ENDP

END