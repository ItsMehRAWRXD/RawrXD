; =============================================================================
; SwarmV29_Renderer_VTable.asm - Backend-Agnostic Renderer Interface
; =============================================================================
; 39 function pointers for AZDO rendering
; Supports OpenGL, Vulkan, Direct3D backends
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            TYPE DEFINITIONS
; =============================================================================
SWARMV29_RENDERER_VTABLE STRUCT
    ; ========================================
    ; Core Functions (13)
    ; ========================================
    Initialize          QWORD ?    ; Initialize renderer
    Shutdown            QWORD ?    ; Shutdown renderer
    GetDeviceCaps       QWORD ?    ; Get device capabilities
    GetDeviceInfo       QWORD ?    ; Get device info string
    GetLastError         QWORD ?    ; Get last error code
    ClearError          QWORD ?    ; Clear error state
    SetViewport         QWORD ?    ; Set viewport
    SetScissor          QWORD ?    ; Set scissor rect
    SetClearColor       QWORD ?    ; Set clear color
    SetClearDepth       QWORD ?    ; Set clear depth
    SetClearStencil     QWORD ?    ; Set clear stencil
    Clear               QWORD ?    ; Clear buffers
    Flush               QWORD ?    ; Flush commands
    
    ; ========================================
    ; Buffer Management (8)
    ; ========================================
    CreateBuffer        QWORD ?    ; Create GPU buffer
    DestroyBuffer       QWORD ?    ; Destroy GPU buffer
    MapBuffer           QWORD ?    ; Map buffer for CPU access
    UnmapBuffer         QWORD ?    ; Unmap buffer
    WriteBuffer        QWORD ?    ; Write to buffer
    ReadBuffer          QWORD ?    ; Read from buffer
    CopyBuffer          QWORD ?    ; Copy buffer to buffer
    FlushBuffer         QWORD ?    ; Flush buffer range
    
    ; ========================================
    ; Texture Management (8)
    ; ========================================
    CreateTexture       QWORD ?    ; Create texture
    DestroyTexture      QWORD ?    ; Destroy texture
    BindTexture         QWORD ?    ; Bind texture to slot
    UnbindTexture       QWORD ?    ; Unbind texture
    UploadTexture       QWORD ?    ; Upload texture data
    DownloadTexture     QWORD ?    ; Download texture data
    GenerateMips        QWORD ?    ; Generate mipmaps
    SetTextureParams    QWORD ?    ; Set texture parameters
    
    ; ========================================
    ; Shader Management (6)
    ; ========================================
    CreateShader        QWORD ?    ; Create shader program
    DestroyShader       QWORD ?    ; Destroy shader program
    BindShader          QWORD ?    ; Bind shader program
    UnbindShader        QWORD ?    ; Unbind shader program
    SetUniform          QWORD ?    ; Set uniform value
    SetUniformBuffer    QWORD ?    ; Set uniform buffer
    
    ; ========================================
    ; Draw Calls (4)
    ; ========================================
    DrawArrays          QWORD ?    ; Draw arrays
    DrawElements        QWORD ?    ; Draw indexed
    DrawArraysInstanced QWORD ?    ; Draw instanced arrays
    DrawElementsInstanced QWORD ?  ; Draw instanced indexed
    
    ; ========================================
    ; State Management (0 - handled by State Cache)
    ; ========================================
    
    ; Total: 39 function pointers
SWARMV29_RENDERER_VTABLE ENDS

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_VTable_Init
PUBLIC SwarmV29_VTable_Get
PUBLIC SwarmV29_VTable_Set
PUBLIC SwarmV29_VTable_Validate
PUBLIC SwarmV29_VTable_GetMissingCount
PUBLIC SwarmV29_VTable_GetFinishedCount

; =============================================================================
;                            DATA
; =============================================================================
.data

; Global VTable instance
ALIGN 64
g_VTable SWARMV29_RENDERER_VTABLE <>

; VTable status
VTableInitialized DWORD 0
VTableMissingCount DWORD 0
VTableFinishedCount DWORD 0

; Function names for debugging
ALIGN 8
VTableFunctionNames QWORD OFFSET InitializeName
                     QWORD OFFSET ShutdownName
                     QWORD OFFSET GetDeviceCapsName
                     QWORD OFFSET GetDeviceInfoName
                     QWORD OFFSET GetLastErrorName
                     QWORD OFFSET ClearErrorName
                     QWORD OFFSET SetViewportName
                     QWORD OFFSET SetScissorName
                     QWORD OFFSET SetClearColorName
                     QWORD OFFSET SetClearDepthName
                     QWORD OFFSET SetClearStencilName
                     QWORD OFFSET ClearName
                     QWORD OFFSET FlushName
                     QWORD OFFSET CreateBufferName
                     QWORD OFFSET DestroyBufferName
                     QWORD OFFSET MapBufferName
                     QWORD OFFSET UnmapBufferName
                     QWORD OFFSET WriteBufferName
                     QWORD OFFSET ReadBufferName
                     QWORD OFFSET CopyBufferName
                     QWORD OFFSET FlushBufferName
                     QWORD OFFSET CreateTextureName
                     QWORD OFFSET DestroyTextureName
                     QWORD OFFSET BindTextureName
                     QWORD OFFSET UnbindTextureName
                     QWORD OFFSET UploadTextureName
                     QWORD OFFSET DownloadTextureName
                     QWORD OFFSET GenerateMipsName
                     QWORD OFFSET SetTextureParamsName
                     QWORD OFFSET CreateShaderName
                     QWORD OFFSET DestroyShaderName
                     QWORD OFFSET BindShaderName
                     QWORD OFFSET UnbindShaderName
                     QWORD OFFSET SetUniformName
                     QWORD OFFSET SetUniformBufferName
                     QWORD OFFSET DrawArraysName
                     QWORD OFFSET DrawElementsName
                     QWORD OFFSET DrawArraysInstancedName
                     QWORD OFFSET DrawElementsInstancedName

; Function name strings
InitializeName          BYTE "Initialize", 0
ShutdownName            BYTE "Shutdown", 0
GetDeviceCapsName       BYTE "GetDeviceCaps", 0
GetDeviceInfoName       BYTE "GetDeviceInfo", 0
GetLastErrorName        BYTE "GetLastError", 0
ClearErrorName          BYTE "ClearError", 0
SetViewportName         BYTE "SetViewport", 0
SetScissorName          BYTE "SetScissor", 0
SetClearColorName       BYTE "SetClearColor", 0
SetClearDepthName       BYTE "SetClearDepth", 0
SetClearStencilName     BYTE "SetClearStencil", 0
ClearName               BYTE "Clear", 0
FlushName               BYTE "Flush", 0
CreateBufferName        BYTE "CreateBuffer", 0
DestroyBufferName       BYTE "DestroyBuffer", 0
MapBufferName           BYTE "MapBuffer", 0
UnmapBufferName         BYTE "UnmapBuffer", 0
WriteBufferName         BYTE "WriteBuffer", 0
ReadBufferName           BYTE "ReadBuffer", 0
CopyBufferName          BYTE "CopyBuffer", 0
FlushBufferName         BYTE "FlushBuffer", 0
CreateTextureName       BYTE "CreateTexture", 0
DestroyTextureName      BYTE "DestroyTexture", 0
BindTextureName         BYTE "BindTexture", 0
UnbindTextureName       BYTE "UnbindTexture", 0
UploadTextureName       BYTE "UploadTexture", 0
DownloadTextureName     BYTE "DownloadTexture", 0
GenerateMipsName        BYTE "GenerateMips", 0
SetTextureParamsName    BYTE "SetTextureParams", 0
CreateShaderName        BYTE "CreateShader", 0
DestroyShaderName       BYTE "DestroyShader", 0
BindShaderName          BYTE "BindShader", 0
UnbindShaderName        BYTE "UnbindShader", 0
SetUniformName          BYTE "SetUniform", 0
SetUniformBufferName    BYTE "SetUniformBuffer", 0
DrawArraysName          BYTE "DrawArrays", 0
DrawElementsName        BYTE "DrawElements", 0
DrawArraysInstancedName BYTE "DrawArraysInstanced", 0
DrawElementsInstancedName BYTE "DrawElementsInstanced", 0

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_VTable_Init
; Initialize VTable with function pointers
;
; RCX = function pointer array (39 QWORDs)
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_VTable_Init PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    
    ; Copy function pointers
    lea rdi, g_VTable
    mov rsi, rcx
    mov ecx, SIZEOF SWARMV29_RENDERER_VTABLE / 8
    rep movsq
    
    ; Mark as initialized
    mov DWORD PTR [VTableInitialized], 1
    
    ; Validate and count
    call SwarmV29_VTable_Validate
    
    xor eax, eax
    jmp @@done
    
@@invalid_params:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_VTable_Init ENDP

; =============================================================================
; SwarmV29_VTable_Get
; Get VTable pointer
;
; Returns: RAX = pointer to VTable
; =============================================================================
SwarmV29_VTable_Get PROC FRAME
    SWARMV29_ABI_FRAME
    
    lea rax, g_VTable
    
    SWARMV29_ABI_EPILOG
SwarmV29_VTable_Get ENDP

; =============================================================================
; SwarmV29_VTable_Set
; Set individual function pointer
;
; RCX = function index (0-38)
; RDX = function pointer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_VTable_Set PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Validate index
    cmp ecx, 0
    jl @@invalid_index
    cmp ecx, 39
    jge @@invalid_index
    
    ; Set function pointer
    lea rax, g_VTable
    mov QWORD PTR [rax + rcx * 8], rdx
    
    xor eax, eax
    jmp @@done
    
@@invalid_index:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_VTable_Set ENDP

; =============================================================================
; SwarmV29_VTable_Validate
; Validate VTable and count missing/finished functions
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_VTable_Validate PROC FRAME
    SWARMV29_ABI_FRAME
    
    xor ebx, ebx            ; missing count
    xor ecx, ecx            ; finished count
    xor edx, edx            ; index
    
@@validate_loop:
    cmp edx, 39
    jge @@validate_done
    
    ; Get function pointer
    lea rax, g_VTable
    mov rax, QWORD PTR [rax + rdx * 8]
    
    ; Check if null (missing)
    test rax, rax
    jz @@missing
    
    ; Check if implemented (finished)
    ; A finished function has a valid address (not a stub)
    ; For now, just count non-null as finished
    inc ecx                 ; finished count
    jmp @@next
    
@@missing:
    inc ebx                 ; missing count
    
@@next:
    inc edx
    jmp @@validate_loop
    
@@validate_done:
    mov DWORD PTR [VTableMissingCount], ebx
    mov DWORD PTR [VTableFinishedCount], ecx
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
SwarmV29_VTable_Validate ENDP

; =============================================================================
; SwarmV29_VTable_GetMissingCount
; Get count of missing functions
;
; Returns: EAX = missing count
; =============================================================================
SwarmV29_VTable_GetMissingCount PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov eax, DWORD PTR [VTableMissingCount]
    
    SWARMV29_ABI_EPILOG
SwarmV29_VTable_GetMissingCount ENDP

; =============================================================================
; SwarmV29_VTable_GetFinishedCount
; Get count of finished functions
;
; Returns: EAX = finished count
; =============================================================================
SwarmV29_VTable_GetFinishedCount PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov eax, DWORD PTR [VTableFinishedCount]
    
    SWARMV29_ABI_EPILOG
SwarmV29_VTable_GetFinishedCount ENDP

END