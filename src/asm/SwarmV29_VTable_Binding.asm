; =============================================================================
; SwarmV29_VTable_Binding.asm - Production Integration
; =============================================================================
; Binds VTable to actual backend implementations
; OpenGL, Vulkan, Direct3D backends
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_Bind_OpenGL
PUBLIC SwarmV29_Bind_Vulkan
PUBLIC SwarmV29_Bind_D3D11
PUBLIC SwarmV29_Bind_D3D12
PUBLIC SwarmV29_Bind_Null
PUBLIC SwarmV29_Bind_Custom

; =============================================================================
;                            EXTERNALS
; =============================================================================
EXTERN SwarmV29_VTable_Init:PROC
EXTERN SwarmV29_VTable_Set:PROC

; =============================================================================
;                            DATA
; =============================================================================
.data

; Backend type
CurrentBackend DWORD 0    ; 0: None, 1: OpenGL, 2: Vulkan, 3: D3D11, 4: D3D12, 5: Null, 6: Custom

; Backend names
ALIGN 8
BackendNames QWORD OFFSET BackendNoneName
             QWORD OFFSET BackendOpenGLName
             QWORD OFFSET BackendVulkanName
             QWORD OFFSET BackendD3D11Name
             QWORD OFFSET BackendD3D12Name
             QWORD OFFSET BackendNullName
             QWORD OFFSET BackendCustomName

BackendNoneName   BYTE "None", 0
BackendOpenGLName BYTE "OpenGL", 0
BackendVulkanName BYTE "Vulkan", 0
BackendD3D11Name  BYTE "Direct3D 11", 0
BackendD3D12Name  BYTE "Direct3D 12", 0
BackendNullName   BYTE "Null", 0
BackendCustomName BYTE "Custom", 0

; VTable function array (39 QWORDs)
ALIGN 64
VTableFunctions QWORD 39 DUP (<>)

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_Bind_OpenGL
; Bind VTable to OpenGL backend
;
; RCX = OpenGL function table pointer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Bind_OpenGL PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    
    mov r12, rcx            ; OpenGL function table
    
    ; Set backend type
    mov DWORD PTR [CurrentBackend], 1
    
    ; Initialize VTable functions array
    lea rdi, VTableFunctions
    
    ; Core Functions (13)
    mov rax, QWORD PTR [r12 + 0]     ; Initialize
    mov QWORD PTR [rdi + 0], rax
    mov rax, QWORD PTR [r12 + 8]     ; Shutdown
    mov QWORD PTR [rdi + 8], rax
    mov rax, QWORD PTR [r12 + 16]    ; GetDeviceCaps
    mov QWORD PTR [rdi + 16], rax
    mov rax, QWORD PTR [r12 + 24]    ; GetDeviceInfo
    mov QWORD PTR [rdi + 24], rax
    mov rax, QWORD PTR [r12 + 32]    ; GetLastError
    mov QWORD PTR [rdi + 32], rax
    mov rax, QWORD PTR [r12 + 40]    ; ClearError
    mov QWORD PTR [rdi + 40], rax
    mov rax, QWORD PTR [r12 + 48]    ; SetViewport
    mov QWORD PTR [rdi + 48], rax
    mov rax, QWORD PTR [r12 + 56]    ; SetScissor
    mov QWORD PTR [rdi + 56], rax
    mov rax, QWORD PTR [r12 + 64]    ; SetClearColor
    mov QWORD PTR [rdi + 64], rax
    mov rax, QWORD PTR [r12 + 72]    ; SetClearDepth
    mov QWORD PTR [rdi + 72], rax
    mov rax, QWORD PTR [r12 + 80]    ; SetClearStencil
    mov QWORD PTR [rdi + 80], rax
    mov rax, QWORD PTR [r12 + 88]    ; Clear
    mov QWORD PTR [rdi + 88], rax
    mov rax, QWORD PTR [r12 + 96]    ; Flush
    mov QWORD PTR [rdi + 96], rax
    
    ; Buffer Management (8)
    mov rax, QWORD PTR [r12 + 104]   ; CreateBuffer
    mov QWORD PTR [rdi + 104], rax
    mov rax, QWORD PTR [r12 + 112]   ; DestroyBuffer
    mov QWORD PTR [rdi + 112], rax
    mov rax, QWORD PTR [r12 + 120]   ; MapBuffer
    mov QWORD PTR [rdi + 120], rax
    mov rax, QWORD PTR [r12 + 128]   ; UnmapBuffer
    mov QWORD PTR [rdi + 128], rax
    mov rax, QWORD PTR [r12 + 136]   ; WriteBuffer
    mov QWORD PTR [rdi + 136], rax
    mov rax, QWORD PTR [r12 + 144]   ; ReadBuffer
    mov QWORD PTR [rdi + 144], rax
    mov rax, QWORD PTR [r12 + 152]   ; CopyBuffer
    mov QWORD PTR [rdi + 152], rax
    mov rax, QWORD PTR [r12 + 160]   ; FlushBuffer
    mov QWORD PTR [rdi + 160], rax
    
    ; Texture Management (8)
    mov rax, QWORD PTR [r12 + 168]   ; CreateTexture
    mov QWORD PTR [rdi + 168], rax
    mov rax, QWORD PTR [r12 + 176]   ; DestroyTexture
    mov QWORD PTR [rdi + 176], rax
    mov rax, QWORD PTR [r12 + 184]   ; BindTexture
    mov QWORD PTR [rdi + 184], rax
    mov rax, QWORD PTR [r12 + 192]   ; UnbindTexture
    mov QWORD PTR [rdi + 192], rax
    mov rax, QWORD PTR [r12 + 200]   ; UploadTexture
    mov QWORD PTR [rdi + 200], rax
    mov rax, QWORD PTR [r12 + 208]   ; DownloadTexture
    mov QWORD PTR [rdi + 208], rax
    mov rax, QWORD PTR [r12 + 216]   ; GenerateMips
    mov QWORD PTR [rdi + 216], rax
    mov rax, QWORD PTR [r12 + 224]   ; SetTextureParams
    mov QWORD PTR [rdi + 224], rax
    
    ; Shader Management (6)
    mov rax, QWORD PTR [r12 + 232]   ; CreateShader
    mov QWORD PTR [rdi + 232], rax
    mov rax, QWORD PTR [r12 + 240]   ; DestroyShader
    mov QWORD PTR [rdi + 240], rax
    mov rax, QWORD PTR [r12 + 248]   ; BindShader
    mov QWORD PTR [rdi + 248], rax
    mov rax, QWORD PTR [r12 + 256]   ; UnbindShader
    mov QWORD PTR [rdi + 256], rax
    mov rax, QWORD PTR [r12 + 264]   ; SetUniform
    mov QWORD PTR [rdi + 264], rax
    mov rax, QWORD PTR [r12 + 272]   ; SetUniformBuffer
    mov QWORD PTR [rdi + 272], rax
    
    ; Draw Calls (4)
    mov rax, QWORD PTR [r12 + 280]   ; DrawArrays
    mov QWORD PTR [rdi + 280], rax
    mov rax, QWORD PTR [r12 + 288]   ; DrawElements
    mov QWORD PTR [rdi + 288], rax
    mov rax, QWORD PTR [r12 + 296]   ; DrawArraysInstanced
    mov QWORD PTR [rdi + 296], rax
    mov rax, QWORD PTR [r12 + 304]   ; DrawElementsInstanced
    mov QWORD PTR [rdi + 304], rax
    
    ; Initialize VTable
    lea rcx, VTableFunctions
    call SwarmV29_VTable_Init
    
    xor eax, eax
    jmp @@done
    
@@invalid_params:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Bind_OpenGL ENDP

; =============================================================================
; SwarmV29_Bind_Vulkan
; Bind VTable to Vulkan backend
;
; RCX = Vulkan function table pointer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Bind_Vulkan PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    
    mov r12, rcx
    
    ; Set backend type
    mov DWORD PTR [CurrentBackend], 2
    
    ; Initialize VTable functions array
    lea rdi, VTableFunctions
    
    ; Copy all 39 function pointers
    mov ecx, 39
    rep movsq
    
    ; Initialize VTable
    lea rcx, VTableFunctions
    call SwarmV29_VTable_Init
    
    xor eax, eax
    jmp @@done
    
@@invalid_params:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Bind_Vulkan ENDP

; =============================================================================
; SwarmV29_Bind_D3D11
; Bind VTable to Direct3D 11 backend
;
; RCX = D3D11 function table pointer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Bind_D3D11 PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    
    mov r12, rcx
    
    ; Set backend type
    mov DWORD PTR [CurrentBackend], 3
    
    ; Initialize VTable functions array
    lea rdi, VTableFunctions
    
    ; Copy all 39 function pointers
    mov ecx, 39
    rep movsq
    
    ; Initialize VTable
    lea rcx, VTableFunctions
    call SwarmV29_VTable_Init
    
    xor eax, eax
    jmp @@done
    
@@invalid_params:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Bind_D3D11 ENDP

; =============================================================================
; SwarmV29_Bind_D3D12
; Bind VTable to Direct3D 12 backend
;
; RCX = D3D12 function table pointer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Bind_D3D12 PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    
    mov r12, rcx
    
    ; Set backend type
    mov DWORD PTR [CurrentBackend], 4
    
    ; Initialize VTable functions array
    lea rdi, VTableFunctions
    
    ; Copy all 39 function pointers
    mov ecx, 39
    rep movsq
    
    ; Initialize VTable
    lea rcx, VTableFunctions
    call SwarmV29_VTable_Init
    
    xor eax, eax
    jmp @@done
    
@@invalid_params:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Bind_D3D12 ENDP

; =============================================================================
; SwarmV29_Bind_Null
; Bind VTable to null backend (for testing)
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Bind_Null PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Set backend type
    mov DWORD PTR [CurrentBackend], 5
    
    ; Clear all function pointers
    lea rdi, VTableFunctions
    xor eax, eax
    mov ecx, 39
    rep stosq
    
    ; Initialize VTable
    lea rcx, VTableFunctions
    call SwarmV29_VTable_Init
    
    xor eax, eax
    SWARMV29_ABI_EPILOG
SwarmV29_Bind_Null ENDP

; =============================================================================
; SwarmV29_Bind_Custom
; Bind VTable to custom backend
;
; RCX = custom function table pointer
;
; Returns: EAX = 0 on success
; =============================================================================
SwarmV29_Bind_Custom PROC FRAME
    SWARMV29_ABI_FRAME
    
    test rcx, rcx
    jz @@invalid_params
    
    mov r12, rcx
    
    ; Set backend type
    mov DWORD PTR [CurrentBackend], 6
    
    ; Initialize VTable functions array
    lea rdi, VTableFunctions
    
    ; Copy all 39 function pointers
    mov ecx, 39
    rep movsq
    
    ; Initialize VTable
    lea rcx, VTableFunctions
    call SwarmV29_VTable_Init
    
    xor eax, eax
    jmp @@done
    
@@invalid_params:
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Bind_Custom ENDP

END