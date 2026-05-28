; ==============================================================================
; SwarmV29_Renderer_State_Cache.asm
; PHASE-29f: State Shadowing for "Approaching Zero Driver Overhead"
; Target: Eliminate redundant GPU state changes via dirty-state tracking
; ------------------------------------------------------------------------------
; Architecture:
;   - Maintains a shadow copy of all GPU state in CPU memory
;   - Compares requested state against shadow before issuing driver calls
;   - Only calls driver when state actually changes (massive performance gain)
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Dependencies: SwarmV29_Macros.inc
; ==============================================================================

INCLUDE SwarmV29_Macros.inc

; ==============================================================================
; State Shadowing Structure (64-byte cache-aligned)
; ==============================================================================
.data
    ALIGN 64
    Renderer_State_Cache STRUCT
        DepthTestEnabled    BYTE ?      ; 0=Disabled, 1=Enabled
        DepthFunc           BYTE ?      ; 0=Never, 1=Less, 2=Equal, 3=LEqual, etc.
        CullMode            BYTE ?      ; 0=None, 1=Front, 2=Back
        BlendMode           BYTE ?      ; 0=Opaque, 1=Alpha, 2=Additive
        ScissorEnabled      BYTE ?      ; 0=Disabled, 1=Enabled
        ViewportWidth       DWORD ?     ; Current viewport width
        ViewportHeight      DWORD ?      ; Current viewport height
        ActiveTextureSlot   DWORD ?      ; Currently bound texture slot
        BoundShaderProgram  QWORD ?     ; Currently bound shader program
        BoundVertexBuffer    QWORD ?     ; Currently bound VBO
        BoundIndexBuffer     QWORD ?     ; Currently bound IBO
        BoundVertexArray     QWORD ?     ; Currently bound VAO
        Padding             BYTE 24 dup(?) ; Pad to 64 bytes
    Renderer_State_Cache ENDS

    ; Global state instance (initialized to all zeros)
    g_CurrentState Renderer_State_Cache <>

    ; Dirty flags (bitmask of changed state)
    ALIGN 8
    g_StateDirtyFlags QWORD 0

    ; State change counters (for profiling)
    ALIGN 8
    g_StateChangesTotal   QWORD 0
    g_StateChangesSkipped QWORD 0

.code

; ==============================================================================
; Renderer_SetDepthTest
; Sets depth testing state with dirty tracking
; Input: RCX = Enable flag (0=Disable, 1=Enable)
;        RDX = Depth function (optional, 0=keep current)
; Output: RAX = 0 on success, error code on failure
; ==============================================================================
ALIGN 16
Renderer_SetDepthTest PROC
    SWARM_PROC_START Renderer_SetDepthTest, <>
    
    ; Compare against cached state
    mov al, [g_CurrentState.DepthTestEnabled]
    cmp al, cl
    je .Skip_DepthTest                    ; State unchanged, skip driver call
    
    ; State changed - update cache
    mov [g_CurrentState.DepthTestEnabled], cl
    
    ; Mark depth state as dirty
    or [g_StateDirtyFlags], 01h
    
    ; Update depth function if specified
    test rdx, rdx
    jz .Done
    mov [g_CurrentState.DepthFunc], dl
    or [g_StateDirtyFlags], 02h
    
.Done:
    inc [g_StateChangesTotal]
    xor rax, rax
    jmp .Epilogue
    
.Skip_DepthTest:
    inc [g_StateChangesSkipped]
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_SetDepthTest ENDP

; ==============================================================================
; Renderer_SetCullMode
; Sets face culling mode with dirty tracking
; Input: RCX = Cull mode (0=None, 1=Front, 2=Back)
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Renderer_SetCullMode PROC
    SWARM_PROC_START Renderer_SetCullMode, <>
    
    mov al, [g_CurrentState.CullMode]
    cmp al, cl
    je .Skip_CullMode
    
    ; State changed
    mov [g_CurrentState.CullMode], cl
    or [g_StateDirtyFlags], 04h
    inc [g_StateChangesTotal]
    xor rax, rax
    jmp .Epilogue
    
.Skip_CullMode:
    inc [g_StateChangesSkipped]
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_SetCullMode ENDP

; ==============================================================================
; Renderer_SetBlendMode
; Sets blending mode with dirty tracking
; Input: RCX = Blend mode (0=Opaque, 1=Alpha, 2=Additive)
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Renderer_SetBlendMode PROC
    SWARM_PROC_START Renderer_SetBlendMode, <>
    
    mov al, [g_CurrentState.BlendMode]
    cmp al, cl
    je .Skip_BlendMode
    
    ; State changed
    mov [g_CurrentState.BlendMode], cl
    or [g_StateDirtyFlags], 08h
    inc [g_StateChangesTotal]
    xor rax, rax
    jmp .Epilogue
    
.Skip_BlendMode:
    inc [g_StateChangesSkipped]
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_SetBlendMode ENDP

; ==============================================================================
; Renderer_SetViewport
; Sets viewport dimensions with dirty tracking
; Input: RCX = Width, RDX = Height
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Renderer_SetViewport PROC
    SWARM_PROC_START Renderer_SetViewport, <>
    
    ; Check width
    mov eax, [g_CurrentState.ViewportWidth]
    cmp eax, ecx
    jne .Viewport_Changed
    
    ; Check height
    mov eax, [g_CurrentState.ViewportHeight]
    cmp eax, edx
    je .Skip_Viewport
    
.Viewport_Changed:
    mov [g_CurrentState.ViewportWidth], ecx
    mov [g_CurrentState.ViewportHeight], edx
    or [g_StateDirtyFlags], 10h
    inc [g_StateChangesTotal]
    xor rax, rax
    jmp .Epilogue
    
.Skip_Viewport:
    inc [g_StateChangesSkipped]
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_SetViewport ENDP

; ==============================================================================
; Renderer_BindTexture
; Binds texture to slot with dirty tracking
; Input: RCX = Texture ID, RDX = Texture slot
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Renderer_BindTexture PROC
    SWARM_PROC_START Renderer_BindTexture, <>
    
    ; Check if slot matches
    mov eax, [g_CurrentState.ActiveTextureSlot]
    cmp eax, edx
    jne .Texture_Changed
    
    ; Check if texture ID matches (simplified - real impl would check array)
    ; For now, just mark as changed
    ; TODO: Implement texture ID tracking array
    
.Texture_Changed:
    mov [g_CurrentState.ActiveTextureSlot], edx
    or [g_StateDirtyFlags], 20h
    inc [g_StateChangesTotal]
    xor rax, rax
    jmp .Epilogue
    
.Skip_Texture:
    inc [g_StateChangesSkipped]
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_BindTexture ENDP

; ==============================================================================
; Renderer_BindShaderProgram
; Binds shader program with dirty tracking
; Input: RCX = Shader program ID
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Renderer_BindShaderProgram PROC
    SWARM_PROC_START Renderer_BindShaderProgram, <>
    
    mov rax, [g_CurrentState.BoundShaderProgram]
    cmp rax, rcx
    je .Skip_Shader
    
    ; State changed
    mov [g_CurrentState.BoundShaderProgram], rcx
    or [g_StateDirtyFlags], 40h
    inc [g_StateChangesTotal]
    xor rax, rax
    jmp .Epilogue
    
.Skip_Shader:
    inc [g_StateChangesSkipped]
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_BindShaderProgram ENDP

; ==============================================================================
; Renderer_BindVertexBuffer
; Binds vertex buffer with dirty tracking
; Input: RCX = Buffer ID
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Renderer_BindVertexBuffer PROC
    SWARM_PROC_START Renderer_BindVertexBuffer, <>
    
    mov rax, [g_CurrentState.BoundVertexBuffer]
    cmp rax, rcx
    je .Skip_VBO
    
    mov [g_CurrentState.BoundVertexBuffer], rcx
    or [g_StateDirtyFlags], 80h
    inc [g_StateChangesTotal]
    xor rax, rax
    jmp .Epilogue
    
.Skip_VBO:
    inc [g_StateChangesSkipped]
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_BindVertexBuffer ENDP

; ==============================================================================
; Renderer_GetStateStats
; Returns state change statistics for profiling
; Output: RAX = Total state changes, RCX = Skipped changes
; ==============================================================================
ALIGN 16
Renderer_GetStateStats PROC
    mov rax, [g_StateChangesTotal]
    mov rcx, [g_StateChangesSkipped]
    ret
Renderer_GetStateStats ENDP

; ==============================================================================
; Renderer_ResetStateCache
; Resets all cached state (call after backend switch)
; ==============================================================================
ALIGN 16
Renderer_ResetStateCache PROC
    ; Zero out the entire state structure
    lea rdi, [g_CurrentState]
    mov rcx, SIZEOF Renderer_State_Cache
    xor eax, eax
    rep stosb
    
    ; Clear dirty flags
    mov qword ptr [g_StateDirtyFlags], 0
    
    ; Reset counters
    mov qword ptr [g_StateChangesTotal], 0
    mov qword ptr [g_StateChangesSkipped], 0
    
    ret
Renderer_ResetStateCache ENDP

; ==============================================================================
; Renderer_FlushDirtyState
; Flushes all dirty state to GPU (calls actual driver functions)
; This is where the VTable would be called in a real implementation
; ==============================================================================
ALIGN 16
Renderer_FlushDirtyState PROC
    SWARM_PROC_START Renderer_FlushDirtyState, <>
    
    ; Check if any state is dirty
    mov rax, [g_StateDirtyFlags]
    test rax, rax
    jz .No_Dirty_State
    
    ; TODO: Call actual driver functions via VTable
    ; For now, just clear the dirty flags
    mov qword ptr [g_StateDirtyFlags], 0
    
.No_Dirty_State:
    xor rax, rax
    
.Epilogue:
    SWARM_PROC_END
Renderer_FlushDirtyState ENDP

END