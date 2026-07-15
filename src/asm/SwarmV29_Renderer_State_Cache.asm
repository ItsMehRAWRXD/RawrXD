; =============================================================================
; SwarmV29_Renderer_State_Cache.asm - State Shadowing for AZDO
; =============================================================================
; Approaching Zero Driver Overhead (AZDO) state shadowing
; Tracks OpenGL state changes and skips redundant driver calls
; Date: 2026-07-08
; =============================================================================

INCLUDE SwarmV29_Macros.inc

; =============================================================================
;                            EXPORTS
; =============================================================================
PUBLIC SwarmV29_Init_State_Cache
PUBLIC SwarmV29_Shadow_State
PUBLIC SwarmV29_Get_Renderer_Stats
PUBLIC SwarmV29_Reset_Stats

; =============================================================================
;                            DATA
; =============================================================================
.data

; State shadow cache (256 entries max)
ALIGN 64
SwarmV29_State_Cache STRUCT
    DepthTest       DWORD ?
    DepthMask       DWORD ?
    DepthFunc       DWORD ?
    CullFace        DWORD ?
    CullFaceMode    DWORD ?
    BlendEnabled    DWORD ?
    BlendSrc        DWORD ?
    BlendDst        DWORD ?
    ScissorEnabled  DWORD ?
    ScissorX        DWORD ?
    ScissorY        DWORD ?
    ScissorW        DWORD ?
    ScissorH        DWORD ?
    ViewportX       DWORD ?
    ViewportY       DWORD ?
    ViewportW       DWORD ?
    ViewportH        DWORD ?
    DirtyFlags      QWORD ?
SwarmV29_State_Cache ENDS

; Global state cache
ALIGN 64
g_StateCache     SwarmV29_State_Cache <>
g_StateInitialized DWORD 0

; Statistics
ALIGN 64
g_TotalStateRequests  QWORD 0
g_DriverCallsIssued   QWORD 0
g_SkippedStateChanges QWORD 0
g_CacheHitRate        QWORD 0

; Dirty flag bits
DIRTY_DEPTH_TEST      EQU 00000001h
DIRTY_DEPTH_MASK      EQU 00000002h
DIRTY_DEPTH_FUNC      EQU 00000004h
DIRTY_CULL_FACE       EQU 00000008h
DIRTY_CULL_MODE       EQU 00000010h
DIRTY_BLEND_ENABLED   EQU 00000020h
DIRTY_BLEND_SRC       EQU 00000040h
DIRTY_BLEND_DST       EQU 00000080h
DIRTY_SCISSOR_ENABLED EQU 00000100h
DIRTY_SCISSOR_RECT    EQU 00000200h
DIRTY_VIEWPORT        EQU 00000400h

; =============================================================================
;                            CODE
; =============================================================================
.code

; =============================================================================
; SwarmV29_Init_State_Cache
; Initialize the state shadow cache
;
; Returns: EAX = 0 on success, -1 on failure
; =============================================================================
SwarmV29_Init_State_Cache PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Check if already initialized
    mov eax, g_StateInitialized
    test eax, eax
    jnz @@already_init
    
    ; Clear state cache
    lea rdi, g_StateCache
    xor eax, eax
    mov ecx, SIZEOF SwarmV29_State_Cache
    rep stosb
    
    ; Set default values
    lea rdi, g_StateCache
    mov DWORD PTR [rdi + SwarmV29_State_Cache.DepthTest], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.DepthMask], 1
    mov DWORD PTR [rdi + SwarmV29_State_Cache.DepthFunc], 515h  ; GL_LEQUAL
    mov DWORD PTR [rdi + SwarmV29_State_Cache.CullFace], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.CullFaceMode], 405h  ; GL_BACK
    mov DWORD PTR [rdi + SwarmV29_State_Cache.BlendEnabled], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.BlendSrc], 1  ; GL_ONE
    mov DWORD PTR [rdi + SwarmV29_State_Cache.BlendDst], 0  ; GL_ZERO
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ScissorEnabled], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ScissorX], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ScissorY], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ScissorW], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ScissorH], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ViewportX], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ViewportY], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ViewportW], 0
    mov DWORD PTR [rdi + SwarmV29_State_Cache.ViewportH], 0
    mov QWORD PTR [rdi + SwarmV29_State_Cache.DirtyFlags], 0
    
    ; Mark initialized
    mov g_StateInitialized, 1
    
    ; Clear stats
    mov g_TotalStateRequests, 0
    mov g_DriverCallsIssued, 0
    mov g_SkippedStateChanges, 0
    mov g_CacheHitRate, 0
    
    xor eax, eax
    jmp @@done
    
@@already_init:
    xor eax, eax
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Init_State_Cache ENDP

; =============================================================================
; SwarmV29_Shadow_State
; Compare requested state against shadow cache, update dirty flags if changed
;
; RCX = state_type (0=depth, 1=cull, 2=blend, 3=scissor, 4=viewport)
; RDX = new_value
; R8  = new_value2 (for multi-value states)
; R9  = new_value3 (for multi-value states)
;
; Returns: EAX = 1 if state changed (dirty), 0 if unchanged (cache hit)
; =============================================================================
SwarmV29_Shadow_State PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Increment total requests
    SWARMV29_ATOMIC_INC g_TotalStateRequests
    
    lea rdi, g_StateCache
    
    ; Dispatch based on state_type
    cmp ecx, 0
    je @@depth_test
    cmp ecx, 1
    je @@cull_face
    cmp ecx, 2
    je @@blend
    cmp ecx, 3
    je @@scissor
    cmp ecx, 4
    je @@viewport
    jmp @@invalid
    
@@depth_test:
    ; Compare depth test state
    mov eax, [rdi + SwarmV29_State_Cache.DepthTest]
    cmp eax, edx
    je @@cache_hit
    
    ; State changed - update cache
    mov [rdi + SwarmV29_State_Cache.DepthTest], edx
    or QWORD PTR [rdi + SwarmV29_State_Cache.DirtyFlags], DIRTY_DEPTH_TEST
    SWARMV29_ATOMIC_INC g_DriverCallsIssued
    mov eax, 1
    jmp @@done
    
@@cull_face:
    ; Compare cull face state
    mov eax, [rdi + SwarmV29_State_Cache.CullFace]
    cmp eax, edx
    jne @@cull_changed
    mov eax, [rdi + SwarmV29_State_Cache.CullFaceMode]
    cmp eax, r8d
    je @@cache_hit
    
@@cull_changed:
    mov [rdi + SwarmV29_State_Cache.CullFace], edx
    mov [rdi + SwarmV29_State_Cache.CullFaceMode], r8d
    or QWORD PTR [rdi + SwarmV29_State_Cache.DirtyFlags], DIRTY_CULL_FACE OR DIRTY_CULL_MODE
    SWARMV29_ATOMIC_INC g_DriverCallsIssued
    mov eax, 1
    jmp @@done
    
@@blend:
    ; Compare blend state
    mov eax, [rdi + SwarmV29_State_Cache.BlendEnabled]
    cmp eax, edx
    jne @@blend_changed
    mov eax, [rdi + SwarmV29_State_Cache.BlendSrc]
    cmp eax, r8d
    jne @@blend_changed
    mov eax, [rdi + SwarmV29_State_Cache.BlendDst]
    cmp eax, r9d
    je @@cache_hit
    
@@blend_changed:
    mov [rdi + SwarmV29_State_Cache.BlendEnabled], edx
    mov [rdi + SwarmV29_State_Cache.BlendSrc], r8d
    mov [rdi + SwarmV29_State_Cache.BlendDst], r9d
    or QWORD PTR [rdi + SwarmV29_State_Cache.DirtyFlags], DIRTY_BLEND_ENABLED OR DIRTY_BLEND_SRC OR DIRTY_BLEND_DST
    SWARMV29_ATOMIC_INC g_DriverCallsIssued
    mov eax, 1
    jmp @@done
    
@@scissor:
    ; Compare scissor state
    mov eax, [rdi + SwarmV29_State_Cache.ScissorEnabled]
    cmp eax, edx
    jne @@scissor_changed
    mov eax, [rdi + SwarmV29_State_Cache.ScissorX]
    cmp eax, r8d
    jne @@scissor_changed
    mov eax, [rdi + SwarmV29_State_Cache.ScissorY]
    cmp eax, r9d
    jne @@scissor_changed
    ; Check width/height from stack
    mov eax, [rsp + 40 + 8]  ; 5th parameter
    cmp eax, [rdi + SwarmV29_State_Cache.ScissorW]
    jne @@scissor_changed
    mov eax, [rsp + 40 + 16]  ; 6th parameter
    cmp eax, [rdi + SwarmV29_State_Cache.ScissorH]
    je @@cache_hit
    
@@scissor_changed:
    mov [rdi + SwarmV29_State_Cache.ScissorEnabled], edx
    mov [rdi + SwarmV29_State_Cache.ScissorX], r8d
    mov [rdi + SwarmV29_State_Cache.ScissorY], r9d
    mov eax, [rsp + 40 + 8]
    mov [rdi + SwarmV29_State_Cache.ScissorW], eax
    mov eax, [rsp + 40 + 16]
    mov [rdi + SwarmV29_State_Cache.ScissorH], eax
    or QWORD PTR [rdi + SwarmV29_State_Cache.DirtyFlags], DIRTY_SCISSOR_ENABLED OR DIRTY_SCISSOR_RECT
    SWARMV29_ATOMIC_INC g_DriverCallsIssued
    mov eax, 1
    jmp @@done
    
@@viewport:
    ; Compare viewport state
    mov eax, [rdi + SwarmV29_State_Cache.ViewportX]
    cmp eax, edx
    jne @@viewport_changed
    mov eax, [rdi + SwarmV29_State_Cache.ViewportY]
    cmp eax, r8d
    jne @@viewport_changed
    mov eax, [rdi + SwarmV29_State_Cache.ViewportW]
    cmp eax, r9d
    jne @@viewport_changed
    mov eax, [rsp + 40 + 8]
    cmp eax, [rdi + SwarmV29_State_Cache.ViewportH]
    je @@cache_hit
    
@@viewport_changed:
    mov [rdi + SwarmV29_State_Cache.ViewportX], edx
    mov [rdi + SwarmV29_State_Cache.ViewportY], r8d
    mov [rdi + SwarmV29_State_Cache.ViewportW], r9d
    mov eax, [rsp + 40 + 8]
    mov [rdi + SwarmV29_State_Cache.ViewportH], eax
    or QWORD PTR [rdi + SwarmV29_State_Cache.DirtyFlags], DIRTY_VIEWPORT
    SWARMV29_ATOMIC_INC g_DriverCallsIssued
    mov eax, 1
    jmp @@done
    
@@cache_hit:
    ; State unchanged - skip driver call
    SWARMV29_ATOMIC_INC g_SkippedStateChanges
    xor eax, eax
    jmp @@done
    
@@invalid:
    ; Invalid state type
    mov eax, -1
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Shadow_State ENDP

; =============================================================================
; SwarmV29_Get_Renderer_Stats
; Get performance statistics
;
; RCX = pointer to stats array (4 QWORDs)
; =============================================================================
SwarmV29_Get_Renderer_Stats PROC FRAME
    SWARMV29_ABI_FRAME
    
    ; Copy stats to output array
    mov rax, g_TotalStateRequests
    mov [rcx + 0], rax
    mov rax, g_DriverCallsIssued
    mov [rcx + 8], rax
    mov rax, g_SkippedStateChanges
    mov [rcx + 16], rax
    
    ; Calculate cache hit rate
    mov rax, g_TotalStateRequests
    test rax, rax
    jz @@zero_requests
    
    mov rbx, g_SkippedStateChanges
    imul rbx, 100  ; Percentage
    xor rdx, rdx
    div rax  ; (skipped * 100) / total
    mov [rcx + 24], rax
    jmp @@done
    
@@zero_requests:
    mov QWORD PTR [rcx + 24], 0
    
@@done:
    SWARMV29_ABI_EPILOG
SwarmV29_Get_Renderer_Stats ENDP

; =============================================================================
; SwarmV29_Reset_Stats
; Reset performance counters
; =============================================================================
SwarmV29_Reset_Stats PROC FRAME
    SWARMV29_ABI_FRAME
    
    mov g_TotalStateRequests, 0
    mov g_DriverCallsIssued, 0
    mov g_SkippedStateChanges, 0
    mov g_CacheHitRate, 0
    
    SWARMV29_ABI_EPILOG
SwarmV29_Reset_Stats ENDP

END