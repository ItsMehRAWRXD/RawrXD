; ==============================================================================
; SwarmV29_Modern_GL_State.asm
; PHASE-29f: Modern OpenGL State Shadowing (AZDO Architecture)
; Target: Eliminate redundant GPU state changes via dirty-state tracking
; ------------------------------------------------------------------------------
; Architecture:
;   - Compares requested state against shadow cache before driver calls
;   - Only issues glEnable/glDisable when state actually changes
;   - Tracks metrics for performance analysis
;   - Integrates with SwarmV29_Renderer_State_Cache for backend-agnostic dispatch
;
; ABI: Windows x64 (RCX, RDX, R8, R9)
; Dependencies: SwarmV29_Macros.inc, SwarmV29_Renderer_State_Cache.asm
; ==============================================================================

INCLUDE SwarmV29_Macros.inc

; ==============================================================================
; External OpenGL Function Pointers (Resolved via wglGetProcAddress)
; These are populated by SwarmV29_API_Bridge at runtime
; ==============================================================================
EXTERN p_glEnable : QWORD
EXTERN p_glDisable : QWORD
EXTERN p_glCullFace : QWORD
EXTERN p_glBlendFunc : QWORD
EXTERN p_glDepthFunc : QWORD
EXTERN p_glViewport : QWORD
EXTERN p_glScissor : QWORD

; ==============================================================================
; OpenGL State Tokens (Standard GL Enums)
; ==============================================================================
GL_DEPTH_TEST           EQU 0B71h
GL_CULL_FACE            EQU 0B44h
GL_BLEND                EQU 0BE2h
GL_SCISSOR_TEST         EQU 0C11h
GL_STENCIL_TEST         EQU 0B90h
GL_DITHER               EQU 0BD0h

; GL Culling Constants
GL_FRONT                EQU 0404h
GL_BACK                 EQU 0405h
GL_FRONT_AND_BACK       EQU 0408h

; GL Depth Functions
GL_NEVER                EQU 0200h
GL_LESS                 EQU 0201h
GL_EQUAL                EQU 0202h
GL_LEQUAL               EQU 0203h
GL_GREATER              EQU 0204h
GL_NOTEQUAL             EQU 0205h
GL_GEQUAL               EQU 0206h
GL_ALWAYS               EQU 0207h

; GL Blend Functions
GL_ZERO                 EQU 0
GL_ONE                  EQU 1
GL_SRC_ALPHA            EQU 0302h
GL_ONE_MINUS_SRC_ALPHA  EQU 0303h
GL_DST_ALPHA            EQU 0304h
GL_ONE_MINUS_DST_ALPHA  EQU 0305h

; ==============================================================================
; Profiling and Optimization Metrics
; ==============================================================================
.data
    ALIGN 64
    g_TotalStateRequests    QWORD 0     ; Total state change requests
    g_DriverCallsIssued    QWORD 0     ; Actual driver calls made
    g_SkippedStateChanges  QWORD 0     ; Bypassed driver calls (cache hits)
    g_CacheHitRate          QWORD 0     ; Percentage of cache hits
    g_LastStateChangeTime   QWORD 0     ; QPC timestamp of last change

    ; Depth function mapping table
    ALIGN 16
    g_DepthFuncTable LABEL DWORD
    DWORD GL_NEVER          ; 0
    DWORD GL_LESS           ; 1
    DWORD GL_EQUAL          ; 2
    DWORD GL_LEQUAL         ; 3
    DWORD GL_GREATER        ; 4
    DWORD GL_NOTEQUAL       ; 5
    DWORD GL_GEQUAL         ; 6
    DWORD GL_ALWAYS         ; 7

.code

; ==============================================================================
; Modern_GL_SetState
; Core state-shadowing function for OpenGL backend
; Input: RCX = Pointer to Renderer_State_Cache_Struct with desired state
; Output: RAX = 0 on success, error code on failure
; ==============================================================================
ALIGN 16
Modern_GL_SetState PROC
    SWARM_PROC_START Modern_GL_SetState, <rbx, rsi, rdi>
    
    ; 1. Verification Barriers
    SWARM_CHECK_NULL rcx, .Error_Null_Pointer
    SWARM_CHECK_ALIGN rcx, .Error_Misaligned
    
    ; Save pointers
    mov rsi, rcx                        ; rsi = Inbound target state
    lea rdi, [g_CurrentState]           ; rdi = Active shadow state cache
    
    ; Increment total requests
    inc qword ptr [g_TotalStateRequests]
    
    ; ========================================================================
    ; 2. Pipeline Stage: Depth Testing
    ; ========================================================================
    mov al, byte ptr [rsi + 0]          ; Offset 0: DepthTestEnabled
    cmp al, byte ptr [rdi + 0]
    je .Evaluate_Culling                 ; Cache hit: bypass driver
    
    ; State changed - update cache
    mov byte ptr [rdi + 0], al
    inc qword ptr [g_DriverCallsIssued]
    
    test al, al
    jz .Disable_Depth
    
    ; Enable depth test
    mov rcx, GL_DEPTH_TEST
    cmp qword ptr [p_glEnable], 0
    je .Error_Null_Pointer
    call [p_glEnable]
    
    ; Set depth function if specified
    mov al, byte ptr [rsi + 1]          ; Offset 1: DepthFunc
    cmp al, byte ptr [rdi + 1]
    je .Evaluate_Culling
    
    mov byte ptr [rdi + 1], al
    inc qword ptr [g_DriverCallsIssued]
    
    ; Map depth function index to GL enum
    and rax, 0FFh
    lea rbx, [g_DepthFuncTable]
    mov ecx, [rbx + rax * 4]
    
    mov rcx, ecx
    cmp qword ptr [p_glDepthFunc], 0
    je .Error_Null_Pointer
    call [p_glDepthFunc]
    jmp .Evaluate_Culling
    
.Disable_Depth:
    mov rcx, GL_DEPTH_TEST
    cmp qword ptr [p_glDisable], 0
    je .Error_Null_Pointer
    call [p_glDisable]
    
    ; ========================================================================
    ; 3. Pipeline Stage: Face Culling
    ; ========================================================================
.Evaluate_Culling:
    mov al, byte ptr [rsi + 2]          ; Offset 2: CullMode
    cmp al, byte ptr [rdi + 2]
    je .Evaluate_Blending
    
    mov byte ptr [rdi + 2], al
    inc qword ptr [g_DriverCallsIssued]
    
    test al, al
    jz .Disable_Culling
    
    ; Enable culling
    mov rcx, GL_CULL_FACE
    cmp qword ptr [p_glEnable], 0
    je .Error_Null_Pointer
    call [p_glEnable]
    
    ; Set cull face
    cmp al, 1                            ; 1 = Front, 2 = Back
    je .Cull_Front
    mov rcx, GL_BACK
    jmp .Apply_Cull
.Cull_Front:
    mov rcx, GL_FRONT
.Apply_Cull:
    cmp qword ptr [p_glCullFace], 0
    je .Error_Null_Pointer
    call [p_glCullFace]
    jmp .Evaluate_Blending
    
.Disable_Culling:
    mov rcx, GL_CULL_FACE
    cmp qword ptr [p_glDisable], 0
    je .Error_Null_Pointer
    call [p_glDisable]
    
    ; ========================================================================
    ; 4. Pipeline Stage: Alpha Blending
    ; ========================================================================
.Evaluate_Blending:
    mov al, byte ptr [rsi + 3]          ; Offset 3: BlendMode
    cmp al, byte ptr [rdi + 3]
    je .Evaluate_Scissor
    
    mov byte ptr [rdi + 3], al
    inc qword ptr [g_DriverCallsIssued]
    
    test al, al
    jz .Disable_Blending
    
    ; Enable blending
    mov rcx, GL_BLEND
    cmp qword ptr [p_glEnable], 0
    je .Error_Null_Pointer
    call [p_glEnable]
    
    ; Set blend function (standard alpha blending)
    ; glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA)
    mov rcx, GL_SRC_ALPHA
    mov rdx, GL_ONE_MINUS_SRC_ALPHA
    cmp qword ptr [p_glBlendFunc], 0
    je .Error_Null_Pointer
    call [p_glBlendFunc]
    jmp .Evaluate_Scissor
    
.Disable_Blending:
    mov rcx, GL_BLEND
    cmp qword ptr [p_glDisable], 0
    je .Error_Null_Pointer
    call [p_glDisable]
    
    ; ========================================================================
    ; 5. Pipeline Stage: Scissor Test
    ; ========================================================================
.Evaluate_Scissor:
    mov al, byte ptr [rsi + 4]          ; Offset 4: ScissorEnabled
    cmp al, byte ptr [rdi + 4]
    je .Evaluate_Viewport
    
    mov byte ptr [rdi + 4], al
    inc qword ptr [g_DriverCallsIssued]
    
    test al, al
    jz .Disable_Scissor
    
    ; Enable scissor test
    mov rcx, GL_SCISSOR_TEST
    cmp qword ptr [p_glEnable], 0
    je .Error_Null_Pointer
    call [p_glEnable]
    jmp .Evaluate_Viewport
    
.Disable_Scissor:
    mov rcx, GL_SCISSOR_TEST
    cmp qword ptr [p_glDisable], 0
    je .Error_Null_Pointer
    call [p_glDisable]
    
    ; ========================================================================
    ; 6. Pipeline Stage: Viewport
    ; ========================================================================
.Evaluate_Viewport:
    ; Check viewport dimensions (DWORD pair)
    mov eax, dword ptr [rsi + 8]        ; Offset 8: ViewportWidth
    cmp eax, dword ptr [rdi + 8]
    jne .Viewport_Changed
    
    mov eax, dword ptr [rsi + 12]       ; Offset 12: ViewportHeight
    cmp eax, dword ptr [rdi + 12]
    je .Collate_Metrics
    
.Viewport_Changed:
    ; Update cache
    mov eax, dword ptr [rsi + 8]
    mov dword ptr [rdi + 8], eax
    mov eax, dword ptr [rsi + 12]
    mov dword ptr [rdi + 12], eax
    inc qword ptr [g_DriverCallsIssued]
    
    ; glViewport(0, 0, width, height)
    xor rcx, rcx                        ; x = 0
    xor rdx, rdx                        ; y = 0
    mov r8d, dword ptr [rsi + 8]        ; width
    mov r9d, dword ptr [rsi + 12]       ; height
    cmp qword ptr [p_glViewport], 0
    je .Error_Null_Pointer
    call [p_glViewport]
    
    ; ========================================================================
    ; 7. Metrics Collation
    ; ========================================================================
.Collate_Metrics:
    ; Calculate skipped changes
    mov rax, qword ptr [g_TotalStateRequests]
    sub rax, qword ptr [g_DriverCallsIssued]
    mov qword ptr [g_SkippedStateChanges], rax
    
    ; Calculate cache hit rate (percentage)
    mov rcx, 100
    mul rcx                              ; rax = skipped * 100
    mov rcx, qword ptr [g_TotalStateRequests]
    test rcx, rcx
    jz .Divide_By_Zero
    div rcx                              ; rax = (skipped * 100) / total
    mov qword ptr [g_CacheHitRate], rax
    
    ; Success
    xor rax, rax
    jmp .Epilogue
    
.Divide_By_Zero:
    mov qword ptr [g_CacheHitRate], 0
    xor rax, rax
    jmp .Epilogue
    
.Error_Null_Pointer:
    mov rax, ERR_NULL_POINTER
    int 3
    jmp .Epilogue
    
.Error_Misaligned:
    mov rax, ERR_MISALIGNED
    int 3
    jmp .Epilogue
    
.Epilogue:
    SWARM_PROC_END
Modern_GL_SetState ENDP

; ==============================================================================
; Modern_GL_GetStateStats
; Returns performance caching telemetry
; Output: RAX = Total State Requests
;         RCX = Skipped Changes (Bypassed Driver Calls)
;         RDX = Cache Hit Rate (Percentage)
;         R8  = Driver Calls Issued
; ==============================================================================
ALIGN 16
Modern_GL_GetStateStats PROC
    mov rax, qword ptr [g_TotalStateRequests]
    mov rcx, qword ptr [g_SkippedStateChanges]
    mov rdx, qword ptr [g_CacheHitRate]
    mov r8, qword ptr [g_DriverCallsIssued]
    ret
Modern_GL_GetStateStats ENDP

; ==============================================================================
; Modern_GL_ResetStats
; Resets all performance counters
; ==============================================================================
ALIGN 16
Modern_GL_ResetStats PROC
    mov qword ptr [g_TotalStateRequests], 0
    mov qword ptr [g_DriverCallsIssued], 0
    mov qword ptr [g_SkippedStateChanges], 0
    mov qword ptr [g_CacheHitRate], 0
    mov qword ptr [g_LastStateChangeTime], 0
    ret
Modern_GL_ResetStats ENDP

; ==============================================================================
; Modern_GL_FlushState
; Forces all cached state to be re-issued to driver
; Use after backend switch or context loss
; ==============================================================================
ALIGN 16
Modern_GL_FlushState PROC
    SWARM_PROC_START Modern_GL_FlushState, <rbx>
    
    ; Invalidate all cached state
    lea rbx, [g_CurrentState]
    
    ; Set all bytes to 0xFF (invalid state)
    mov qword ptr [rbx + 0], 0FFFFFFFFFFFFFFFFh
    mov qword ptr [rbx + 8], 0FFFFFFFFFFFFFFFFh
    mov qword ptr [rbx + 16], 0FFFFFFFFFFFFFFFFh
    mov qword ptr [rbx + 24], 0FFFFFFFFFFFFFFFFh
    
    ; Reset counters
    call Modern_GL_ResetStats
    
    xor rax, rax
    
    SWARM_PROC_END
Modern_GL_FlushState ENDP

; ==============================================================================
; Modern_GL_BindShaderProgram
; Binds shader program with dirty tracking
; Input: RCX = Shader program ID
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Modern_GL_BindShaderProgram PROC
    SWARM_PROC_START Modern_GL_BindShaderProgram, <>
    
    ; Check against cached state
    mov rax, qword ptr [g_CurrentState.BoundShaderProgram]
    cmp rax, rcx
    je .Skip_Shader
    
    ; State changed
    mov qword ptr [g_CurrentState.BoundShaderProgram], rcx
    inc qword ptr [g_DriverCallsIssued]
    
    ; TODO: Call glUseProgram via function pointer
    ; mov rcx, rcx
    ; call [p_glUseProgram]
    
.Skip_Shader:
    inc qword ptr [g_SkippedStateChanges]
    xor rax, rax
    
    SWARM_PROC_END
Modern_GL_BindShaderProgram ENDP

; ==============================================================================
; Modern_GL_BindVertexBuffer
; Binds vertex buffer with dirty tracking
; Input: RCX = Buffer ID
; Output: RAX = 0 on success
; ==============================================================================
ALIGN 16
Modern_GL_BindVertexBuffer PROC
    SWARM_PROC_START Modern_GL_BindVertexBuffer, <>
    
    mov rax, qword ptr [g_CurrentState.BoundVertexBuffer]
    cmp rax, rcx
    je .Skip_VBO
    
    mov qword ptr [g_CurrentState.BoundVertexBuffer], rcx
    inc qword ptr [g_DriverCallsIssued]
    
    ; TODO: Call glBindBuffer via function pointer
    
.Skip_VBO:
    inc qword ptr [g_SkippedStateChanges]
    xor rax, rax
    
    SWARM_PROC_END
Modern_GL_BindVertexBuffer ENDP

END