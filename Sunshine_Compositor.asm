; ==============================================================================
; Sunshine_Compositor.asm ? WGL Lockstep Renderer with Deterministic Frame Pacing
; ==============================================================================
; Bare-metal OpenGL 4.6 via WGL. Zero middleman. Dynamic function resolution.
; Fixed: WGL extension bootstrap, robust GL resolution, event-driven sync,
;        correct tape layout (192 bytes/entry), inline telemetry.
; ==============================================================================

option casemap:none

; ==============================================================================
; External APIs
; ==============================================================================
EXTERN LoadLibraryA          : PROC
EXTERN GetProcAddress        : PROC
EXTERN GetDC                 : PROC
EXTERN ReleaseDC             : PROC
EXTERN ChoosePixelFormat     : PROC
EXTERN SetPixelFormat        : PROC
EXTERN SwapBuffers           : PROC
EXTERN SetEvent              : PROC
EXTERN WaitForSingleObject   : PROC
EXTERN CreateEventA          : PROC
EXTERN CloseHandle           : PROC
EXTERN GhostBuffer_WriteEvent : PROC

; ==============================================================================
; External Data
; ==============================================================================
EXTERN g_LockstepTape        : BYTE
EXTERN g_hEvent_SimulationTick : QWORD
EXTERN g_hEvent_FrameComplete  : QWORD

; ==============================================================================
; Data Section
; ==============================================================================
.data
ALIGN 16

; WGL function pointers
wglCreateContext          dq 0
wglMakeCurrent            dq 0
wglDeleteContext          dq 0
wglSwapIntervalEXT        dq 0
wglGetProcAddress         dq 0

; OpenGL 4.6 core function pointers
glClearColor              dq 0
glClear                   dq 0
glViewport                dq 0
glGenBuffers              dq 0
glBindBuffer              dq 0
glBufferData              dq 0
glBufferSubData           dq 0
glMapBufferRange          dq 0
glUnmapBuffer             dq 0
glCreateShader            dq 0
glShaderSource            dq 0
glCompileShader           dq 0
glCreateProgram           dq 0
glAttachShader            dq 0
glLinkProgram             dq 0
glUseProgram              dq 0
glGenVertexArrays         dq 0
glBindVertexArray         dq 0
glEnableVertexAttribArray dq 0
glVertexAttribPointer     dq 0
glDrawArrays              dq 0
glUniformMatrix4fv        dq 0
glGetUniformLocation      dq 0
glDeleteShader            dq 0

; opengl32.dll module handle (for fallback GetProcAddress)
hOpenGL32                 dq 0

; Sunshine context
SUNSHINE_CONTEXT STRUCT
    hDC           dq ?
    hRC           dq ?
    hwnd          dq ?
    wndWidth      dd ?
    wndHeight     dd ?
    currentTick   dq ?
    targetTick    dq ?
    is_vsync      db ?
    pad           db 7 dup(?)
    pbo_handle    dd ?
    vao_handle    dd ?
    shader_prog   dd ?
    view_loc      dd ?
    proj_loc      dd ?
SUNSHINE_CONTEXT ENDS

ALIGN 16
g_SunshineCtx   SUNSHINE_CONTEXT <>

; Strings
szOpengl32              db "opengl32.dll", 0
sz_wglCreateContext     db "wglCreateContext", 0
sz_wglMakeCurrent       db "wglMakeCurrent", 0
sz_wglDeleteContext     db "wglDeleteContext", 0
sz_wglSwapIntervalEXT   db "wglSwapIntervalEXT", 0
sz_wglGetProcAddress    db "wglGetProcAddress", 0

sz_glClearColor         db "glClearColor", 0
sz_glClear              db "glClear", 0
sz_glViewport           db "glViewport", 0
sz_glGenBuffers         db "glGenBuffers", 0
sz_glBindBuffer         db "glBindBuffer", 0
sz_glBufferData         db "glBufferData", 0
sz_glBufferSubData      db "glBufferSubData", 0
sz_glMapBufferRange     db "glMapBufferRange", 0
sz_glUnmapBuffer        db "glUnmapBuffer", 0
sz_glCreateShader       db "glCreateShader", 0
sz_glShaderSource       db "glShaderSource", 0
sz_glCompileShader      db "glCompileShader", 0
sz_glCreateProgram      db "glCreateProgram", 0
sz_glAttachShader       db "glAttachShader", 0
sz_glLinkProgram        db "glLinkProgram", 0
sz_glUseProgram         db "glUseProgram", 0
sz_glGenVertexArrays    db "glGenVertexArrays", 0
sz_glBindVertexArray    db "glBindVertexArray", 0
sz_glEnableVertexAttribArray db "glEnableVertexAttribArray", 0
sz_glVertexAttribPointer db "glVertexAttribPointer", 0
sz_glDrawArrays         db "glDrawArrays", 0
sz_glUniformMatrix4fv  db "glUniformMatrix4fv", 0
sz_glGetUniformLocation db "glGetUniformLocation", 0
sz_glDeleteShader       db "glDeleteShader", 0

; Shader source (minimal passthrough)
szVertexShader:
    db "#version 460 core", 0Ah
    db "layout(location=0) in vec3 aPos;", 0Ah
    db "uniform mat4 view; uniform mat4 proj;", 0Ah
    db "void main(){gl_Position=proj*view*vec4(aPos,1.0);}", 0
szFragmentShader:
    db "#version 460 core", 0Ah
    db "out vec4 FragColor;", 0Ah
    db "void main(){FragColor=vec4(0.0,1.0,0.5,1.0);}", 0

szView                  db "view", 0
szProj                  db "proj", 0

fOne                    dd 1.0
ClearColor              dd 0.05, 0.05, 0.05, 1.0

; Event handles (created by compositor, shared with sim)
g_hCompositorFrameEvent dq 0

; ==============================================================================
; GHOST_WRITE Macro ? Zero-overhead telemetry inline
; ==============================================================================
GHOST_WRITE MACRO event_type:REQ, payload_reg:REQ
    mov cl, event_type
    mov rdx, payload_reg
    call GhostBuffer_WriteEvent
ENDM

; ==============================================================================
; Code Section
; ==============================================================================
.code

; ==============================================================================
; ResolveGLFunc ? Robust GL function resolution
; Tries wglGetProcAddress first, falls back to GetProcAddress(opengl32, name)
; RCX = function name string
; Returns: RAX = function pointer (0 if not found)
; ==============================================================================
ResolveGLFunc PROC
    push rbx
    push rsi
    sub rsp, 28h

    mov rbx, rcx                    ; RBX = name

    ; Try wglGetProcAddress first
    mov rax, [wglGetProcAddress]
    test rax, rax
    jz @@fallback
    mov rcx, rbx
    call rax
    test rax, rax
    jz @@fallback
    cmp rax, 1
    je @@fallback
    cmp rax, 2
    je @@fallback
    cmp rax, 3
    je @@fallback
    cmp rax, 0FFFFFFFFFFFFFFFFh
    je @@fallback
    jmp @@done

@@fallback:
    ; Fallback to GetProcAddress(opengl32.dll, name)
    mov rcx, [hOpenGL32]
    test rcx, rcx
    jz @@fail
    mov rdx, rbx
    call GetProcAddress
    jmp @@done

@@fail:
    xor eax, eax

@@done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
ResolveGLFunc ENDP

; ==============================================================================
; Sunshine_ResolveWGL ? Two-phase bootstrap:
;   Phase 1: Load opengl32.dll, resolve basic WGL via GetProcAddress
;   Phase 2: Create dummy context, make current, resolve GL via wglGetProcAddress
; Returns: RAX = 1 (success) or 0 (failure)
; ==============================================================================
PUBLIC Sunshine_ResolveWGL
Sunshine_ResolveWGL PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 168                    ; Shadow + 40-byte PFD + padding

    ; ?? PHASE 1: Load opengl32.dll ??
    lea rcx, [szOpengl32]
    call LoadLibraryA
    test rax, rax
    jz resolve_fail
    mov [hOpenGL32], rax
    mov rbx, rax                    ; RBX = hOpenGL32

    ; Resolve basic WGL functions via GetProcAddress
    mov rcx, rbx
    lea rdx, [sz_wglCreateContext]
    call GetProcAddress
    mov [wglCreateContext], rax

    mov rcx, rbx
    lea rdx, [sz_wglMakeCurrent]
    call GetProcAddress
    mov [wglMakeCurrent], rax

    mov rcx, rbx
    lea rdx, [sz_wglDeleteContext]
    call GetProcAddress
    mov [wglDeleteContext], rax

    mov rcx, rbx
    lea rdx, [sz_wglGetProcAddress]
    call GetProcAddress
    mov [wglGetProcAddress], rax

    ; ?? PHASE 2: Create dummy window/context to resolve extensions ??
    ; We need a DC with a pixel format to create a GL context
    ; Use the existing hwnd from g_SunshineCtx if available, otherwise fail
    mov r12, [g_SunshineCtx.hwnd]
    test r12, r12
    jz resolve_fail

    mov rcx, r12
    call GetDC
    test rax, rax
    jz resolve_fail
    mov r13, rax                    ; R13 = dummy DC

    ; Setup minimal PFD (40 bytes)
    mov DWORD PTR [rsp + 32], 40
    mov DWORD PTR [rsp + 36], 1
    mov DWORD PTR [rsp + 40], 25h
    mov BYTE PTR [rsp + 44], 0
    mov BYTE PTR [rsp + 45], 32
    mov BYTE PTR [rsp + 50], 24
    mov BYTE PTR [rsp + 51], 8

    lea r8, [rsp + 32]
    xor edx, edx
    mov rcx, r13
    call ChoosePixelFormat
    test rax, rax
    jz resolve_cleanup_dc

    mov rdx, rax
    mov rcx, r13
    lea r8, [rsp + 32]
    call SetPixelFormat
    test eax, eax
    jz resolve_cleanup_dc

    ; Create temporary context
    mov rcx, r13
    call [wglCreateContext]
    test rax, rax
    jz resolve_cleanup_dc
    mov r14, rax                    ; R14 = temp RC

    ; Make temporary context current
    mov rdx, r14
    mov rcx, r13
    call [wglMakeCurrent]

    ; Now resolve wglSwapIntervalEXT via wglGetProcAddress
    mov rcx, OFFSET sz_wglSwapIntervalEXT
    call [wglGetProcAddress]
    mov [wglSwapIntervalEXT], rax

    ; ?? PHASE 3: Resolve all GL 4.6 core functions ??
    lea rcx, [sz_glClearColor]
    call ResolveGLFunc
    mov [glClearColor], rax

    lea rcx, [sz_glClear]
    call ResolveGLFunc
    mov [glClear], rax

    lea rcx, [sz_glViewport]
    call ResolveGLFunc
    mov [glViewport], rax

    lea rcx, [sz_glGenBuffers]
    call ResolveGLFunc
    mov [glGenBuffers], rax

    lea rcx, [sz_glBindBuffer]
    call ResolveGLFunc
    mov [glBindBuffer], rax

    lea rcx, [sz_glBufferData]
    call ResolveGLFunc
    mov [glBufferData], rax

    lea rcx, [sz_glBufferSubData]
    call ResolveGLFunc
    mov [glBufferSubData], rax

    lea rcx, [sz_glMapBufferRange]
    call ResolveGLFunc
    mov [glMapBufferRange], rax

    lea rcx, [sz_glUnmapBuffer]
    call ResolveGLFunc
    mov [glUnmapBuffer], rax

    lea rcx, [sz_glCreateShader]
    call ResolveGLFunc
    mov [glCreateShader], rax

    lea rcx, [sz_glShaderSource]
    call ResolveGLFunc
    mov [glShaderSource], rax

    lea rcx, [sz_glCompileShader]
    call ResolveGLFunc
    mov [glCompileShader], rax

    lea rcx, [sz_glCreateProgram]
    call ResolveGLFunc
    mov [glCreateProgram], rax

    lea rcx, [sz_glAttachShader]
    call ResolveGLFunc
    mov [glAttachShader], rax

    lea rcx, [sz_glLinkProgram]
    call ResolveGLFunc
    mov [glLinkProgram], rax

    lea rcx, [sz_glUseProgram]
    call ResolveGLFunc
    mov [glUseProgram], rax

    lea rcx, [sz_glGenVertexArrays]
    call ResolveGLFunc
    mov [glGenVertexArrays], rax

    lea rcx, [sz_glBindVertexArray]
    call ResolveGLFunc
    mov [glBindVertexArray], rax

    lea rcx, [sz_glEnableVertexAttribArray]
    call ResolveGLFunc
    mov [glEnableVertexAttribArray], rax

    lea rcx, [sz_glVertexAttribPointer]
    call ResolveGLFunc
    mov [glVertexAttribPointer], rax

    lea rcx, [sz_glDrawArrays]
    call ResolveGLFunc
    mov [glDrawArrays], rax

    lea rcx, [sz_glUniformMatrix4fv]
    call ResolveGLFunc
    mov [glUniformMatrix4fv], rax

    lea rcx, [sz_glGetUniformLocation]
    call ResolveGLFunc
    mov [glGetUniformLocation], rax

    lea rcx, [sz_glDeleteShader]
    call ResolveGLFunc
    mov [glDeleteShader], rax

    ; ?? PHASE 4: Cleanup temporary context ??
    xor edx, edx
    xor ecx, ecx
    call [wglMakeCurrent]

    mov rcx, r14
    call [wglDeleteContext]

resolve_cleanup_dc:
    mov rcx, r12
    mov rdx, r13
    call ReleaseDC

    mov eax, 1
    jmp resolve_exit

resolve_fail:
    xor eax, eax

resolve_exit:
    add rsp, 168
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sunshine_ResolveWGL ENDP

; ==============================================================================
; Sunshine_Init ? Create WGL context, compile shaders, setup PBO/VAO
; RCX = HWND, RDX = width, R8 = height
; Returns: RAX = 1 on success
; ==============================================================================
PUBLIC Sunshine_Init
Sunshine_Init PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 168

    mov r12, rcx
    mov r13d, edx
    mov r14d, r8d

    ; Zero context
    lea rdi, g_SunshineCtx
    mov rcx, SIZEOF SUNSHINE_CONTEXT
    xor eax, eax
    rep stosb

    mov [g_SunshineCtx.hwnd], r12
    mov [g_SunshineCtx.wndWidth], r13d
    mov [g_SunshineCtx.wndHeight], r14d
    mov BYTE PTR [g_SunshineCtx.is_vsync], 1

    ; Resolve WGL/GL functions (two-phase bootstrap)
    call Sunshine_ResolveWGL
    test eax, eax
    jz init_fail

    ; Get DC
    mov rcx, r12
    call GetDC
    test rax, rax
    jz init_fail
    mov [g_SunshineCtx.hDC], rax
    mov rsi, rax

    ; Setup pixel format (40 bytes PFD on stack)
    mov DWORD PTR [rsp + 32], 40
    mov DWORD PTR [rsp + 36], 1
    mov DWORD PTR [rsp + 40], 25h
    mov BYTE PTR [rsp + 44], 0
    mov BYTE PTR [rsp + 45], 32
    mov BYTE PTR [rsp + 50], 24
    mov BYTE PTR [rsp + 51], 8

    lea r8, [rsp + 32]
    xor edx, edx
    mov rcx, rsi
    call ChoosePixelFormat
    test rax, rax
    jz init_fail

    mov rdx, rax
    mov rcx, rsi
    lea r8, [rsp + 32]
    call SetPixelFormat
    test eax, eax
    jz init_fail

    ; Create GL context
    mov rcx, rsi
    call [wglCreateContext]
    test rax, rax
    jz init_fail
    mov [g_SunshineCtx.hRC], rax

    ; Make current
    mov rdx, rax
    mov rcx, rsi
    call [wglMakeCurrent]

    ; Enable VSync (now that context is active, wglSwapIntervalEXT is valid)
    mov rax, [wglSwapIntervalEXT]
    test rax, rax
    jz @@skip_vsync
    mov ecx, 1
    call rax
@@skip_vsync:

    ; Compile shaders
    call Sunshine_CompileShaders
    test eax, eax
    jz init_fail

    ; Setup PBO
    mov rax, [glGenBuffers]
    test rax, rax
    jz @@skip_pbo
    lea rcx, [g_SunshineCtx.pbo_handle]
    mov edx, 1
    call rax

    mov rax, [glBindBuffer]
    test rax, rax
    jz @@skip_pbo
    mov edx, 88ECh
    mov ecx, [g_SunshineCtx.pbo_handle]
    call rax
@@skip_pbo:

    ; Setup VAO
    mov rax, [glGenVertexArrays]
    test rax, rax
    jz @@skip_vao
    lea rcx, [g_SunshineCtx.vao_handle]
    mov edx, 1
    call rax
@@skip_vao:

    ; Initial viewport
    mov rax, [glViewport]
    test rax, rax
    jz @@skip_viewport
    mov r8d, r14d
    mov edx, r13d
    xor ecx, ecx
    xor r9d, r9d
    call rax
@@skip_viewport:

    ; Clear color
    mov rax, [glClearColor]
    test rax, rax
    jz @@skip_clearcolor
    xorps xmm0, xmm0
    xorps xmm1, xmm1
    xorps xmm2, xmm2
    movss xmm3, [fOne]
    call rax
@@skip_clearcolor:

    ; Create frame complete event (auto-reset, initially signaled)
    xor ecx, ecx
    mov edx, 1              ; manual reset = TRUE
    mov r8d, 1              ; initial state = signaled
    xor r9d, r9d
    call CreateEventA
    mov [g_hCompositorFrameEvent], rax

    mov eax, 1
    jmp init_exit

init_fail:
    xor eax, eax

init_exit:
    add rsp, 168
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sunshine_Init ENDP

; ==============================================================================
; Sunshine_CompileShaders ? Compile vertex + fragment, link program
; Returns: RAX = 1 (success)
; ==============================================================================
Sunshine_CompileShaders PROC
    push rbx
    push rsi
    sub rsp, 40h

    ; Compile vertex shader
    mov rax, [glCreateShader]
    test rax, rax
    jz compile_fail
    mov ecx, 8B31h
    call rax
    mov ebx, eax

    lea rcx, [szVertexShader]
    mov [rsp + 32], rcx
    mov DWORD PTR [rsp + 40], 0
    mov edx, 1
    lea r8, [rsp + 32]
    xor r9d, r9d
    mov rcx, rbx
    mov rax, [glShaderSource]
    call rax

    mov ecx, ebx
    mov rax, [glCompileShader]
    call rax

    ; Compile fragment shader
    mov rax, [glCreateShader]
    mov ecx, 8B30h
    call rax
    mov esi, eax

    lea rcx, [szFragmentShader]
    mov [rsp + 32], rcx
    mov DWORD PTR [rsp + 40], 0
    mov edx, 1
    lea r8, [rsp + 32]
    xor r9d, r9d
    mov rcx, rsi
    mov rax, [glShaderSource]
    call rax

    mov ecx, esi
    mov rax, [glCompileShader]
    call rax

    ; Link program
    mov rax, [glCreateProgram]
    call rax
    mov [g_SunshineCtx.shader_prog], eax

    mov edx, ebx
    mov ecx, eax
    mov rax, [glAttachShader]
    call rax

    mov edx, esi
    mov ecx, [g_SunshineCtx.shader_prog]
    mov rax, [glAttachShader]
    call rax

    mov ecx, [g_SunshineCtx.shader_prog]
    mov rax, [glLinkProgram]
    call rax

    ; Get uniform locations
    lea rdx, [szView]
    mov ecx, [g_SunshineCtx.shader_prog]
    mov rax, [glGetUniformLocation]
    call rax
    mov [g_SunshineCtx.view_loc], eax

    lea rdx, [szProj]
    mov ecx, [g_SunshineCtx.shader_prog]
    mov rax, [glGetUniformLocation]
    call rax
    mov [g_SunshineCtx.proj_loc], eax

    ; Cleanup shaders
    mov ecx, ebx
    mov rax, [glDeleteShader]
    call rax
    mov ecx, esi
    mov rax, [glDeleteShader]
    call rax

    mov eax, 1
    jmp compile_exit

compile_fail:
    xor eax, eax

compile_exit:
    add rsp, 40h
    pop rsi
    pop rbx
    ret
Sunshine_CompileShaders ENDP

; ==============================================================================
; Sunshine_Present ? Lockstep frame render with event-driven sync
; RCX = targetTick
; Returns: RAX = tick rendered
; ==============================================================================
PUBLIC Sunshine_Present
Sunshine_Present PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 40h

    mov rbx, rcx                    ; RBX = targetTick

    ; ?? WAIT FOR SIMULATION TICK (event-driven) ??
    ; Wait on g_hEvent_SimulationTick, then verify tape
    mov rcx, [g_hEvent_SimulationTick]
    test rcx, rcx
    jz @@spin_fallback

    mov edx, 0FFFFFFFFh             ; INFINITE
    call WaitForSingleObject

    ; Verify tape entry is READY and tick matches
    ; TapeEntry size = 192 bytes, ready field at offset 168
    mov r12, rbx
    and r12, 255                    ; R12 = idx = tick & 255

    imul r13, r12, 192              ; R13 = offset
    lea rax, g_LockstepTape
    lea rsi, [rax + r13]            ; RSI = &entries[idx]

    ; Check ready == 2 (TAPE_READY)
    mov eax, [rsi + 168]
    cmp eax, 2
    jne @@desync

    ; Verify tick_id matches
    mov rax, [rsi + 0]              ; tick_id
    cmp rax, rbx
    jne @@desync

    ; Verify state_hash non-zero
    mov rax, [rsi + 16]             ; state_hash
    test rax, rax
    jz @@desync

    ; ?? LOG FRAME ??
    GHOST_WRITE 61h, rbx            ; GHOST_FRAME_COMPLETE

    ; ?? RENDER ??
    ; Clear
    mov rax, [glClear]
    test rax, rax
    jz @@skip_clear
    mov ecx, 4000h
    call rax
@@skip_clear:

    ; Swap buffers
    mov rcx, [g_SunshineCtx.hDC]
    call SwapBuffers

    ; Update currentTick
    mov [g_SunshineCtx.currentTick], rbx

    ; Signal frame complete
    mov rcx, [g_hCompositorFrameEvent]
    test rcx, rcx
    jz @@skip_signal
    call SetEvent
@@skip_signal:

    ; Mark tape entry CONSUMED (ready = 3)
    mov DWORD PTR [rsi + 168], 3

    mov rax, rbx
    jmp @@present_exit

@@spin_fallback:
    ; Fallback spin-wait if event not available
@@spin:
    mov rax, [g_SunshineCtx.currentTick]
    cmp rax, rbx
    jb @@spin
    jmp @@skip_clear

@@desync:
    ; Log desync
    GHOST_WRITE 62h, rbx            ; GHOST_DESYNC
    xor eax, eax
    jmp @@present_exit

@@present_exit:
    add rsp, 40h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Sunshine_Present ENDP

; ==============================================================================
; Sunshine_SetVSync ? Toggle VSync at runtime
; RCX = 1 (on) or 0 (off)
; ==============================================================================
PUBLIC Sunshine_SetVSync
Sunshine_SetVSync PROC
    push rbx
    sub rsp, 28h

    mov ebx, ecx
    mov BYTE PTR [g_SunshineCtx.is_vsync], bl

    mov rax, [wglSwapIntervalEXT]
    test rax, rax
    jz @@exit
    mov ecx, ebx
    call rax

@@exit:
    add rsp, 28h
    pop rbx
    ret
Sunshine_SetVSync ENDP

; ==============================================================================
; Sunshine_Shutdown ? Cleanup WGL context
; ==============================================================================
PUBLIC Sunshine_Shutdown
Sunshine_Shutdown PROC
    push rbx
    sub rsp, 28h

    mov rbx, [g_SunshineCtx.hRC]
    test rbx, rbx
    jz @@skip_rc

    xor edx, edx
    xor ecx, ecx
    call [wglMakeCurrent]

    mov rcx, rbx
    call [wglDeleteContext]

@@skip_rc:
    mov rcx, [g_SunshineCtx.hwnd]
    mov rdx, [g_SunshineCtx.hDC]
    test rdx, rdx
    jz @@skip_dc
    call ReleaseDC

@@skip_dc:
    ; Close event handle
    mov rcx, [g_hCompositorFrameEvent]
    test rcx, rcx
    jz @@skip_event
    call CloseHandle
@@skip_event:

    ; Zero context
    lea rdi, g_SunshineCtx
    mov rcx, SIZEOF SUNSHINE_CONTEXT
    xor eax, eax
    rep stosb

    add rsp, 28h
    pop rbx
    ret
Sunshine_Shutdown ENDP

; ==============================================================================
; Sunshine_GetCurrentTick / Sunshine_SetCurrentTick
; ==============================================================================
PUBLIC Sunshine_GetCurrentTick
Sunshine_GetCurrentTick PROC
    mov rax, [g_SunshineCtx.currentTick]
    ret
Sunshine_GetCurrentTick ENDP

PUBLIC Sunshine_SetCurrentTick
Sunshine_SetCurrentTick PROC
    mov [g_SunshineCtx.currentTick], rcx
    ret
Sunshine_SetCurrentTick ENDP

end
