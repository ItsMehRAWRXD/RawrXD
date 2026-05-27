; Sovereign_Compositor.asm
; x64 MASM ? Zero Dependency
; Minimal WGL OpenGL 3.3 context. Single quad. Shader hot-reload.
; Renders at display refresh via wglSwapIntervalEXT(1).

.data
    ; Pixel format descriptor (legacy, required for context creation)
    ALIGN 8
    pfd             DW      40      ; nSize
                    DW      1       ; nVersion
                    DD      25h     ; dwFlags = PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER | PFD_DRAW_TO_WINDOW
                    DB      0       ; iPixelType = PFD_TYPE_RGBA
                    DB      32      ; cColorBits
                    DB      0, 0, 0, 0, 0, 0, 0, 0 ; Shift/Bits (Ignored)
                    DB      0, 0, 0, 0, 0          ; AccumBits (Ignored)
                    DB      24      ; cDepthBits
                    DB      8       ; cStencilBits
                    DB      0       ; cAuxBuffers
                    DB      0       ; iLayerType
                    DB      0       ; bReserved
                    DD      0       ; dwLayerMask
                    DD      0       ; dwVisibleMask
                    DD      0       ; dwDamageMask

    ; Window state
    hWnd            DQ      0
    wnd_class       DB      80 DUP(0) ; 80 bytes for WNDCLASSEXA
    hDC             DQ      0
    hGLRC           DQ      0

    ; Shader program
    shader_program  DD      0
    quad_vao        DD      0
    quad_vbo        DD      0
    
    vert_shader     DD      0
    frag_shader     DD      0

    ; Function pointers (resolved at init)
    wglCreateContextAttribsARB_ptr  DQ 0
    wglSwapIntervalEXT_ptr          DQ 0
    glGenVertexArrays_ptr           DQ 0
    glBindVertexArray_ptr           DQ 0
    glGenBuffers_ptr                DQ 0
    glBindBuffer_ptr                DQ 0
    glBufferData_ptr                DQ 0
    glVertexAttribPointer_ptr       DQ 0
    glEnableVertexAttribArray_ptr   DQ 0
    glCreateShader_ptr              DQ 0
    glShaderSource_ptr              DQ 0
    glCompileShader_ptr             DQ 0
    glGetShaderiv_ptr               DQ 0
    glCreateProgram_ptr             DQ 0
    glAttachShader_ptr              DQ 0
    glLinkProgram_ptr               DQ 0
    glUseProgram_ptr                DQ 0
    glGetUniformLocation_ptr        DQ 0
    glUniform1f_ptr                 DQ 0
    glUniform2f_ptr                 DQ 0
    glDrawArrays_ptr                DQ 0
    glClear_ptr                     DQ 0
    glViewport_ptr                  DQ 0

    ; Vertex data: 2 triangles = 6 vertices, 2 floats each (position)
    ; Fullscreen quad in clip space
    quad_verts      REAL4   -1.0, -1.0,   1.0, -1.0,   -1.0, 1.0
                    REAL4    1.0, -1.0,   1.0,  1.0,   -1.0, 1.0

    ; Default fragment shader source (embedded, hot-reloadable from disk later)
    frag_shader_src DB      "#version 330 core",10
                    DB      "out vec4 fragColor;",10
                    DB      "uniform float u_time;",10
                    DB      "uniform vec2 u_res;",10
                    DB      "void main(){",10
                    DB      "vec2 uv=gl_FragCoord.xy/u_res;",10
                    DB      "fragColor=vec4(uv,0.5+0.5*sin(u_time),1.0);}",10,0
    frag_shader_arr DQ      frag_shader_src

    vert_shader_src DB      "#version 330 core",10
                    DB      "layout(location=0)in vec2 aPos;",10
                    DB      "void main(){gl_Position=vec4(aPos,0.0,1.0);}",10,0
    vert_shader_arr DQ      vert_shader_src

.code
    extern GetModuleHandleA:PROC
    extern RegisterClassExA:PROC
    extern CreateWindowExA:PROC
    extern DefWindowProcA:PROC
    extern GetDC:PROC
    extern ChoosePixelFormat:PROC
    extern SetPixelFormat:PROC
    extern wglCreateContext:PROC
    extern wglMakeCurrent:PROC
    extern wglGetProcAddress:PROC
    extern wglDeleteContext:PROC
    extern ShowWindow:PROC
    extern UpdateWindow:PROC
    extern glClearColor:PROC
    extern glClear:PROC
    extern glDrawArrays:PROC
    extern glViewport:PROC
    extern SwapBuffers:PROC
    extern GetClientRect:PROC
    

; -------------------------------------------------------------------
; Sovereign_Compositor_Init
; Creates window, WGL context, resolves GL function pointers.
; Input:  RCX = window width, RDX = window height
; Output: RAX = 1 success, 0 fail
; -------------------------------------------------------------------
Sovereign_Compositor_Init PROC
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 0B0h

    mov     r12d, ecx               ; width
    mov     r13d, edx               ; height
    xor     r15, r15

    ; Register window class
    xor     ecx, ecx
    call    GetModuleHandleA
    mov     rbx, rax

    lea     r9, [wnd_class]
    mov     dword ptr [r9], 80             ; cbSize
    mov     dword ptr [r9+4], 0            ; style
    lea     rax, [Sovereign_Compositor_WndProc]
    mov     qword ptr [r9+8], rax          ; lpfnWndProc
    mov     dword ptr [r9+16], 0           ; cbClsExtra
    mov     dword ptr [r9+20], 0           ; cbWndExtra
    mov     qword ptr [r9+24], rbx         ; hInstance
    mov     qword ptr [r9+32], 0           ; hIcon
    mov     qword ptr [r9+40], 0           ; hCursor
    mov     qword ptr [r9+48], 0           ; hbrBackground
    mov     qword ptr [r9+56], 0           ; lpszMenuName
    lea     rax, [wnd_class_name]
    mov     qword ptr [r9+64], rax         ; lpszClassName
    mov     qword ptr [r9+72], 0           ; hIconSm

    lea     rcx, [wnd_class]
    call    RegisterClassExA
    test    rax, rax
    jz      fail_init_2

    ; Create window
    xor     ecx, ecx
    lea     rdx, [wnd_class_name]
    xor     r8, r8
    mov     r9d, 06CF0000h          ; WS_OVERLAPPEDWINDOW | WS_CLIPSIBLINGS | WS_CLIPCHILDREN
    mov     qword ptr [rsp+20h], 0
    mov     qword ptr [rsp+28h], 0
    mov     [rsp+30h], r12
    mov     [rsp+38h], r13
    mov     qword ptr [rsp+40h], 0
    mov     qword ptr [rsp+48h], 0
    mov     qword ptr [rsp+50h], rbx
    mov     qword ptr [rsp+58h], 0
    call    CreateWindowExA
    test    rax, rax
    jz      fail_init_3
    mov     [hWnd], rax

    ; Get DC
    mov     rcx, [hWnd]
    call    GetDC
    test    rax, rax
    jz      fail_init_4
    mov     [hDC], rax

    ; Set pixel format
    mov     rcx, [hDC]
    lea     rdx, [pfd]
    call    ChoosePixelFormat
    test    eax, eax
    jz      fail_init_5

    mov     rcx, [hDC]
    mov     edx, eax
    lea     r8, [pfd]
    call    SetPixelFormat
    test    eax, eax
    jz      fail_init_6

    ; Create legacy context (required for wglGetProcAddress)
    mov     rcx, [hDC]
    call    wglCreateContext
    test    rax, rax
    jz      fail_init_7
    mov     [hGLRC], rax
    
    mov     rcx, [hDC]
    mov     rdx, [hGLRC]
    call    wglMakeCurrent
    test    eax, eax
    jz      fail_init_8

    ; Resolve extension functions
    lea     rcx, [str_wglCreateContextAttribsARB]
    call    wglGetProcAddress
    test    rax, rax
    jz      fail_init_9
    mov     [wglCreateContextAttribsARB_ptr], rax

    lea     rcx, [str_wglSwapIntervalEXT]
    call    wglGetProcAddress
    test    rax, rax
    jz      fail_init_9
    mov     [wglSwapIntervalEXT_ptr], rax

    ; Create core profile context
    mov     rcx, [hDC]
    xor     edx, edx                ; shareContext = NULL
    mov     r8d, 1                  ; major = 3
    mov     r9d, 3                  ; minor = 3
    sub     rsp, 30h
    mov     dword ptr [rsp], 02091h ; WGL_CONTEXT_MAJOR_VERSION_ARB
    mov     dword ptr [rsp+4], 3
    mov     dword ptr [rsp+8], 02092h ; WGL_CONTEXT_MINOR_VERSION_ARB
    mov     dword ptr [rsp+12], 3
    mov     dword ptr [rsp+16], 09126h ; WGL_CONTEXT_PROFILE_MASK_ARB
    mov     dword ptr [rsp+20], 1    ; WGL_CONTEXT_CORE_PROFILE_BIT_ARB
    mov     dword ptr [rsp+24], 0    ; terminator
    mov     r8, rsp
    call    [wglCreateContextAttribsARB_ptr]
    add     rsp, 30h
    test    rax, rax
    jz      fail_init_10

    ; Make core context current
    mov     r14, rax                ; Save core context handle
    mov     rcx, [hDC]
    mov     rdx, r14
    call    wglMakeCurrent
    test    eax, eax
    jz      fail_init_11
    
    ; Delete legacy context
    mov     rcx, [hGLRC]
    call    wglDeleteContext
    mov     [hGLRC], r14

    ; Enable VSync
    mov     ecx, 1
    call    [wglSwapIntervalEXT_ptr]

    ; Resolve GL 3.3 functions
    call    Sovereign_ResolveGLPointers

    ; Create quad geometry
    call    Sovereign_CreateQuad

    ; Compile default shader
    call    Sovereign_CompileDefaultShader

    ; Show window
    mov     rcx, [hWnd]
    mov     edx, 1                  ; SW_SHOWNORMAL
    call    ShowWindow
    mov     rcx, [hWnd]
    call    UpdateWindow

    ; Validate pointers
    cmp     qword ptr [glUseProgram_ptr], 0
    je      fail_init_12


    mov     rax, 1
    jmp     done_init

fail_init_11:
    mov     r15, 11
    jmp     fail_init_destroy_context
fail_init_10:
    mov     r15, 10
    jmp     fail_init_release_legacy
fail_init_9:
    mov     r15, 9
    jmp     fail_init_release_legacy
fail_init_8:
    mov     r15, 8
    jmp     fail_init_destroy_context
fail_init_7:
    mov     r15, 7
    jmp     fail_init_ret
fail_init_6:
    mov     r15, 6
    jmp     fail_init_ret
fail_init_5:
    mov     r15, 5
    jmp     fail_init_ret
fail_init_4:
    mov     r15, 4
    jmp     fail_init_ret
fail_init_3:
    mov     r15, 3
    jmp     fail_init_ret
fail_init_2:
    mov     r15, 2
    jmp     fail_init_ret
fail_init_12:
    mov     r15, 12
    jmp     fail_init_release_legacy


fail_init_release_legacy:
    xor     ecx, ecx
    xor     edx, edx
    call    wglMakeCurrent

fail_init_destroy_context:
    mov     rcx, [hGLRC]
    test    rcx, rcx
    jz      fail_init_ret

    call    wglDeleteContext

fail_init_ret:
    mov     rax, r15 ; Return failure code

done_init:
    add     rsp, 0B0h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
Sovereign_Compositor_Init ENDP


; -------------------------------------------------------------------
; Sovereign_ResolveGLPointers
; Resolves all GL 3.3 function pointers via wglGetProcAddress.
; -------------------------------------------------------------------
Sovereign_ResolveGLPointers PROC
    sub rsp, 28h

    lea     rcx, [str_glGenVertexArrays]
    call    wglGetProcAddress
    mov     [glGenVertexArrays_ptr], rax

    lea     rcx, [str_glBindVertexArray]
    call    wglGetProcAddress
    mov     [glBindVertexArray_ptr], rax

    lea     rcx, [str_glGenBuffers]
    call    wglGetProcAddress
    mov     [glGenBuffers_ptr], rax

    lea     rcx, [str_glBindBuffer]
    call    wglGetProcAddress
    mov     [glBindBuffer_ptr], rax

    lea     rcx, [str_glBufferData]
    call    wglGetProcAddress
    mov     [glBufferData_ptr], rax

    lea     rcx, [str_glVertexAttribPointer]
    call    wglGetProcAddress
    mov     [glVertexAttribPointer_ptr], rax

    lea     rcx, [str_glEnableVertexAttribArray]
    call    wglGetProcAddress
    mov     [glEnableVertexAttribArray_ptr], rax

    lea     rcx, [str_glCreateShader]
    call    wglGetProcAddress
    mov     [glCreateShader_ptr], rax

    lea     rcx, [str_glShaderSource]
    call    wglGetProcAddress
    mov     [glShaderSource_ptr], rax

    lea     rcx, [str_glCompileShader]
    call    wglGetProcAddress
    mov     [glCompileShader_ptr], rax

    lea     rcx, [str_glGetShaderiv]
    call    wglGetProcAddress
    mov     [glGetShaderiv_ptr], rax

    lea     rcx, [str_glCreateProgram]
    call    wglGetProcAddress
    mov     [glCreateProgram_ptr], rax

    lea     rcx, [str_glAttachShader]
    call    wglGetProcAddress
    mov     [glAttachShader_ptr], rax

    lea     rcx, [str_glLinkProgram]
    call    wglGetProcAddress
    mov     [glLinkProgram_ptr], rax

    lea     rcx, [str_glUseProgram]
    call    wglGetProcAddress
    mov     [glUseProgram_ptr], rax

    lea     rcx, [str_glGetUniformLocation]
    call    wglGetProcAddress
    mov     [glGetUniformLocation_ptr], rax

    lea     rcx, [str_glUniform1f]
    call    wglGetProcAddress
    mov     [glUniform1f_ptr], rax

    lea     rcx, [str_glUniform2f]
    call    wglGetProcAddress
    mov     [glUniform2f_ptr], rax

    add rsp, 28h
    ret
Sovereign_ResolveGLPointers ENDP

; -------------------------------------------------------------------
; Sovereign_CreateQuad
; Uploads fullscreen quad to GPU.
; -------------------------------------------------------------------
Sovereign_CreateQuad PROC
    sub     rsp, 38h

    lea     rcx, [quad_vao]
    call    [glGenVertexArrays_ptr]
    mov     ecx, [quad_vao]
    call    [glBindVertexArray_ptr]

    lea     rcx, [quad_vbo]
    call    [glGenBuffers_ptr]
    mov     ecx, [quad_vbo]
    call    [glBindBuffer_ptr]
    mov     ecx, 08892h             ; GL_ARRAY_BUFFER
    mov     edx, 48                 ; 6 vertices * 2 floats * 4 bytes
    lea     r8, [quad_verts]
    mov     r9d, 088E4h             ; GL_STATIC_DRAW
    call    [glBufferData_ptr]

    mov     ecx, 0                  ; index
    mov     edx, 2                  ; size
    mov     r8d, 01406h             ; GL_FLOAT
    mov     r9d, 0                  ; normalized
    mov     qword ptr [rsp+20h], 0  ; stride
    mov     qword ptr [rsp+28h], 0  ; offset
    call    [glVertexAttribPointer_ptr]
    mov     ecx, 0
    call    [glEnableVertexAttribArray_ptr]

    add     rsp, 38h
    ret
Sovereign_CreateQuad ENDP

; -------------------------------------------------------------------
; Sovereign_CompileDefaultShader
; Compiles embedded vertex + fragment shader.
; -------------------------------------------------------------------
Sovereign_CompileDefaultShader PROC
    sub     rsp, 38h

    ; Vertex Shader
    mov     ecx, 08B31h             ; GL_VERTEX_SHADER
    call    [glCreateShader_ptr]
    mov     [vert_shader], eax

    mov     ecx, eax
    mov     edx, 1
    lea     r8, [vert_shader_arr]
    xor     r9d, r9d
    call    [glShaderSource_ptr]

    mov     ecx, [vert_shader]
    call    [glCompileShader_ptr]

    ; Fragment Shader
    mov     ecx, 08B30h             ; GL_FRAGMENT_SHADER
    call    [glCreateShader_ptr]
    mov     [frag_shader], eax

    mov     ecx, eax
    mov     edx, 1
    lea     r8, [frag_shader_arr]
    xor     r9d, r9d
    call    [glShaderSource_ptr]

    mov     ecx, [frag_shader]
    call    [glCompileShader_ptr]

    ; Program
    call    [glCreateProgram_ptr]
    mov     [shader_program], eax

    mov     ecx, eax
    mov     edx, [vert_shader]
    call    [glAttachShader_ptr]

    mov     ecx, [shader_program]
    mov     edx, [frag_shader]
    call    [glAttachShader_ptr]

    mov     ecx, [shader_program]
    call    [glLinkProgram_ptr]

    add     rsp, 38h
    ret
Sovereign_CompileDefaultShader ENDP

; -------------------------------------------------------------------
; Sovereign_Compositor_Render
; Called once per frame from Tick Master after simulation step.
; Input:  xmm0 = u_time (float), xmm1 = width (float), xmm2 = height (float)
; -------------------------------------------------------------------
Sovereign_Compositor_Render PROC
    push    rbx
    sub     rsp, 30h

    mov     rax, [glUseProgram_ptr]
    test    rax, rax
    jz      skip_render

    ; Save floats to stack to preserve across calls
    movss   real4 ptr [rsp+20h], xmm0
    movss   real4 ptr [rsp+24h], xmm1
    movss   real4 ptr [rsp+28h], xmm2

    ; Set viewport
    xor     ecx, ecx
    xor     edx, edx
    cvttss2si r8d, real4 ptr [rsp+24h]
    cvttss2si r9d, real4 ptr [rsp+28h]
    call    glViewport

    ; Clear
    mov     ecx, 04000h             ; GL_COLOR_BUFFER_BIT
    call    glClear

    ; Use shader
    mov     ecx, [shader_program]
    call    [glUseProgram_ptr]

    ; Set uniforms
    ; u_time
    mov     ecx, [shader_program]
    lea     rdx, [str_u_time]
    call    [glGetUniformLocation_ptr]
    mov     ecx, eax
    movss   xmm1, real4 ptr [rsp+20h]
    call    [glUniform1f_ptr]

    ; u_res
    mov     ecx, [shader_program]
    lea     rdx, [str_u_res]
    call    [glGetUniformLocation_ptr]
    mov     ecx, eax
    movss   xmm1, real4 ptr [rsp+24h]
    movss   xmm2, real4 ptr [rsp+28h]
    call    [glUniform2f_ptr]

    ; Draw quad
    mov     ecx, 0                  ; GL_TRIANGLES
    xor     edx, edx                ; first
    mov     r8d, 6                  ; count
    call    glDrawArrays

    ; Swap
    mov     rcx, [hDC]
    call    SwapBuffers

skip_render:
    add     rsp, 30h
    pop     rbx
    ret
Sovereign_Compositor_Render ENDP

; -------------------------------------------------------------------
; Sovereign_Compositor_WndProc
; Minimal. Defers to DefWindowProc.
; -------------------------------------------------------------------
Sovereign_Compositor_WndProc PROC
    jmp     DefWindowProcA
Sovereign_Compositor_WndProc ENDP

.data
str_wglCreateContextAttribsARB  DB "wglCreateContextAttribsARB", 0
str_wglSwapIntervalEXT          DB "wglSwapIntervalEXT", 0
str_glGenVertexArrays           DB "glGenVertexArrays", 0
str_glBindVertexArray           DB "glBindVertexArray", 0
str_glGenBuffers                DB "glGenBuffers", 0
str_glBindBuffer                DB "glBindBuffer", 0
str_glBufferData                DB "glBufferData", 0
str_glVertexAttribPointer       DB "glVertexAttribPointer", 0
str_glEnableVertexAttribArray   DB "glEnableVertexAttribArray", 0
str_glCreateShader              DB "glCreateShader", 0
str_glShaderSource              DB "glShaderSource", 0
str_glCompileShader             DB "glCompileShader", 0
str_glGetShaderiv               DB "glGetShaderiv", 0
str_glCreateProgram             DB "glCreateProgram", 0
str_glAttachShader              DB "glAttachShader", 0
str_glLinkProgram               DB "glLinkProgram", 0
str_glUseProgram                DB "glUseProgram", 0
str_glGetUniformLocation        DB "glGetUniformLocation", 0
str_glUniform1f                 DB "glUniform1f", 0
str_glUniform2f                 DB "glUniform2f", 0
str_glDrawArrays                DB "glDrawArrays", 0
str_glClear                     DB "glClear", 0
str_glViewport                  DB "glViewport", 0

str_u_time                      DB "u_time", 0
str_u_res                       DB "u_res", 0
wnd_class_name                  DB "SunshineCompositor", 0

PUBLIC  Sovereign_Compositor_Init
PUBLIC  Sovereign_Compositor_Render

END
