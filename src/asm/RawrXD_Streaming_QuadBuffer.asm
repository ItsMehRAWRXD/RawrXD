; =============================================================================
; RawrXD_Streaming_QuadBuffer.asm
; SPSC Ring Buffer + GDI Double-Buffer Render Loop for Tensor Streaming
; Targets: 60 FPS HWND-rendered tensor heatmap / token stream visualization
; Architecture: x64 MASM | Windows ABI | No CRT | No exceptions
;
; Exports:
;   SQB_Init            — Initialize SPSC ring and render state
;   SQB_Shutdown        — Tear down threads, DCs, window
;   SQB_CreateRenderWnd — Create child HWND for BitBlt target
;   SQB_DestroyRenderWnd— Destroy HWND and release GDI resources
;   SQB_PushFrame       — Producer: push tensor frame into SPSC ring
;   SQB_GetFrameStats   — Query dropped frames, current FPS, ring occupancy
;   SQB_SetTargetFPS    — Adjust render timer interval at runtime
;
; Build: ml64.exe /c /Zi /Zd /Fo RawrXD_Streaming_QuadBuffer.obj
; Link:  ws2_32.lib kernel32.lib user32.lib gdi32.lib
; =============================================================================

OPTION CASemap:NONE

; -----------------------------------------------------------------------------
; Exports
; -----------------------------------------------------------------------------
PUBLIC SQB_Init
PUBLIC SQB_Shutdown
PUBLIC SQB_CreateRenderWnd
PUBLIC SQB_DestroyRenderWnd
PUBLIC SQB_PushFrame
PUBLIC SQB_GetFrameStats
PUBLIC SQB_SetTargetFPS

; -----------------------------------------------------------------------------
; Constants
; -----------------------------------------------------------------------------
SQB_RING_SLOTS          EQU     4               ; Quad-buffer = 4 slots
SQB_SLOT_BYTES          EQU     (4*1024*1024)   ; 4MB per slot (tensor heatmap)
SQB_TARGET_FPS          EQU     60
SQB_TIMER_MS            EQU     16              ; 1000/60 ≈ 16.6ms
SQB_MAGIC               EQU     053514248h      ; 'SQB' + version

; GDI constants
WM_APP_RENDER           EQU     0x8000          ; Private window message
CS_HREDRAW              EQU     00002h
CS_VREDRAW              EQU     00001h
WS_CHILD                EQU     40000000h
WS_VISIBLE                EQU     10000000h

; -----------------------------------------------------------------------------
; Structures (aligned to 8)
; -----------------------------------------------------------------------------
SPSC_SLOT               STRUCT  8
    Ready               DD      ?               ; 0=empty, 1=ready, 2=consumed
    _pad0               DD      ?
    DataPtr             DQ      ?               ; -> slot payload
    DataLen             DQ      ?               ; valid bytes in slot
    TimestampQPC        DQ      ?               ; QPC when pushed
SPSC_SLOT               ENDS

SPSC_RING               STRUCT  8
    Magic               DD      ?
    SlotCount           DD      ?
    WriteIdx            DD      ?               ; Producer index (mod count)
    ReadIdx             DD      ?                ; Consumer index (mod count)
    DroppedFrames       DQ      ?               ; Producer overwrites
    RenderedFrames      DQ      ?               ; Consumer completions
    LastFrameQPC        DQ      ?               ; For FPS calc
    SlotSize            DQ      ?
    pSlots              DQ      ?               ; -> SPSC_SLOT[SlotCount]
    pSlotData           DQ      ?               ; contiguous blob for all slots
SPSC_RING               ENDS

RENDER_CTX              STRUCT  8
    hWnd                DQ      ?
    hDC                 DQ      ?               ; Window DC
    hMemDC              DQ      ?               ; Compatible mem DC
    hDIB                DQ      ?               ; DIB section bitmap
    pDIBBits            DQ      ?               ; -> locked bitmap bits
    Width               DD      ?
    Height              DD      ?
    BytesPerPixel       DD      ?
    Pitch               DD      ?
    hRenderThread       DQ      ?
    hTimer              DQ      ?               ; Multimedia timer handle
    Running             DD      ?
    TargetFPS           DD      ?
    _pad1               DD      ?
RENDER_CTX              ENDS

; -----------------------------------------------------------------------------
; External Imports
; -----------------------------------------------------------------------------
EXTERN CreateWindowExW:PROC
EXTERN DestroyWindow:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN CreateCompatibleDC:PROC
EXTERN DeleteDC:PROC
EXTERN CreateDIBSection:PROC
EXTERN SelectObject:PROC
EXTERN DeleteObject:PROC
EXTERN BitBlt:PROC
EXTERN SetDIBits:PROC
EXTERN GetDIBits:PROC
EXTERN QueryPerformanceCounter:PROC
EXTERN QueryPerformanceFrequency:PROC
EXTERN CreateThread:PROC
EXTERN WaitForSingleObject:PROC
EXTERN CloseHandle:PROC
EXTERN Sleep:PROC
EXTERN timeSetEvent:PROC
EXTERN timeKillEvent:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC
EXTERN memset:PROC
EXTERN memcpy:PROC
EXTERN EnterCriticalSection:PROC
EXTERN LeaveCriticalSection:PROC
EXTERN InitializeCriticalSection:PROC
EXTERN DeleteCriticalSection:PROC

; -----------------------------------------------------------------------------
; Data Section
; -----------------------------------------------------------------------------
.DATA
ALIGN 16

; Global singletons
g_RingCtx               DQ      0
g_RenderCtx             DQ      0
g_QPCFreq               DQ      0
g_InitDone              DD      0

; Bitmap info header (packed 40 bytes)
ALIGN 8
g_BMIH:
    DB 40, 0, 0, 0          ; biSize = 40
    DW 0, 0                 ; biWidth (patched at runtime)
    DW 0, 0                 ; biHeight (patched at runtime)
    DW 1, 0                 ; biPlanes = 1
    DW 24, 0                ; biBitCount = 24
    DD 0                    ; biCompression = BI_RGB
    DD 0                    ; biSizeImage
    DD 0                    ; biXPelsPerMeter
    DD 0                    ; biYPelsPerMeter
    DD 0                    ; biClrUsed
    DD 0                    ; biClrImportant

; Critical section for ring index updates (very short hold)
ALIGN 8
g_RingCS                DB 64 DUP(0)

; -----------------------------------------------------------------------------
; Code Section
; -----------------------------------------------------------------------------
.CODE

; =============================================================================
; SQB_Init — Allocate ring + render context, init QPC frequency
; RCX = SlotCount (suggest 4), RDX = SlotBytes (suggest 4MB)
; Returns: RAX = 0 on success, -1 on error
; =============================================================================
SQB_Init PROC FRAME
    .endprolog
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 40

    cmp     g_InitDone, 0
    jne     @init_already

    ; --- Capture QPC frequency once ---
    lea     rcx, g_QPCFreq
    call    QueryPerformanceFrequency

    ; --- Allocate SPSC_RING ---
    mov     rcx, SIZEOF SPSC_RING
    xor     edx, edx
    mov     r8d, 1000h OR 2000h         ; MEM_COMMIT | MEM_RESERVE
    mov     r9d, 4                      ; PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      @init_fail
    mov     rbx, rax                    ; rbx = ring ptr
    mov     g_RingCtx, rax

    mov     DWORD PTR [rbx].SPSC_RING.Magic, SQB_MAGIC
    mov     eax, ecx
    cmp     eax, 1
    cmova   ecx, eax
    cmp     ecx, SQB_RING_SLOTS
    cmova   ecx, SQB_RING_SLOTS
    mov     [rbx].SPSC_RING.SlotCount, ecx
    mov     [rbx].SPSC_RING.WriteIdx, 0
    mov     [rbx].SPSC_RING.ReadIdx, 0
    mov     QWORD PTR [rbx].SPSC_RING.DroppedFrames, 0
    mov     QWORD PTR [rbx].SPSC_RING.RenderedFrames, 0

    ; Slot size = max(requested, 64KB)
    mov     rax, rdx
    cmp     rax, 65536
    cmovb   rax, 65536
    mov     [rbx].SPSC_RING.SlotSize, rax

    ; --- Allocate slot metadata array ---
    mov     ecx, [rbx].SPSC_RING.SlotCount
    mov     r8, rcx
    imul    r8, SIZEOF SPSC_SLOT
    mov     rcx, r8
    xor     edx, edx
    mov     r8d, 1000h OR 2000h
    mov     r9d, 4
    call    VirtualAlloc
    test    rax, rax
    jz      @init_fail_ring
    mov     [rbx].SPSC_RING.pSlots, rax
    mov     rdi, rax

    ; --- Allocate contiguous slot data blob ---
    mov     r8, [rbx].SPSC_RING.SlotSize
    mov     eax, [rbx].SPSC_RING.SlotCount
    mul     r8                          ; rax = total bytes
    mov     rcx, rax
    xor     edx, edx
    mov     r8d, 1000h OR 2000h
    mov     r9d, 4
    call    VirtualAlloc
    test    rax, rax
    jz      @init_fail_slots
    mov     [rbx].SPSC_RING.pSlotData, rax

    ; --- Zero slot metadata and init DataPtr ---
    mov     rsi, [rbx].SPSC_RING.pSlots
    mov     rdi, [rbx].SPSC_RING.pSlotData
    mov     ecx, [rbx].SPSC_RING.SlotCount
    xor     r8d, r8d

@init_slot_loop:
    mov     DWORD PTR [rsi].SPSC_SLOT.Ready, 0
    mov     [rsi].SPSC_SLOT.DataPtr, rdi
    mov     QWORD PTR [rsi].SPSC_SLOT.DataLen, 0
    mov     QWORD PTR [rsi].SPSC_SLOT.TimestampQPC, 0
    add     rdi, [rbx].SPSC_RING.SlotSize
    add     rsi, SIZEOF SPSC_SLOT
    dec     ecx
    jnz     @init_slot_loop

    ; --- Allocate RENDER_CTX ---
    mov     rcx, SIZEOF RENDER_CTX
    xor     edx, edx
    mov     r8d, 1000h OR 2000h
    mov     r9d, 4
    call    VirtualAlloc
    test    rax, rax
    jz      @init_fail_blob
    mov     g_RenderCtx, rax
    mov     rdi, rax
    xor     eax, eax
    mov     ecx, SIZEOF RENDER_CTX
    rep     stosb

    mov     rax, g_RenderCtx
    mov     DWORD PTR [rax].RENDER_CTX.TargetFPS, SQB_TARGET_FPS

    ; --- Init critical section ---
    lea     rcx, g_RingCS
    call    InitializeCriticalSection

    mov     g_InitDone, 1
    xor     eax, eax
    jmp     @init_exit

@init_already:
    xor     eax, eax
    jmp     @init_exit

@init_fail_blob:
    mov     rcx, [rbx].SPSC_RING.pSlotData
    xor     edx, edx
    mov     r8d, 8000h                  ; MEM_RELEASE
    call    VirtualFree
@init_fail_slots:
    mov     rcx, [rbx].SPSC_RING.pSlots
    xor     edx, edx
    mov     r8d, 8000h
    call    VirtualFree
@init_fail_ring:
    mov     rcx, rbx
    xor     edx, edx
    mov     r8d, 8000h
    call    VirtualFree
    mov     g_RingCtx, 0
@init_fail:
    mov     rax, -1

@init_exit:
    add     rsp, 40
    pop     rsi
    pop     rdi
    pop     rbx
    ret
SQB_Init ENDP

; =============================================================================
; SQB_CreateRenderWnd — Create HWND and GDI double-buffer resources
; RCX = parent HWND, RDX = width, R8 = height, R9 = child ID
; Returns: RAX = child HWND or 0
; =============================================================================
SQB_CreateRenderWnd PROC FRAME
    .endprolog
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 88

    mov     r12, rcx                    ; parent HWND
    mov     r13d, edx                   ; width
    mov     r14d, r8d                   ; height
    mov     r15d, r9d                   ; child ID

    mov     rax, g_RenderCtx
    test    rax, rax
    jz      @crwnd_fail
    mov     rbx, rax

    ; --- Create child window ---
    ; CreateWindowExW(0, L"STATIC", NULL, WS_CHILD|WS_VISIBLE, 0,0,w,h, parent, (HMENU)id, NULL, NULL)
    xor     ecx, ecx                    ; dwExStyle
    lea     rdx, @szStaticClass
    xor     r8d, r8d                    ; lpWindowName = NULL
    mov     r9d, WS_CHILD OR WS_VISIBLE ; dwStyle
    mov     DWORD PTR [rsp+32], 0       ; X
    mov     DWORD PTR [rsp+40], 0       ; Y
    mov     DWORD PTR [rsp+48], r13d    ; nWidth
    mov     DWORD PTR [rsp+56], r14d    ; nHeight
    mov     rax, r12
    mov     QWORD PTR [rsp+64], rax     ; hWndParent
    mov     rax, r15
    mov     QWORD PTR [rsp+72], rax     ; hMenu = (HMENU)id
    mov     QWORD PTR [rsp+80], 0       ; hInstance — let Windows resolve
    call    CreateWindowExW
    test    rax, rax
    jz      @crwnd_fail
    mov     [rbx].RENDER_CTX.hWnd, rax
    mov     [rbx].RENDER_CTX.Width, r13d
    mov     [rbx].RENDER_CTX.Height, r14d
    mov     DWORD PTR [rbx].RENDER_CTX.BytesPerPixel, 3

    ; --- Get window DC ---
    mov     rcx, [rbx].RENDER_CTX.hWnd
    call    GetDC
    mov     [rbx].RENDER_CTX.hDC, rax

    ; --- Create compatible memory DC ---
    mov     rcx, rax
    call    CreateCompatibleDC
    mov     [rbx].RENDER_CTX.hMemDC, rax

    ; --- Build BITMAPINFO and create DIB section ---
    mov     eax, r13d
    mov     WORD PTR [g_BMIH+4], ax     ; biWidth low
    mov     eax, r14d
    neg     eax
    mov     WORD PTR [g_BMIH+6], ax     ; biHeight = negative (top-down)

    mov     rcx, [rbx].RENDER_CTX.hDC
    lea     rdx, g_BMIH
    xor     r8d, r8d                    ; usage = DIB_RGB_COLORS
    lea     r9, [rbx].RENDER_CTX.pDIBBits
    mov     QWORD PTR [rsp+32], 0       ; hSection = NULL
    mov     QWORD PTR [rsp+40], 0       ; offset
    call    CreateDIBSection
    test    rax, rax
    jz      @crwnd_fail_dc
    mov     [rbx].RENDER_CTX.hDIB, rax

    ; --- Select DIB into mem DC ---
    mov     rcx, [rbx].RENDER_CTX.hMemDC
    mov     rdx, rax
    call    SelectObject

    ; --- Calculate pitch (4-byte aligned) ---
    mov     eax, r13d
    imul    eax, 3                      ; width * 3 bytes
    add     eax, 3
    and     eax, 0FFFFFFFCh             ; align up to 4
    mov     [rbx].RENDER_CTX.Pitch, eax

    ; --- Clear to black ---
    mov     rcx, [rbx].RENDER_CTX.pDIBBits
    xor     edx, edx
    mov     r8d, r13d
    imul    r8d, [rbx].RENDER_CTX.Pitch
    call    memset

    mov     rax, [rbx].RENDER_CTX.hWnd
    jmp     @crwnd_exit

@crwnd_fail_dc:
    mov     rcx, [rbx].RENDER_CTX.hWnd
    call    DestroyWindow
@crwnd_fail:
    xor     eax, eax

@crwnd_exit:
    add     rsp, 88
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; Local string literal
@szStaticClass:
    DW 'S','T','A','T','I','C',0

SQB_CreateRenderWnd ENDP

; =============================================================================
; SQB_DestroyRenderWnd — Release all GDI resources and destroy HWND
; No params (uses global render ctx)
; Returns: RAX = 0
; =============================================================================
SQB_DestroyRenderWnd PROC FRAME
    .endprolog
    push    rbx
    sub     rsp, 40

    mov     rbx, g_RenderCtx
    test    rbx, rbx
    jz      @drwnd_done

    ; Stop render timer if running
    cmp     DWORD PTR [rbx].RENDER_CTX.Running, 0
    je      @drwnd_no_timer
    mov     rcx, [rbx].RENDER_CTX.hTimer
    test    rcx, rcx
    jz      @drwnd_no_timer
    call    timeKillEvent
    mov     QWORD PTR [rbx].RENDER_CTX.hTimer, 0
@drwnd_no_timer:

    ; Release DC
    mov     rcx, [rbx].RENDER_CTX.hWnd
    mov     rdx, [rbx].RENDER_CTX.hDC
    test    rdx, rdx
    jz      @drwnd_no_dc
    call    ReleaseDC
    mov     QWORD PTR [rbx].RENDER_CTX.hDC, 0
@drwnd_no_dc:

    ; Delete mem DC
    mov     rcx, [rbx].RENDER_CTX.hMemDC
    test    rcx, rcx
    jz      @drwnd_no_memdc
    call    DeleteDC
    mov     QWORD PTR [rbx].RENDER_CTX.hMemDC, 0
@drwnd_no_memdc:

    ; Delete DIB bitmap
    mov     rcx, [rbx].RENDER_CTX.hDIB
    test    rcx, rcx
    jz      @drwnd_no_dib
    call    DeleteObject
    mov     QWORD PTR [rbx].RENDER_CTX.hDIB, 0
@drwnd_no_dib:

    ; Destroy window
    mov     rcx, [rbx].RENDER_CTX.hWnd
    test    rcx, rcx
    jz      @drwnd_no_wnd
    call    DestroyWindow
    mov     QWORD PTR [rbx].RENDER_CTX.hWnd, 0
@drwnd_no_wnd:

@drwnd_done:
    xor     eax, eax
    add     rsp, 40
    pop     rbx
    ret
SQB_DestroyRenderWnd ENDP

; =============================================================================
; SQB_PushFrame — Producer: copy tensor data into next SPSC ring slot
; RCX = pData, RDX = DataLen
; Returns: RAX = 0 (queued), 1 (dropped / ring full)
; =============================================================================
SQB_PushFrame PROC FRAME
    .endprolog
    push    rbx
    push    rdi
    push    rsi
    sub     rsp, 40

    mov     rdi, g_RingCtx
    test    rdi, rdi
    jz      @push_fail

    mov     rbx, rcx                    ; pData
    mov     r12, rdx                    ; DataLen

    ; --- Lock ---
    lea     rcx, g_RingCS
    call    EnterCriticalSection

    ; Compute next write index
    mov     eax, [rdi].SPSC_RING.WriteIdx
    inc     eax
    cmp     eax, [rdi].SPSC_RING.SlotCount
    jb      @push_idx_ok
    xor     eax, eax
@push_idx_ok:

    ; Check if next slot is consumed (ready for overwrite)
    mov     rsi, [rdi].SPSC_RING.pSlots
    mov     edx, eax
    imul    rdx, SIZEOF SPSC_SLOT
    add     rsi, rdx
    cmp     DWORD PTR [rsi].SPSC_SLOT.Ready, 2    ; 2 = consumed
    je      @push_overwrite
    cmp     DWORD PTR [rsi].SPSC_SLOT.Ready, 0      ; 0 = empty
    je      @push_overwrite

    ; Ring full — drop frame
    inc     QWORD PTR [rdi].SPSC_RING.DroppedFrames
    lea     rcx, g_RingCS
    call    LeaveCriticalSection
    mov     rax, 1
    jmp     @push_exit

@push_overwrite:
    ; Advance write index
    mov     [rdi].SPSC_RING.WriteIdx, eax

    ; Get slot pointer
    mov     edx, eax
    imul    rdx, SIZEOF SPSC_SLOT
    mov     rsi, [rdi].SPSC_RING.pSlots
    add     rsi, rdx

    ; Clamp data length to slot size
    mov     r8, r12
    cmp     r8, [rdi].SPSC_RING.SlotSize
    cmova   r8, [rdi].SPSC_RING.SlotSize

    ; Copy data
    mov     rcx, [rsi].SPSC_SLOT.DataPtr
    mov     rdx, rbx
    call    memcpy
    mov     [rsi].SPSC_SLOT.DataLen, r8

    ; Stamp QPC
    lea     rcx, [rsi].SPSC_SLOT.TimestampQPC
    call    QueryPerformanceCounter

    ; Mark ready
    mov     DWORD PTR [rsi].SPSC_SLOT.Ready, 1

    ; Unlock
    lea     rcx, g_RingCS
    call    LeaveCriticalSection

    xor     eax, eax
    jmp     @push_exit

@push_fail:
    mov     rax, 1

@push_exit:
    add     rsp, 40
    pop     rsi
    pop     rdi
    pop     rbx
    ret
SQB_PushFrame ENDP

; =============================================================================
; SQB_RenderThreadProc — Consumer: blit latest ready frame to HWND at 60 FPS
; RCX = unused (thread param)
; =============================================================================
SQB_RenderThreadProc PROC FRAME
    .endprolog
    push    rbx
    push    r12
    push    r13
    sub     rsp, 40

    mov     rbx, g_RenderCtx
    test    rbx, rbx
    jz      @rend_exit
    mov     r12, g_RingCtx
    test    r12, r12
    jz      @rend_exit

@rend_loop:
    cmp     DWORD PTR [rbx].RENDER_CTX.Running, 0
    je      @rend_exit

    ; --- Find latest ready slot ---
    mov     r13, -1                     ; best slot index
    mov     rsi, [r12].SPSC_RING.pSlots
    mov     ecx, [r12].SPSC_RING.SlotCount
    xor     r8d, r8d                    ; loop counter

@rend_scan:
    cmp     DWORD PTR [rsi].SPSC_SLOT.Ready, 1
    jne     @rend_next
    cmp     r13, -1
    je      @rend_pick
    ; Compare QPC timestamps — pick newest
    mov     rax, [rsi].SPSC_SLOT.TimestampQPC
    mov     rdi, [r12].SPSC_RING.pSlots
    mov     rdx, r13
    imul    rdx, SIZEOF SPSC_SLOT
    add     rdi, rdx
    cmp     rax, [rdi].SPSC_SLOT.TimestampQPC
    jb      @rend_next
@rend_pick:
    mov     r13d, r8d
@rend_next:
    add     rsi, SIZEOF SPSC_SLOT
    inc     r8d
    dec     ecx
    jnz     @rend_scan

    cmp     r13, -1
    je      @rend_nothing_ready

    ; --- Blit the frame ---
    mov     rsi, [r12].SPSC_RING.pSlots
    mov     rdx, r13
    imul    rdx, SIZEOF SPSC_SLOT
    add     rsi, rdx

    ; Copy slot data into DIB bits (tensor heatmap -> RGB24)
    mov     rcx, [rbx].RENDER_CTX.pDIBBits
    mov     rdx, [rsi].SPSC_SLOT.DataPtr
    mov     r8, [rsi].SPSC_SLOT.DataLen
    ; Clamp to DIB size
    mov     eax, [rbx].RENDER_CTX.Width
    imul    eax, [rbx].RENDER_CTX.Height
    imul    eax, 3
    cmp     r8, rax
    cmova   r8, rax
    call    memcpy

    ; Mark consumed
    mov     DWORD PTR [rsi].SPSC_SLOT.Ready, 2
    inc     QWORD PTR [r12].SPSC_RING.RenderedFrames

    ; --- BitBlt mem DC -> window DC ---
    mov     rcx, [rbx].RENDER_CTX.hDC
    xor     edx, edx                    ; dest x
    xor     r8d, r8d                    ; dest y
    mov     r9d, [rbx].RENDER_CTX.Width
    mov     eax, [rbx].RENDER_CTX.Height
    mov     DWORD PTR [rsp+32], eax     ; dest h
    mov     rax, [rbx].RENDER_CTX.hMemDC
    mov     QWORD PTR [rsp+40], rax     ; src DC
    mov     DWORD PTR [rsp+48], 0       ; src x
    mov     DWORD PTR [rsp+56], 0       ; src y
    mov     eax, 0CC0020h               ; SRCCOPY
    mov     DWORD PTR [rsp+64], eax   ; rop
    call    BitBlt

@rend_nothing_ready:
    ; --- Frame pacing: sleep to target ~60 FPS ---
    mov     ecx, SQB_TIMER_MS
    call    Sleep
    jmp     @rend_loop

@rend_exit:
    add     rsp, 40
    pop     r13
    pop     r12
    pop     rbx
    xor     eax, eax
    ret
SQB_RenderThreadProc ENDP

; =============================================================================
; SQB_Shutdown — Stop render thread, free all resources
; No params
; Returns: RAX = 0
; =============================================================================
SQB_Shutdown PROC FRAME
    .endprolog
    push    rbx
    sub     rsp, 40

    cmp     g_InitDone, 0
    je      @shut_done

    ; Stop render loop
    mov     rbx, g_RenderCtx
    test    rbx, rbx
    jz      @shut_free_ring
    mov     DWORD PTR [rbx].RENDER_CTX.Running, 0

    ; Wait for render thread
    mov     rcx, [rbx].RENDER_CTX.hRenderThread
    test    rcx, rcx
    jz      @shut_no_wait
    mov     edx, 5000                   ; 5 second timeout
    call    WaitForSingleObject
    mov     rcx, [rbx].RENDER_CTX.hRenderThread
    call    CloseHandle
    mov     QWORD PTR [rbx].RENDER_CTX.hRenderThread, 0
@shut_no_wait:

    ; Destroy window resources
    call    SQB_DestroyRenderWnd

    ; Free render context
    mov     rcx, rbx
    xor     edx, edx
    mov     r8d, 8000h
    call    VirtualFree
    mov     g_RenderCtx, 0

@shut_free_ring:
    mov     rbx, g_RingCtx
    test    rbx, rbx
    jz      @shut_cs

    mov     rcx, [rbx].SPSC_RING.pSlotData
    test    rcx, rcx
    jz      @shut_no_blob
    xor     edx, edx
    mov     r8d, 8000h
    call    VirtualFree
@shut_no_blob:

    mov     rcx, [rbx].SPSC_RING.pSlots
    test    rcx, rcx
    jz      @shut_no_slots
    xor     edx, edx
    mov     r8d, 8000h
    call    VirtualFree
@shut_no_slots:

    mov     rcx, rbx
    xor     edx, edx
    mov     r8d, 8000h
    call    VirtualFree
    mov     g_RingCtx, 0

@shut_cs:
    lea     rcx, g_RingCS
    call    DeleteCriticalSection

    mov     g_InitDone, 0

@shut_done:
    xor     eax, eax
    add     rsp, 40
    pop     rbx
    ret
SQB_Shutdown ENDP

; =============================================================================
; SQB_GetFrameStats — Return ring statistics to caller
; RCX = pOut (4 QWORDs: RenderedFrames, DroppedFrames, SlotCount, SlotSize)
; Returns: RAX = 0
; =============================================================================
SQB_GetFrameStats PROC FRAME
    .endprolog
    push    rbx
    sub     rsp, 40

    mov     rbx, g_RingCtx
    test    rbx, rbx
    jz      @stats_zero

    mov     rax, [rbx].SPSC_RING.RenderedFrames
    mov     [rcx], rax
    mov     rax, [rbx].SPSC_RING.DroppedFrames
    mov     [rcx+8], rax
    xor     eax, eax
    mov     eax, [rbx].SPSC_RING.SlotCount
    mov     [rcx+16], rax
    mov     rax, [rbx].SPSC_RING.SlotSize
    mov     [rcx+24], rax
    jmp     @stats_exit

@stats_zero:
    xor     eax, eax
    mov     [rcx], rax
    mov     [rcx+8], rax
    mov     [rcx+16], rax
    mov     [rcx+24], rax

@stats_exit:
    xor     eax, eax
    add     rsp, 40
    pop     rbx
    ret
SQB_GetFrameStats ENDP

; =============================================================================
; SQB_SetTargetFPS — Adjust render thread sleep interval
; RCX = new FPS (clamped 1..240)
; Returns: RAX = actual timer ms
; =============================================================================
SQB_SetTargetFPS PROC FRAME
    .endprolog
    push    rbx
    sub     rsp, 40

    mov     rbx, g_RenderCtx
    test    rbx, rbx
    jz      @fps_fail

    cmp     ecx, 1
    cmovb   ecx, 1
    cmp     ecx, 240
    cmova   ecx, 240

    mov     [rbx].RENDER_CTX.TargetFPS, ecx
    mov     eax, 1000
    xor     edx, edx
    div     ecx

    jmp     @fps_exit

@fps_fail:
    mov     eax, SQB_TIMER_MS

@fps_exit:
    add     rsp, 40
    pop     rbx
    ret
SQB_SetTargetFPS ENDP

; =============================================================================
; End
; =============================================================================
END
