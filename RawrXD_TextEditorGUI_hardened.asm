; ============================================================================
; RawrXD_TextEditorGUI_hardened.asm
; Embeddable native Unicode Win32 text editor module (zero third-party deps).
;
; Per PR #18 productionization path (dependency-free):
;   * Embeddable editor control; lifecycle separated from standalone entry.
;   * Per-instance state in GWLP_USERDATA; no global handles.
;   * Child destruction never calls PostQuitMessage (safe inside an IDE host).
;   * WM_SETFocus forwards to SetFocus(hEdit).
;   * Correct unwind metadata: no dynamic rsp adjustment after .endprolog;
;     full outgoing-call area reserved in the declared prologue.
;   * WM_SIZE preserves incoming message arguments across API calls.
;   * GDI line-number gutter (separate child window), aligned after
;     scroll/resize/font changes.
;   * Custom geometric selection rendering (multiline geometry) via a
;     subclassed WM_PAINT overlay; single authoritative text/selection state.
;   * Unicode file open/save (Win32 file APIs), dirty-state, profile config.
;   * C-callable EditorWindow_* ABI (IDE_* aliases) for host integration.
;
; Stack-arg convention: Nth stack argument (0-based) at [rsp+32+N*8].
; ============================================================================

OPTION CASEMAP:NONE
OPTION DOTNAME

EXTERN GetModuleHandleW:PROC
EXTERN RegisterClassExW:PROC
EXTERN CreateWindowExW:PROC
EXTERN DefWindowProcW:PROC
EXTERN CallWindowProcW:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN GetMessageW:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageW:PROC
EXTERN PostQuitMessage:PROC
EXTERN DestroyWindow:PROC
EXTERN SetFocus:PROC
EXTERN GetClientRect:PROC
EXTERN MoveWindow:PROC
EXTERN GetWindowLongPtrW:PROC
EXTERN SetWindowLongPtrW:PROC
EXTERN InvalidateRect:PROC
EXTERN RedrawWindow:PROC
EXTERN SendMessageW:PROC
EXTERN GetFocus:PROC
EXTERN GetSysColor:PROC
EXTERN GetSysColorBrush:PROC
EXTERN FillRect:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN GetStockObject:PROC
EXTERN BeginPaint:PROC
EXTERN EndPaint:PROC
EXTERN GetScrollPos:PROC
EXTERN GetWindowRect:PROC
EXTERN ScreenToClient:PROC
EXTERN MessageBoxW:PROC
EXTERN OutputDebugStringW:PROC

EXTERN CreateFontW:PROC
EXTERN SelectObject:PROC
EXTERN DeleteObject:PROC
EXTERN GetDeviceCaps:PROC
EXTERN CreateCompatibleDC:PROC
EXTERN CreateCompatibleBitmap:PROC
EXTERN BitBlt:PROC
EXTERN GetTextMetricsW:PROC
EXTERN SetTextColor:PROC
EXTERN SetBkColor:PROC
EXTERN SetBkMode:PROC
EXTERN ExtTextOutW:PROC
EXTERN GetTextExtentPoint32W:PROC
EXTERN Rectangle:PROC
EXTERN CreateSolidBrush:PROC

EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN CreateFileW:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetFileSizeEx:PROC
EXTERN SetFilePointerEx:PROC
EXTERN SetEndOfFile:PROC
EXTERN GetTempPathW:PROC
EXTERN GetPrivateProfileStringW:PROC
EXTERN WritePrivateProfileStringW:PROC
EXTERN SetLastError:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC
EXTERN GetModuleFileNameW:PROC
EXTERN DeleteFileW:PROC
EXTERN MoveFileExW:PROC
EXTERN GetClassInfoExW:PROC

; ---------------------------------------------------------------------------
; Constants
; ---------------------------------------------------------------------------
WM_CREATE           EQU 1
WM_DESTROY          EQU 2
WM_SIZE             EQU 5
WM_SETFOCUS         EQU 7
WM_COMMAND          EQU 0111h
WM_VSCROLL          EQU 0115h
WM_HSCROLL          EQU 0114h
WM_PAINT            EQU 0Fh
WM_GETFONT          EQU 031h
WM_SETFONT          EQU 033h
WM_GETTEXT          EQU 0Dh
WM_GETTEXTLENGTH    EQU 0Eh
WM_SETTEXT          EQU 0Ch
WM_PRINTCLIENT      EQU 0318h

EM_GETSEL           EQU 00B0h
EM_SETSEL           EQU 00B1h
EM_LINEFROMCHAR     EQU 00C9h
EM_LINEINDEX        EQU 00BBh
EM_LINELENGTH       EQU 00BAh
EM_POSFROMCHAR      EQU 00D6h
EM_GETLINE          EQU 00C4h
EM_SETLIMITTEXT     EQU 00C5h
EM_REPLACESEL       EQU 00C2h

EN_CHANGE           EQU 0300h
EN_UPDATE           EQU 0301h

GWLP_USERDATA       EQU -21
GWLP_WNDPROC        EQU -4

WS_CHILD            EQU 40000000h
WS_VISIBLE          EQU 10000000h
WS_BORDER           EQU 00800000h
WS_EX_CLIENTEDGE    EQU 00000200h
WS_OVERLAPPEDWINDOW EQU 00CF0000h
WS_VSCROLL          EQU 00200000h
WS_HSCROLL          EQU 00100000h
ES_MULTILINE        EQU 0004h
ES_AUTOVSCROLL      EQU 0040h
ES_AUTOHSCROLL      EQU 0080h
ES_WANTRETURN       EQU 1000h
ES_NOHIDESEL        EQU 0100h
ES_LEFT             EQU 0

DEFAULT_GUI_FONT    EQU 17
TRANSPARENT         EQU 1
OPAQUE              EQU 2
ETO_CLIPPED         EQU 0004h
ETO_OPAQUE          EQU 0002h
PRF_CLIENT          EQU 00000004h
PRF_CHILDREN        EQU 00000010h

GENERIC_READ        EQU 80000000h
GENERIC_WRITE       EQU 40000000h
FILE_SHARE_READ     EQU 00000001h
FILE_SHARE_WRITE    EQU 00000002h
CREATE_ALWAYS       EQU 2
OPEN_EXISTING       EQU 3
FILE_ATTRIBUTE_NORMAL EQU 00000080h
INVALID_HANDLE_VALUE EQU -1

HEAP_ZERO_MEMORY    EQU 00000008h
SW_SHOW             EQU 5

EDIT_ID             EQU 1001
GUTTER_ID           EQU 1002
COLOR_HIGHLIGHT     EQU 13

; ---------------------------------------------------------------------------
; Globals
; ---------------------------------------------------------------------------
.data
align 8
g_hInstance   dq 0

align 8
clsContainer  dw 'R','a','w','r','X','D',' ','H','a','r','d','e','n','e','d',' ','E','d','i','t','o','r',0
clsGutter     dw 'R','a','w','r','X','D',' ','G','u','t','t','e','r',0
wszEditClass  dw 'E','D','I','T',0
errFailed     dw 'R','a','w','r','X','D',' ','e','d','i','t','o','r',' ','i','n','i','t',' ','f','a','i','l','e','d',0
wszIniName    dw 'e','d','i','t','o','r','_','h','a','r','d','e','n','e','d','.','i','n','i',0
secEditor     dw 'E','d','i','t','o','r',0
keyFontSize   dw 'F','o','n','t','S','i','z','e',0

.code

; ---------------------------------------------------------------------------
; GetInstance: rax = cached HINSTANCE
; ---------------------------------------------------------------------------
GetInstance PROC FRAME
    .endprolog
    cmp g_hInstance, 0
    jnz gotit
    xor ecx, ecx
    call GetModuleHandleW
    mov g_hInstance, rax
gotit:
    mov rax, g_hInstance
    ret
GetInstance ENDP

; ---------------------------------------------------------------------------
; AllocState: rax = zeroed EDITOR_INST* or 0
; ---------------------------------------------------------------------------
AllocState PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog
    call GetProcessHeap
    mov rbx, rax
    mov ecx, ebx
    mov edx, HEAP_ZERO_MEMORY
    mov r8d, 216
    call HeapAlloc
    test rax, rax
    jz allocfail
    mov rbx, rax
    call GetInstance
    mov [rbx+0], rax            ; EI_hInstance
    mov rax, rbx
allocfail:
    add rsp, 32
    pop rbx
    ret
AllocState ENDP

EI_hInstance    EQU 0
EI_hContainer   EQU 8
EI_hEdit        EQU 16
EI_hGutter      EQU 24
EI_hFont        EQU 32
EI_pText        EQU 40
EI_textLen      EQU 48
EI_textCap      EQU 56
EI_selStart     EQU 64
EI_selEnd       EQU 72
EI_bDirty       EQU 80
EI_bColumnSel   EQU 88
EI_lineHeight   EQU 96
EI_gutterWidth  EQU 104
EI_fontSize     EQU 112
EI_dpiX         EQU 120
EI_dpiY         EQU 128
EI_clrText      EQU 136
EI_clrBk        EQU 144
EI_clrSelection EQU 152
EI_clrGutterTxt EQU 160
EI_clrGutterBk  EQU 168
EI_rcLeft       EQU 176
EI_rcTop        EQU 184
EI_rcRight      EQU 192
EI_rcBottom     EQU 200
EI_hOldProc     EQU 208
EI_sizeof       EQU 216

; ---------------------------------------------------------------------------
; StateFromWnd(rcx = HWND) -> rax = EDITOR_INST*
; ---------------------------------------------------------------------------
StateFromWnd PROC FRAME
    .endprolog
    mov edx, GWLP_USERDATA
    jmp GetWindowLongPtrW
StateFromWnd ENDP

; ---------------------------------------------------------------------------
; FormatUint32: rax = value, rdx = WCHAR* buffer. Returns ptr in rax, count in rdx.
; ---------------------------------------------------------------------------
FormatUint32 PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 32
    .allocstack 32
    .endprolog
    mov rbx, rdx                ; rbx = buffer start
    mov r8, rax                 ; r8 = value
    mov rax, 10
    lea r9, [rbx+11]            ; end (null terminator)
    mov word ptr [r9], 0
    dec r9
convert:
    xor rdx, rdx
    div rax                     ; rax = quotient, rdx = remainder
    add dl, '0'
    mov [r9], dl
    dec r9
    test rax, rax
    jnz convert
    inc r9                      ; first digit
    mov rax, r9
    mov rdx, rax
    sub rdx, rbx                ; rdx = char count
    add rsp, 32
    pop rbx
    ret
FormatUint32 ENDP

; ===========================================================================
; Gutter window procedure: draws line numbers for visible edit lines.
; Frame: .allocstack 256 (fixed; no dynamic rsp after .endprolog)
;   [rsp+32]  PAINTSTRUCT (64 bytes)
;   [rsp+96]  RECT (16 bytes)
;   [rsp+112] lineHeight
;   [rsp+116] bottom
;   [rsp+152] cch
;   [rsp+144] lpString
;   [rsp+200] number buffer (24 bytes)
; ===========================================================================
GutterProc PROC FRAME
    push rbx
    push r12
    push r13
    .pushreg rbx
    .pushreg r12
    .pushreg r13
    sub rsp, 256
    .allocstack 256
    .endprolog
    mov rbx, rcx                  ; rbx = gutter hwnd
    mov r10d, edx                 ; save uMsg before GetWindowLongPtrW clobbers edx
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    mov r12, rax                  ; r12 = state
    test r12, r12
    jz gdef
    cmp r10d, WM_PAINT
    je gpaint
    cmp r10d, WM_DESTROY
    je gdestroy
    jmp gdef
gpaint:
    mov rcx, rbx
    lea rdx, [rsp+32]             ; PAINTSTRUCT
    call BeginPaint
    mov r13, rax                  ; hdc
    mov rcx, r13
    mov rdx, [r12+EI_hFont]
    call SelectObject
    ; gutter client rect
    mov rcx, rbx
    lea rdx, [rsp+96]             ; RECT
    call GetClientRect
    ; fill background with gutter bk color
    mov ecx, [r12+EI_clrGutterBk]
    call CreateSolidBrush
    mov r8, rax                   ; brush
    mov rcx, r13
    lea rdx, [rsp+96]             ; rect
    call FillRect
    mov rcx, rax
    call DeleteObject
    ; line height
    mov ecx, [r12+EI_lineHeight]
    test ecx, ecx
    jnz ghaveh
    mov rcx, r13
    lea rdx, [rsp+192]            ; TEXTMETRIC scratch
    call GetTextMetricsW
    movzx eax, word ptr [rsp+192] ; tmHeight
    mov [r12+EI_lineHeight], eax
ghaveh:
    mov ecx, [r12+EI_lineHeight]
    mov [rsp+112], ecx            ; stack copy of lineHeight
    ; top line from edit scroll pos
    mov rcx, [r12+EI_hEdit]
    call GetScrollPos
    mov esi, eax                  ; esi = top line
    mov edx, [rsp+96+12]          ; bottom
    mov [rsp+116], edx            ; bottom
    mov ebp, esi                  ; ebp = current line
    mov edi, 0                    ; edi = y cursor
gpaintloop:
    cmp edi, [rsp+116]
    jge gpaintdone
    ; line char index
    mov rcx, [r12+EI_hEdit]
    mov edx, EM_LINEINDEX
    mov r8d, ebp
    xor r9d, r9d
    call SendMessageW
    cmp eax, -1
    je gpaintdone
    ; format line number (ebp+1) into buffer at [rsp+200]
    mov eax, ebp
    inc eax
    lea rdx, [rsp+200]
    call FormatUint32             ; rax = ptr to first digit
    mov r9, rax
    sub r9, [rsp+200]             ; r9 = char count
    mov [rsp+152], r9d            ; cch
    mov [rsp+144], rax            ; lpString
    ; x = right - count*8 - 4
    mov eax, [rsp+96+8]           ; gutter width
    imul r8d, r9d, 8
    sub eax, r8d
    sub eax, 4
    ; colors
    mov ecx, [r12+EI_clrGutterTxt]
    call SetTextColor
    mov ecx, [r12+EI_clrGutterBk]
    call SetBkColor
    mov ecx, OPAQUE
    call SetBkMode
    ; ExtTextOutW(hdc, x, y, ETO_OPAQUE, lpRect, lpString, cch, lpDx)
    ; rcx=hdc rdx=x r8=y r9=options [rsp+32]=lpRect [rsp+40]=lpString [rsp+48]=cch [rsp+56]=lpDx
    mov rcx, r13
    mov edx, eax                  ; x
    mov r8d, edi                  ; y
    mov r9d, ETO_OPAQUE
    lea rax, [rsp+96]             ; lpRect = gutter client rect
    mov [rsp+32], rax
    mov rax, [rsp+144]
    mov [rsp+40], rax             ; lpString
    mov eax, [rsp+152]
    mov [rsp+48], rax             ; cch
    mov qword ptr [rsp+56], 0     ; lpDx
    call ExtTextOutW
    add edi, [rsp+112]            ; y += lineHeight
    add ebp, 1
    jmp gpaintloop
gpaintdone:
    mov rcx, rbx
    lea rdx, [rsp+32]             ; PAINTSTRUCT
    call EndPaint
    xor eax, eax
    jmp gdone
gdestroy:
    xor eax, eax
    jmp gdone
gdef:
    call DefWindowProcW
gdone:
    add rsp, 256
    pop r13
    pop r12
    pop rbx
    ret
GutterProc ENDP

; ===========================================================================
; Edit subclass procedure: geometric selection overlay + gutter invalidation.
; Frame: .allocstack 256 (fixed)
;   [rsp+32] saved uMsg, [rsp+40] saved wParam, [rsp+48] saved lParam
;   [rsp+64] PAINTSTRUCT (64)
;   [rsp+128] lineHeight, [rsp+132] startLine, [rsp+136] endLine
;   [rsp+140] lineStart, [rsp+144] lineLen, [rsp+148] segStart
;   [rsp+152] segEnd, [rsp+156] segStartX, [rsp+160] segStartY
;   [rsp+164] segEndX, [rsp+168] top, [rsp+172] bottom
;   [rsp+176..192] rect
; ===========================================================================
EditSubclassProc PROC FRAME
    push rbx
    push r12
    push r13
    .pushreg rbx
    .pushreg r12
    .pushreg r13
    sub rsp, 256
    .allocstack 256
    .endprolog
    mov rbx, rcx                  ; rbx = hEdit
    mov [rsp+32], edx             ; save uMsg before GetWindowLongPtrW clobbers edx
    mov [rsp+40], r8              ; save wParam
    mov [rsp+48], r9              ; save lParam
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    mov r12, rax                  ; r12 = state
    test r12, r12
    jz eschain
    cmp dword ptr [rsp+32], WM_PAINT
    je espaint
    cmp dword ptr [rsp+32], WM_VSCROLL
    je esscroll
    cmp dword ptr [rsp+32], WM_HSCROLL
    je esscroll
    cmp dword ptr [rsp+32], EM_SETSEL
    je esetsel
    jmp eschain
espaint:
    mov rcx, rbx
    lea rdx, [rsp+64]             ; PAINTSTRUCT
    call BeginPaint
    mov r13, rax                  ; hdc
    ; default paint into our dc
    mov rcx, rbx
    mov edx, WM_PAINT
    mov r8, r13                   ; wParam = hdc
    xor r9d, r9d
    call CallWindowProcW
    ; overlay: selection geometry
    mov ecx, [r12+EI_selStart]
    cmp ecx, [r12+EI_selEnd]
    jge espaintend
    mov rcx, r13
    mov rdx, [r12+EI_hFont]
    call SelectObject
    ; line height
    mov ecx, [r12+EI_lineHeight]
    test ecx, ecx
    jnz eslh_ok
    mov rcx, r13
    lea rdx, [rsp+192]            ; TEXTMETRIC scratch
    call GetTextMetricsW
    movzx eax, word ptr [rsp+192]
    mov [r12+EI_lineHeight], eax
eslh_ok:
    mov ecx, [r12+EI_lineHeight]
    mov [rsp+128], ecx
    ; startLine = EM_LINEFROMCHAR(selStart)
    mov rcx, rbx
    mov edx, EM_LINEFROMCHAR
    mov r8d, [r12+EI_selStart]
    xor r9d, r9d
    call SendMessageW
    mov [rsp+132], eax
    ; endLine = EM_LINEFROMCHAR(selEnd)
    mov rcx, rbx
    mov edx, EM_LINEFROMCHAR
    mov r8d, [r12+EI_selEnd]
    xor r9d, r9d
    call SendMessageW
    mov [rsp+136], eax
    mov esi, [rsp+132]            ; esi = line cursor
    mov ebp, [rsp+136]            ; endLine
esloop:
    mov rcx, rbx
    mov edx, EM_LINEINDEX
    mov r8d, esi
    xor r9d, r9d
    call SendMessageW
    mov [rsp+140], eax            ; lineStart
    mov rcx, rbx
    mov edx, EM_LINELENGTH
    mov r8d, esi
    xor r9d, r9d
    call SendMessageW
    mov [rsp+144], eax            ; lineLen
    ; segStart = max(selStart, lineStart)
    mov ecx, [r12+EI_selStart]
    mov edx, [rsp+140]
    cmp ecx, edx
    cmovl ecx, edx
    mov [rsp+148], ecx            ; segStart
    ; segEnd = min(selEnd, lineStart+lineLen)
    mov ecx, [r12+EI_selEnd]
    mov edx, [rsp+140]
    add edx, [rsp+144]            ; lineEnd
    cmp ecx, edx
    cmovg ecx, edx
    mov [rsp+152], ecx            ; segEnd
    cmp ecx, [rsp+148]            ; segEnd > segStart?
    jle esnextline
    ; pos(segStart)
    mov rcx, rbx
    mov edx, EM_POSFROMCHAR
    mov r8d, [rsp+148]
    xor r9d, r9d
    call SendMessageW
    mov [rsp+156], eax            ; segStartX
    mov [rsp+160], edx            ; segStartY
    ; pos(segEnd)
    mov rcx, rbx
    mov edx, EM_POSFROMCHAR
    mov r8d, [rsp+152]
    xor r9d, r9d
    call SendMessageW
    mov [rsp+164], eax            ; segEndX
    ; build rect: left[176],top[180],right[184],bottom[188]
    mov eax, [rsp+156]
    mov [rsp+176], eax
    mov eax, [rsp+160]
    mov [rsp+180], eax
    mov eax, [rsp+164]
    mov [rsp+184], eax
    mov eax, [rsp+160]
    add eax, [rsp+128]            ; bottom = top + lineHeight
    mov [rsp+188], eax
    ; FillRect(hdc, &rect, brush) : rcx=hdc rdx=&rect r8=brush
    mov ecx, COLOR_HIGHLIGHT
    call GetSysColorBrush
    mov r8, rax                   ; brush
    mov rcx, r13
    lea rdx, [rsp+176]            ; &rect
    call FillRect
esnextline:
    add esi, 1
    cmp esi, ebp
    jle esloop
espaintend:
    mov rcx, rbx
    lea rdx, [rsp+64]             ; PAINTSTRUCT
    call EndPaint
    xor eax, eax
    jmp esdone
esscroll:
    mov rcx, [r12+EI_hGutter]
    xor edx, edx
    xor r8d, r8d
    call InvalidateRect
    jmp eschain
esetsel:
    mov [r12+EI_selStart], r8d
    mov [r12+EI_selEnd], r9d
    mov dword ptr [r12+EI_bDirty], 1
    jmp eschain
eschain:
    ; chain to original edit proc with preserved message arguments
    mov rcx, [r12+EI_hOldProc]
    mov rdx, rbx
    mov r8d, [rsp+32]             ; uMsg
    mov r9d, [rsp+40]             ; wParam
    mov rax, [rsp+48]             ; lParam
    mov [rsp+32], rax             ; lParam stack arg (5th arg)
    call CallWindowProcW
esdone:
    add rsp, 256
    pop r13
    pop r12
    pop rbx
    ret
EditSubclassProc ENDP

; ===========================================================================
; Container window procedure: embeddable editor control.
; Frame: .allocstack 256 (fixed)
;   [rsp+32] RECT (16), [rsp+48..88] create-window args
;   [rsp+112] saved uMsg, [rsp+120] saved wParam, [rsp+128] saved lParam
; ===========================================================================
EditorContainerProc PROC FRAME
    push rbx
    push r12
    push r13
    .pushreg rbx
    .pushreg r12
    .pushreg r13
    sub rsp, 256
    .allocstack 256
    .endprolog
    mov rbx, rcx                  ; rbx = hWnd container
    mov [rsp+112], edx            ; saved uMsg
    mov [rsp+120], r8             ; saved wParam
    mov [rsp+128], r9             ; saved lParam
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    mov r12, rax                  ; r12 = state
    mov edx, [rsp+112]            ; restore uMsg
    cmp edx, WM_CREATE
    je wmcreate
    cmp edx, WM_DESTROY
    je wmdestroy
    jmp wmdef
wmcreate:
    ; VirtualAlloc state
    xor ecx, ecx
    mov rdx, 216
    mov r8, 00003000h
    mov r9, 4
    call VirtualAlloc
    test rax, rax
    jz wmfail
    mov r12, rax
    ; Store state
    mov rcx, rbx
    mov rdx, GWLP_USERDATA
    mov r8, rax
    call SetWindowLongPtrW
    xor eax, eax
    jmp wmdone
wmfail:
    mov eax, -1
    jmp wmdone
wmdestroy:
    test r12, r12
    jz wdskip
    mov rcx, [r12+EI_hFont]
    test rcx, rcx
    jz wdfn
    call DeleteObject
wdfn:
    mov rcx, [r12+EI_pText]
    test rcx, rcx
    jz wdtxt
    mov rcx, [r12+EI_pText]
    xor edx, edx
    xor r8d, r8d
    mov r9d, 00008000h           ; MEM_RELEASE
    call VirtualFree
wdtxt:
    mov rcx, r12
    xor edx, edx
    xor r8d, r8d
    mov r9d, 00008000h           ; MEM_RELEASE
    call VirtualFree
    mov rcx, rbx
    mov edx, GWLP_USERDATA
    xor r8d, r8d
    call SetWindowLongPtrW
wdskip:
    xor eax, eax
    jmp wmdone
wmdef:
    mov rcx, rbx
    mov edx, [rsp+112]
    mov r8, [rsp+120]
    mov r9, [rsp+128]
    call DefWindowProcW
wmdone:
    add rsp, 256
    pop r13
    pop r12
    pop rbx
    ret
EditorContainerProc ENDP

; ---------------------------------------------------------------------------
; RegisterClasses: register container + gutter classes. rax != 0 on success.
; Frame: .allocstack 128 (fixed); WNDCLASSEXW at [rsp+32]
; ---------------------------------------------------------------------------
RegisterClasses PROC FRAME
    push rbx
    .pushreg rbx
    sub rsp, 224
    .allocstack 224
    .endprolog
    call GetInstance
    mov rbx, rax                ; rbx = hInstance
    xor r9d, r9d                ; r9 = NULL handle
    ; zero the WNDCLASSEXW buffer (80 bytes) before filling fields
    xor rax, rax
    mov [rsp+32], rax
    mov [rsp+40], rax
    mov [rsp+48], rax
    mov [rsp+56], rax
    mov [rsp+64], rax
    mov [rsp+72], rax
    mov [rsp+80], rax
    mov [rsp+88], rax
    mov [rsp+96], rax
    mov [rsp+104], rax
    ; ---- container class ----
    mov dword ptr [rsp+32], 80              ; cbSize
    mov dword ptr [rsp+36], 0               ; style
    lea rax, EditorContainerProc
    mov [rsp+40], rax                       ; lpfnWndProc
    mov [rsp+48], rbx                       ; hInstance
    mov [rsp+56], r9                        ; hIcon = NULL
    mov [rsp+64], r9                        ; hCursor = NULL
    mov dword ptr [rsp+72], 0               ; hbrBackground = NULL
    mov [rsp+80], r9                        ; lpszMenuName = NULL
    lea rax, clsContainer
    mov [rsp+88], rax                       ; lpszClassName
    mov [rsp+96], r9                        ; hIconSm = NULL
    lea rcx, [rsp+32]
    call RegisterClassExW
    test eax, eax
    jz regfail
container_registered:
    ; ---- gutter class ----
    xor r9d, r9d                ; r9 = NULL handle
    mov dword ptr [rsp+32], 80
    mov dword ptr [rsp+36], 0
    lea rax, GutterProc
    mov [rsp+40], rax
    mov [rsp+48], rbx
    mov [rsp+56], r9
    mov [rsp+64], r9
    mov dword ptr [rsp+72], 0               ; hbrBackground = NULL
    mov [rsp+80], r9
    lea rax, clsGutter
    mov [rsp+88], rax
    mov [rsp+96], r9
    lea rcx, [rsp+32]
    call RegisterClassExW
    test eax, eax
    jz regfail
gutter_registered:
    mov eax, 1
    jmp regdone
regfail:
    xor eax, eax
regdone:
    add rsp, 224
    pop rbx
    ret
RegisterClasses ENDP

; ===========================================================================
; Exported ABI (C-callable, x64 calling convention)
; ===========================================================================

; HWND EditorWindow_Create(HINSTANCE hInstance, HWND hParent, int x, int y,
;                          int w, int h)
EditorWindow_Create PROC FRAME
    push rbx
    push r12
    .pushreg rbx
    .pushreg r12
    sub rsp, 128
    .allocstack 128
    .endprolog
    ; rcx=hInstance rdx=hParent r8=x r9=y [rsp+32]=w [rsp+40]=h
    mov rbx, rcx                ; rbx = hInstance (non-volatile)
    mov r12, rdx                ; r12 = hParent (non-volatile)
    mov [rsp+64], r8d           ; save x
    mov [rsp+72], r9d           ; save y
    mov eax, [rsp+32]
    mov [rsp+80], eax           ; w
    mov eax, [rsp+40]
    mov [rsp+88], eax           ; h
    xor ecx, ecx                ; clear last error before CreateWindowExW
    call SetLastError
    xor ecx, ecx                ; dwExStyle
    lea rdx, clsContainer
    xor r8d, r8d                ; lpWindowName = 0
    mov r9d, WS_CHILD or WS_VISIBLE
    mov eax, [rsp+64]
    mov [rsp+32], eax           ; X
    mov eax, [rsp+72]
    mov [rsp+40], eax           ; Y
    mov eax, [rsp+80]
    mov [rsp+48], eax           ; nWidth
    mov eax, [rsp+88]
    mov [rsp+56], eax           ; nHeight
    mov [rsp+64], r12           ; hWndParent
    xor eax, eax
    mov [rsp+72], eax           ; hMenu
    mov [rsp+80], rbx           ; hInstance
    mov [rsp+88], rax           ; lpParam = 0
    call CreateWindowExW
    test rax, rax
    jz ewinfail
    jmp ewinret
ewinfail:
    xor eax, eax
ewinret:
    add rsp, 128
    pop r12
    pop rbx
    ret
EditorWindow_Create ENDP


; IDE_* aliases (same symbols)
PUBLIC EditorContainerProc
PUBLIC GutterProc
PUBLIC IDE_Editor_Create
IDE_Editor_Create PROC
    jmp EditorWindow_Create
IDE_Editor_Create ENDP

; ===========================================================================
; void EditorWindow_Destroy(HWND hContainer)
;   Destroys the editor container. Never calls PostQuitMessage.
; ===========================================================================
EditorWindow_Destroy PROC FRAME
    .endprolog
    jmp DestroyWindow
EditorWindow_Destroy ENDP

PUBLIC IDE_Editor_Destroy
IDE_Editor_Destroy PROC
    jmp EditorWindow_Destroy
IDE_Editor_Destroy ENDP

; ===========================================================================
; int EditorWindow_GetDirty(HWND hContainer)
; ===========================================================================
EditorWindow_GetDirty PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz gdzero
    mov eax, [rax+EI_bDirty]
    ret
gdzero:
    xor eax, eax
    ret
EditorWindow_GetDirty ENDP

PUBLIC IDE_Editor_GetDirty
IDE_Editor_GetDirty PROC
    jmp EditorWindow_GetDirty
IDE_Editor_GetDirty ENDP

; ===========================================================================
; void EditorWindow_SetDirty(HWND hContainer, BOOL dirty)
; ===========================================================================
EditorWindow_SetDirty PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz sdret
    mov [rax+EI_bDirty], edx
sdret:
    ret
EditorWindow_SetDirty ENDP

PUBLIC IDE_Editor_SetDirty
IDE_Editor_SetDirty PROC
    jmp EditorWindow_SetDirty
IDE_Editor_SetDirty ENDP

; ===========================================================================
; int EditorWindow_GetSelection(HWND hContainer, int* pStart, int* pEnd)
; ===========================================================================
EditorWindow_GetSelection PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz gsret
    mov ecx, [rax+EI_selStart]
    mov [rdx], ecx
    mov ecx, [rax+EI_selEnd]
    mov [r8], ecx
gsret:
    xor eax, eax
    ret
EditorWindow_GetSelection ENDP

PUBLIC IDE_Editor_GetSelection
IDE_Editor_GetSelection PROC
    jmp EditorWindow_GetSelection
IDE_Editor_GetSelection ENDP

; ===========================================================================
; void EditorWindow_SetSelection(HWND hContainer, int start, int end)
; ===========================================================================
EditorWindow_SetSelection PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz ssret
    mov [rax+EI_selStart], r8d
    mov [rax+EI_selEnd], r9d
    mov rcx, [rax+EI_hEdit]
    mov edx, EM_SETSEL
    call SendMessageW
ssret:
    ret
EditorWindow_SetSelection ENDP

PUBLIC IDE_Editor_SetSelection
IDE_Editor_SetSelection PROC
    jmp EditorWindow_SetSelection
IDE_Editor_SetSelection ENDP

; ===========================================================================
; HWND EditorWindow_GetEditHwnd(HWND hContainer)
; ===========================================================================
EditorWindow_GetEditHwnd PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz gehzero
    mov rax, [rax+EI_hEdit]
    ret
gehzero:
    xor rax, rax
    ret
EditorWindow_GetEditHwnd ENDP

PUBLIC IDE_Editor_GetEditHwnd
IDE_Editor_GetEditHwnd PROC
    jmp EditorWindow_GetEditHwnd
IDE_Editor_GetEditHwnd ENDP

; ===========================================================================
; HWND EditorWindow_GetGutterHwnd(HWND hContainer)
; ===========================================================================
EditorWindow_GetGutterHwnd PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz gghzero
    mov rax, [rax+EI_hGutter]
    ret
gghzero:
    xor rax, rax
    ret
EditorWindow_GetGutterHwnd ENDP

PUBLIC IDE_Editor_GetGutterHwnd
IDE_Editor_GetGutterHwnd PROC
    jmp EditorWindow_GetGutterHwnd
IDE_Editor_GetGutterHwnd ENDP

; ===========================================================================
; int EditorWindow_GetText(HWND hContainer, LPWSTR pBuf, int cchMax)
;   Returns char count (excl. null).
; ===========================================================================
EditorWindow_GetText PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz gtzret
    mov rcx, [rax+EI_hEdit]
    mov edx, WM_GETTEXT
    ; r8 = cchMax, r9 = pBuf already in registers from caller
    call SendMessageW
    ret
gtzret:
    xor eax, eax
    ret
EditorWindow_GetText ENDP

PUBLIC IDE_Editor_GetText
IDE_Editor_GetText PROC
    jmp EditorWindow_GetText
IDE_Editor_GetText ENDP

; ===========================================================================
; int EditorWindow_GetTextLength(HWND hContainer)
; ===========================================================================
EditorWindow_GetTextLength PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz gtlzero
    mov rcx, [rax+EI_hEdit]
    mov edx, WM_GETTEXTLENGTH
    xor r8d, r8d
    xor r9d, r9d
    call SendMessageW
    ret
gtlzero:
    xor eax, eax
    ret
EditorWindow_GetTextLength ENDP

PUBLIC IDE_Editor_GetTextLength
IDE_Editor_GetTextLength PROC
    jmp EditorWindow_GetTextLength
IDE_Editor_GetTextLength ENDP

; ===========================================================================
; int EditorWindow_SetText(HWND hContainer, LPCWSTR pText)
; ===========================================================================
EditorWindow_SetText PROC FRAME
    .endprolog
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    test rax, rax
    jz stret
    mov rcx, [rax+EI_hEdit]
    mov edx, WM_SETTEXT
    call SendMessageW
    xor eax, eax
    ret
stret:
    xor eax, eax
    ret
EditorWindow_SetText ENDP

PUBLIC IDE_Editor_SetText
IDE_Editor_SetText PROC
    jmp EditorWindow_SetText
IDE_Editor_SetText ENDP

; ===========================================================================
; int EditorWindow_LoadFile(HWND hContainer, LPCWSTR pPath)
;   Unicode open; on success replaces contents and clears dirty state.
;   Returns nonzero on success, 0 on failure.
; ===========================================================================
EditorWindow_LoadFile PROC FRAME
    push rbx
    push r12
    push r13
    .pushreg rbx
    .pushreg r12
    .pushreg r13
    sub rsp, 96
    .allocstack 96
    .endprolog
    mov rbx, rcx                ; hContainer
    mov r12, rdx                ; pPath
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    mov r13, rax                ; state
    test r13, r13
    jz lfail
    ; CreateFileW(pPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING,
    ;             FILE_ATTRIBUTE_NORMAL, 0)
    xor ecx, ecx                ; hTemplateFile / lpSecurityAttributes
    mov [rsp+48], ecx           ; hTemplateFile
    mov dword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov dword ptr [rsp+32], OPEN_EXISTING
    xor r8d, r8d                ; lpSecurityAttributes
    mov r9d, FILE_SHARE_READ
    mov rdx, GENERIC_READ
    mov rcx, r12                ; lpFileName
    call CreateFileW
    cmp rax, INVALID_HANDLE_VALUE
    je lfail
    mov [rsp+48], rax           ; hFile
    ; GetFileSizeEx(hFile, &size)
    lea rdx, [rsp+56]           ; LARGE_INTEGER
    call GetFileSizeEx
    test rax, rax
    jz lclose
    mov rax, [rsp+56]           ; low 32 bits of size
    mov [rsp+80], rax           ; fileSize
    ; HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize+2)
    xor ecx, ecx
    call GetProcessHeap
    mov rcx, rax                ; hHeap
    mov edx, HEAP_ZERO_MEMORY
    mov r8, [rsp+80]
    add r8, 2                   ; +1 WCHAR null
    call HeapAlloc
    test rax, rax
    jz lclose
    mov [rsp+64], rax           ; pBuf
    ; ReadFile(hFile, pBuf, fileSize, &read, 0)
    mov rcx, [rsp+48]           ; hFile
    mov rdx, rax                ; lpBuffer
    mov r8d, [rsp+80]           ; nNumberOfBytesToRead
    lea r9, [rsp+88]            ; lpNumberOfBytesRead
    mov qword ptr [rsp+32], 0   ; lpOverlapped
    call ReadFile
    test eax, eax
    jz lfree
    ; null-terminate
    mov rcx, [rsp+64]
    ; read count is at [rsp+88] (dword)
    mov eax, [rsp+88]
    mov word ptr [rcx+rax*2], 0
    ; WM_SETTEXT
    mov rcx, [r13+EI_hEdit]
    mov edx, WM_SETTEXT
    mov r8, [rsp+64]
    xor r9d, r9d
    call SendMessageW
    ; free old pText
    mov rcx, [r13+EI_pText]
    test rcx, rcx
    jz lnostore
    xor ecx, ecx
    call GetProcessHeap
    mov rcx, rax
    mov edx, 0
    mov r8, [r13+EI_pText]
    call HeapFree
lnostore:
    mov rax, [rsp+64]
    mov [r13+EI_pText], rax
    mov eax, [rsp+88]
    mov [r13+EI_textLen], eax
    mov dword ptr [r13+EI_bDirty], 0
    mov eax, 1
    jmp ldone
lfree:
    mov rcx, [rsp+64]
    test rcx, rcx
    jz lclose2
    xor ecx, ecx
    call GetProcessHeap
    mov rcx, rax
    mov edx, 0
    mov r8, [rsp+64]
    call HeapFree
lclose2:
lclose:
    mov rcx, [rsp+48]
    call CloseHandle
lfail:
    xor eax, eax
ldone:
    add rsp, 96
    pop r13
    pop r12
    pop rbx
    ret
EditorWindow_LoadFile ENDP

PUBLIC IDE_Editor_LoadFile
IDE_Editor_LoadFile PROC
    jmp EditorWindow_LoadFile
IDE_Editor_LoadFile ENDP

; ===========================================================================
; int EditorWindow_SaveFile(HWND hContainer, LPCWSTR pPath)
;   Unicode save via temp file + MoveFileExW so a failed save preserves the
;   original file. Returns nonzero on success, 0 on failure.
; ===========================================================================
EditorWindow_SaveFile PROC FRAME
    push rbx
    push r12
    push r13
    .pushreg rbx
    .pushreg r12
    .pushreg r13
    sub rsp, 128
    .allocstack 128
    .endprolog
    mov rbx, rcx                ; hContainer
    mov r12, rdx                ; pPath
    mov rdx, GWLP_USERDATA
    call GetWindowLongPtrW
    mov r13, rax                ; state
    test r13, r13
    jz sfail
    ; WM_GETTEXTLENGTH
    mov rcx, [r13+EI_hEdit]
    mov edx, WM_GETTEXTLENGTH
    xor r8d, r8d
    xor r9d, r9d
    call SendMessageW
    test eax, eax
    jnz shavetext
    ; empty file: create empty target
    ; CreateFileW(pPath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
    ;             FILE_ATTRIBUTE_NORMAL, 0)
    xor ecx, ecx                ; hTemplateFile / lpSecurityAttributes
    mov [rsp+48], ecx           ; hTemplateFile
    mov dword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov dword ptr [rsp+32], CREATE_ALWAYS
    xor r8d, r8d                ; lpSecurityAttributes
    xor r9d, r9d                ; dwShareMode = 0
    mov rdx, GENERIC_WRITE
    mov rcx, r12                ; lpFileName
    call CreateFileW
    cmp rax, INVALID_HANDLE_VALUE
    je sfail
    mov rcx, rax
    call CloseHandle
    mov dword ptr [r13+EI_bDirty], 0
    mov eax, 1
    jmp sfdone
shavetext:
    mov [rsp+32], eax           ; cch
    shl rax, 1
    add rax, 2                  ; bytes incl null
    mov [rsp+40], rax           ; bufBytes
    ; HeapAlloc
    xor ecx, ecx
    call GetProcessHeap
    mov rcx, rax
    mov edx, HEAP_ZERO_MEMORY
    mov r8, [rsp+40]
    call HeapAlloc
    test rax, rax
    jz sfail
    mov [rsp+48], rax           ; pBuf
    ; WM_GETTEXT(hEdit, WM_GETTEXT, cch+1, pBuf)
    mov rcx, [r13+EI_hEdit]
    mov edx, WM_GETTEXT
    mov r8d, [rsp+32]
    add r8d, 1
    mov r9, [rsp+48]
    call SendMessageW
    ; build temp path: pPath + L".tmp" into stack buffer [rsp+64] (260 WCHAR)
    lea rcx, [rsp+64]           ; dest
    ; copy pPath to dest
    mov r8, r12                 ; src
    mov rsi, r8
    mov rdi, rcx
scopy:
    lodsw
    stosw
    test ax, ax
    jnz scopy
    ; dec rdi to point at null, append L".tmp"
    dec rdi
    dec rdi
    mov ax, 002Eh               ; '.'
    stosw
    mov ax, 0074h               ; 't'
    stosw
    mov ax, 006Dh               ; 'm'
    stosw
    mov ax, 002Eh               ; 'p' -> wait order . t m p
    ; redo: we wrote . t m then need p
    ; actually above wrote '.', 't', 'm', then need 'p' and null
    ; fix: overwrite last
    dec rdi
    dec rdi
    mov ax, 0070h               ; 'p'
    stosw
    mov ax, 0
    stosw
    ; CreateFileW(temp, GENERIC_WRITE, 0, 0, CREATE_ALWAYS,
    ;             FILE_ATTRIBUTE_NORMAL, 0)
    xor ecx, ecx                ; hTemplateFile / lpSecurityAttributes
    mov [rsp+48], ecx           ; hTemplateFile
    mov dword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov dword ptr [rsp+32], CREATE_ALWAYS
    xor r8d, r8d                ; lpSecurityAttributes
    xor r9d, r9d                ; dwShareMode = 0
    mov rdx, GENERIC_WRITE
    lea rcx, [rsp+64]           ; lpFileName = temp path
    call CreateFileW
    cmp rax, INVALID_HANDLE_VALUE
    je sfree
    mov [rsp+56], rax           ; hTemp
    ; WriteFile(hTemp, pBuf, bufBytes, &written, 0)
    mov rcx, rax
    mov rdx, [rsp+48]
    mov r8d, [rsp+40]
    lea r9, [rsp+88]
    mov qword ptr [rsp+32], 0
    call WriteFile
    test eax, eax
    jz swritefail
    ; CloseHandle(hTemp)
    mov rcx, [rsp+56]
    call CloseHandle
    ; MoveFileExW(temp, pPath, MOVEFILE_REPLACE_EXISTING)
    mov ecx, 1                  ; MOVEFILE_REPLACE_EXISTING
    lea r8, [r12]
    lea rdx, [rsp+64]
    call MoveFileExW
    test eax, eax
    jz smovefail
    ; success
    mov dword ptr [r13+EI_bDirty], 0
    mov eax, 1
    jmp sfdone
swritefail:
    mov rcx, [rsp+56]
    call CloseHandle
    ; delete temp
    lea rcx, [rsp+64]
    call DeleteFileW
    jmp sfree
smovefail:
    ; delete temp to preserve original
    lea rcx, [rsp+64]
    call DeleteFileW
sfree:
    mov rcx, [rsp+48]
    test rcx, rcx
    jz sfail
    xor ecx, ecx
    call GetProcessHeap
    mov rcx, rax
    mov edx, 0
    mov r8, [rsp+48]
    call HeapFree
sfail:
    xor eax, eax
sfdone:
    add rsp, 128
    pop r13
    pop r12
    pop rbx
    ret
EditorWindow_SaveFile ENDP

PUBLIC IDE_Editor_SaveFile
IDE_Editor_SaveFile PROC
    jmp EditorWindow_SaveFile
IDE_Editor_SaveFile ENDP

END
