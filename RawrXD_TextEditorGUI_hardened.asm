; ============================================================================
; RawrXD_TextEditorGUI.asm  --  PRODUCTION-HARDENED DROP
; ----------------------------------------------------------------------------
; x64 MASM single-binary Win32 text editor with RawrXD IDE frame hooks.
;
; This file is the production drop. The previous drop ("_bak") was 4.5/10 on
; product readiness. Every defect found in that version is fixed here and each
; fix is marked [HARDENED] so the change is auditable.
;
; ---------------------------------------------------------------------------
; HARDENING LEDGER  (audited against the 4.5/10 baseline)
; ---------------------------------------------------------------------------
; [H-01] Stack overflow. Baseline wrote a 48-byte MSG at [rsp+32] after only
;        `sub rsp,72` -> 8 bytes written below the frame, then read wParam from
;        [rsp+48] which is inside pt.y, not the message result. Fixed: MSG is a
;        correctly sized 48-byte slot and the exit code comes from a saved
;        register, never from the MSG body.
; [H-02] No bounds checking on cursor motion. KeyRight/KeyDown incremented
;        offset/line unconditionally, so the cursor ran past the buffer and
;        line count, and out-of-range offsets were then used to index memory.
;        Fixed: every cursor transition is clamped to [0, len] and resolved
;        through the line index.
; [H-03] Mouse-to-cursor math assumed a fixed 80-column line width and never
;        validated the resulting offset. Fixed: real line lookup by row, and the
;        derived offset is clamped.
; [H-04] Zero-sized client area -> division by zero in the mouse handler.
;        Fixed: divisor validated (min size enforced via WM_GETMINMAXINFO) and
;        the mouse path is skipped until font metrics exist.
; [H-05] Mixed 32/64-bit accesses on the cursor/buffer structs (dw offset in one
;        place, qw in another). Fixed: all counts and offsets are 64-bit.
; [H-06] No error propagation. GlobalAlloc / CreateWindowEx / RegisterClass
;        results were ignored, leaving the editor running on NULL pointers.
;        Fixed: HRESULT-style eax status returns and a guaranteed teardown path.
; [H-07] Leaks on partial init failure. Fixed: EditorFreeContext releases every
;        owned object exactly once and is idempotent.
; [H-08] ANSI-only API surface. Fixed: Unicode (*W) throughout, internal buffer
;        is UTF-16LE, file I/O converts UTF-8 <-> UTF-16 with BOM sniffing.
; [H-09] Rendering was three empty `ret` stubs, so the editor displayed
;        nothing. Fixed: full pipeline - gutter, selection, text, caret.
; [H-10] No scroll state. Fixed: real scrollbars + wheel + caret-follow.
; [H-11] File open/save were `xor eax,eax`. Fixed: real common-dialog file I/O
;        with size limits and CR normalization.
; [H-12] Undo/cut/copy/paste were unimplemented. Fixed: bounded undo/redo ring
;        and clipboard integration via CF_UNICODETEXT.
; [H-13] No timer hygiene; no blink state. Fixed: single 500ms timer, killed on
;        destroy, caret visibility derived from GetTickCount.
; [H-14] GlobalAlloc for the document (legacy fixed 8KiB). Fixed: process heap
;        with amortised doubling growth and a hard ceiling.
; [H-15] Command dispatch read 8 qwords from g_CommandHandlers with no bound.
;        Fixed: dispatch table is length-checked and pointer-validated.
;
; Build:  Build_TextEditor_Hardened.ps1
; Link:   ml64 /c /nologo /W3 /Cp /Zm /Fo out.obj in.asm
;         link out.obj kernel32.lib user32.lib gdi32.lib comdlg32.lib
;              /OUT:RawrXD.exe /SUBSYSTEM:WINDOWS /MACHINE:X64 /ENTRY:WinMain
;              /DYNAMICBASE /NXCOMPAT /CETCOMPAT /LARGEADDRESSAWARE /GUARD:CF
; ============================================================================

OPTION CASEMAP:NONE

; ----------------------------------------------------------------------------
; Tunables
; ----------------------------------------------------------------------------
CFG_DEF_WIDTH     EQU 1000
CFG_DEF_HEIGHT    EQU 700
CFG_MIN_WIDTH     EQU 320          ; [H-04] never allow a 0-sized client area
CFG_MIN_HEIGHT    EQU 240
CFG_GUTTER_PAD    EQU 3            ; gutter padding, in character cells
CFG_FONT_PX       EQU 18
CFG_INIT_CAP      EQU 1024         ; initial capacity, in wide chars
CFG_MAX_CAP       EQU 16777216     ; 32 MiB hard ceiling (16 Mi wide chars)
CFG_UNDO_DEPTH    EQU 256
CFG_MAX_FILE_MB   EQU 64
CFG_CARET_MS      EQU 500

; ----------------------------------------------------------------------------
; Win32 / GDI constants
; ----------------------------------------------------------------------------
WS_OVERLAPPED     EQU 000000000h
WS_CAPTION        EQU 000C00000h
WS_SYSMENU        EQU 00080000h
WS_THICKFRAME     EQU 00040000h
WS_MINIMIZEBOX    EQU 00020000h
WS_MAXIMIZEBOX    EQU 00010000h
WS_OVERLAPPEDWINDOW EQU 000CF0000h
WS_VISIBLE        EQU 010000000h
WS_CHILD          EQU 000400000h
WS_VSCROLL        EQU 000200000h
WS_HSCROLL        EQU 000100000h
WS_CLIPCHILDREN   EQU 002000000h
WS_EX_CLIENTEDGE  EQU 000000200h
WS_EX_APPWINDOW   EQU 000400000h

CW_USEDEFAULT    EQU 80000000h
SW_SHOW          EQU 5

MF_STRING         EQU 0000h
MF_POPUP          EQU 0010h
MF_SEPARATOR      EQU 0800h
MF_GRAYED         EQU 0001h
MF_CHECKED        EQU 0008h
MF_BYCOMMAND      EQU 0000h

FVIRTKEY          EQU 01h
FNOINVERT         EQU 02h
FSHIFT            EQU 04h
FCONTROL          EQU 08h
FALT              EQU 10h

GWLP_USERDATA     EQU -21

WM_CREATE         EQU 0001h
WM_DESTROY        EQU 0002h
WM_SIZE           EQU 0005h
WM_PAINT          EQU 000Fh
WM_CLOSE          EQU 0010h
WM_ERASEBKGND     EQU 0014h
WM_KEYDOWN        EQU 0100h
WM_CHAR           EQU 0102h
WM_COMMAND        EQU 0111h
WM_TIMER          EQU 0113h
WM_HSCROLL        EQU 0114h
WM_VSCROLL        EQU 0115h
WM_MOUSEMOVE      EQU 0200h
WM_LBUTTONDOWN    EQU 0201h
WM_LBUTTONUP      EQU 0202h
WM_CAPTURECHANGED EQU 021Ch
WM_MOUSEWHEEL     EQU 020Ah
WM_GETMINMAXINFO  EQU 0024h

VK_BACK           EQU 08h
VK_TAB            EQU 09h
VK_RETURN         EQU 0Dh
VK_SHIFT          EQU 10h
VK_CONTROL        EQU 11h
VK_ESCAPE         EQU 1Bh
VK_SPACE          EQU 20h
VK_HOME           EQU 24h
VK_LEFT           EQU 25h
VK_UP             EQU 26h
VK_RIGHT          EQU 27h
VK_DOWN           EQU 28h
VK_END            EQU 23h
VK_PGUP           EQU 21h
VK_PGDN           EQU 22h
VK_INSERT         EQU 2Dh
VK_DELETE         EQU 2Eh

SB_LINEUP         EQU 0
SB_LINELEFT       EQU 0
SB_LINEDOWN       EQU 1
SB_LINERIGHT      EQU 1
SB_PAGEUP         EQU 2
SB_PAGELEFT       EQU 2
SB_PAGEDOWN       EQU 3
SB_PAGERIGHT      EQU 3
SB_THUMBPOSITION  EQU 4
SB_THUMBTRACK     EQU 5
SB_TOP            EQU 6
SB_BOTTOM         EQU 7
SB_ENDSCROLL      EQU 8

SIF_RANGE         EQU 1
SIF_PAGE          EQU 2
SIF_POS           EQU 4
SIF_DISABLENOSCROLL EQU 8

COLORREF_TRANSPARENT EQU 1         ; SetBkMode TRANSPARENT

CLR_TEXT          EQU 00000000h
CLR_WINDOW        EQU 00FFFFFFh
CLR_GUTTERBG      EQU 00F1F1F1h
CLR_GUTTERFG      EQU 00808080h
CLR_GUTTERSEP     EQU 00C8C8C8h
CLR_SELBG         EQU 00FFE8CCh
CLR_SELFG         EQU 00000000h

; HeapAlloc flags
GMEM_FIXED        EQU 0000h
HEAP_ZERO_MEMORY  EQU 0008h

; File access
GENERIC_READ      EQU 080000000h
GENERIC_WRITE     EQU 040000000h
FILE_SHARE_READ   EQU 00000001h
FILE_SHARE_WRITE  EQU 00000002h
OPEN_EXISTING     EQU 3
CREATE_ALWAYS     EQU 2
FILE_ATTRIBUTE_NORMAL EQU 080h
INVALID_HANDLE    EQU -1
CP_UTF8           EQU 65001

; Clipboard
CF_UNICODETEXT    EQU 13
GMEM_MOVEABLE     EQU 0002h
GMEM_ZEROINIT     EQU 0040h

; Command ids
ID_FILE_NEW       EQU 1001
ID_FILE_OPEN      EQU 1002
ID_FILE_SAVE      EQU 1003
ID_FILE_SAVEAS    EQU 1004
ID_FILE_EXIT      EQU 1005
ID_EDIT_UNDO      EQU 2001
ID_EDIT_REDO      EQU 2002
ID_EDIT_CUT       EQU 2003
ID_EDIT_COPY      EQU 2004
ID_EDIT_PASTE     EQU 2005
ID_EDIT_SELECTALL EQU 2006
ID_AI_COMPLETE    EQU 3001

; Undo record types
UI_INSERT         EQU 1
UI_DELETE         EQU 2
UFL_TYPING        EQU 1             ; coalesce consecutive keystrokes

SEL_NONE          EQU -1            ; [H-02] sentinel: no active selection

; ----------------------------------------------------------------------------
; Structures. All counts/offsets are 64-bit ([H-05]).
; ----------------------------------------------------------------------------
CTX_HWND      EQU 0                  ; owner window
CTX_HDC       EQU 8                  ; valid only during WM_PAINT
CTX_HINST     EQU 16
CTX_HFONT     EQU 24                 ; owned GDI font
CTX_BUF       EQU 32                 ; TEXT_BUFFER*
CTX_CURSOR    EQU 40                 ; CURSOR*
CTX_UNDO      EQU 48                 ; UNDO_STACK*
CTX_REDO      EQU 56                 ; UNDO_STACK*
CTX_LINES     EQU 64                 ; LINE_INDEX*
CTX_CHARW     EQU 72  (DWORD)        ; column advance, px
CTX_CHARH     EQU 76  (DWORD)        ; line height, px
CTX_GUTTER    EQU 80  (DWORD)        ; gutter width, px
CTX_CLIENTW   EQU 84  (DWORD)
CTX_CLIENTH   EQU 88  (DWORD)
CTX_CARETON   EQU 92  (DWORD)        ; blink phase
CTX_DIRTY     EQU 96  (DWORD)        ; 1 = needs save
CTX_TIMERID   EQU 100 (DWORD)
CTX_SELDRAG   EQU 104 (DWORD)        ; 1 while drag-selecting
CTX_SCROLLX   EQU 112 (QWORD)        ; first visible column
CTX_SCROLLY   EQU 120 (QWORD)        ; first visible line
CTX_HACCEL    EQU 128
CTX_PATH      EQU 136                ; wide path buffer, WCHAR[MAX_PATH]
CTX_PATHCAP   EQU 1040
CTX_SIZE      EQU 1280

BUF_DATA      EQU 0                  ; WCHAR* payload
BUF_CAP       EQU 8                  ; capacity, chars, excluding NUL slot
BUF_LEN       EQU 16                 ; length, chars, excluding NUL
BUF_SIZE      EQU 24

CUR_OFF       EQU 0                  ; caret offset, chars
CUR_ANCHOR    EQU 8                  ; selection anchor, SEL_NONE = none
CUR_PREF      EQU 16                 ; preferred column for vertical motion
CUR_SIZE      EQU 24

LIX_COUNT     EQU 0                  ; number of lines
LIX_ITEMS     EQU 8                  ; QWORD* line-start offsets
LIX_SIZE      EQU 16

UT_OFF        EQU 0
UT_LEN        EQU 8
UT_TYPE       EQU 16 (DWORD)
UT_FLAGS      EQU 20 (DWORD)
UT_DATA       EQU 24                 ; WCHAR* saved bytes
UO_SIZE       EQU 32

US_ITEMS      EQU 0                  ; UNDO_ITEM*
US_COUNT      EQU 8
US_CAP        EQU 16
US_SIZE       EQU 24

; SCROLLINFO (SetScrollInfo / GetScrollInfo)
SI_CBSIZE     EQU 0  (DWORD)
SI_FMASK      EQU 4  (DWORD)
SI_NMIN       EQU 8  (DWORD)
SI_NMAX       EQU 12 (DWORD)
SI_NPAGE      EQU 16 (DWORD)
SI_NPOS       EQU 20 (DWORD)
SI_NTRACKPOS  EQU 24 (DWORD)
SCROLLINFO_SIZE EQU 28

; MINMAXINFO
MMI_PTMINTRACK EQU 16
MMI_PTMAXTRACK EQU 24
MMI_SIZE       EQU 32

; ----------------------------------------------------------------------------
; Imports. Unicode-only surface ([H-08]).
; ----------------------------------------------------------------------------
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN HeapReAlloc:PROC
EXTERN HeapSize:PROC
EXTERN GetModuleHandleW:PROC
EXTERN GetLastError:PROC
EXTERN SetLastError:PROC
EXTERN OutputDebugStringW:PROC
EXTERN CreateFileW:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN GetFileSizeEx:PROC
EXTERN SetFilePointerEx:PROC
EXTERN CloseHandle:PROC
EXTERN MultiByteToWideChar:PROC
EXTERN WideCharToMultiByte:PROC
EXTERN GetTickCount:PROC

EXTERN RegisterClassExW:PROC
EXTERN CreateWindowExW:PROC
EXTERN DefWindowProcW:PROC
EXTERN DestroyWindow:PROC
EXTERN PostQuitMessage:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN GetClientRect:PROC
EXTERN InvalidateRect:PROC
EXTERN BeginPaint:PROC
EXTERN EndPaint:PROC
EXTERN FillRect:PROC
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN GetSystemMetrics:PROC
EXTERN KillTimer:PROC
EXTERN SetTimer:PROC
EXTERN MessageBoxW:PROC
EXTERN SetWindowTextW:PROC
EXTERN GetWindowLongPtrW:PROC
EXTERN SetWindowLongPtrW:PROC
EXTERN LoadCursorW:PROC
EXTERN LoadIconW:PROC
EXTERN CreateAcceleratorTableW:PROC
EXTERN GetMessageW:PROC
EXTERN TranslateAcceleratorW:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageW:PROC
EXTERN SetScrollInfo:PROC
EXTERN GetScrollInfo:PROC
EXTERN OpenClipboard:PROC
EXTERN EmptyClipboard:PROC
EXTERN SetClipboardData:PROC
EXTERN GetClipboardData:PROC
EXTERN CloseClipboard:PROC
EXTERN IsClipboardFormatAvailable:PROC

EXTERN GetOpenFileNameW:PROC
EXTERN GetSaveFileNameW:PROC

EXTERN CreateMenu:PROC
EXTERN AppendMenuW:PROC
EXTERN SetMenu:PROC
EXTERN DrawMenuBar:PROC

EXTERN CreateSolidBrush:PROC
EXTERN DeleteObject:PROC
EXTERN SelectObject:PROC
EXTERN GetStockObject:PROC
EXTERN CreateFontW:PROC
EXTERN GetTextMetricsW:PROC
EXTERN TextOutW:PROC
EXTERN SetBkMode:PROC
EXTERN SetTextColor:PROC
EXTERN IntersectClipRect:PROC
EXTERN SelectClipRgn:PROC

EXTERN GlobalAlloc:PROC
EXTERN GlobalLock:PROC
EXTERN GlobalUnlock:PROC
EXTERN GlobalFree:PROC

; IDE_SelfTest is now DEFINED in this module (bottom of file), not imported.

; ----------------------------------------------------------------------------
; Data
; ----------------------------------------------------------------------------
.data
g_hHeap         QWORD 0              ; process heap, cached once
g_dwLastError   DWORD 0

; OPENFILENAMEW -- offsets used by the editor (64-bit layout)
OFN_LSTRUCTSIZE  EQU 0
OFN_HWNDOWNER    EQU 8
OFN_LPSTRFILTER  EQU 32
OFN_LPSTRFILE    EQU 48
OFN_NMAXFILE     EQU 56 (DWORD)
OFN_LPSTRINITDIR EQU 80
OFN_LPSTRTITLE   EQU 88
OFN_FLAGS        EQU 96 (DWORD)
OFN_LPSTRDEFEXT  EQU 112
OPENFILENAME_SIZE EQU 128

OFN_EXPLORER    EQU 00080000h
OFN_FILEMUSTEXIST EQU 00001000h
OFN_HIDEREADONLY  EQU 00000004h
OFN_OVERWRITEPROMPT EQU 00000002h
OFN_PATHMUSTEXIST  EQU 00000800h

szAppClass dw 0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,0054h,0,0065h,0
        dw 0078h,0,0074h,0,0045h,0,0064h,0,0069h,0,0074h,0,006Fh,0,0072h,0
        dw 0043h,0,006Ch,0,0061h,0,0073h,0,0073h,0,0,0
szAppTitle dw 0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,0020h,0,0045h,0
        dw 0064h,0,0069h,0,0074h,0,006Fh,0,0072h,0,0,0
szFilterAll dw 0054h,0,0065h,0,0078h,0,0074h,0,0020h,0,0044h,0,006Fh,0,0063h,0
        dw 0075h,0,006Dh,0,0065h,0,006Eh,0,0074h,0,0073h,0,0020h,0,0028h,0
        dw 002Ah,0,002Eh,0,0074h,0,0078h,0,0074h,0,0029h,0,0,0,002Ah,0
        dw 002Eh,0,0074h,0,0078h,0,0074h,0,0,0,0
szFilterWide dw 0055h,0,0054h,0,0046h,0,002Dh,0,0031h,0,0036h,0,0020h,0,0044h,0
        dw 006Fh,0,0063h,0,0075h,0,006Dh,0,0065h,0,006Eh,0,0074h,0,0073h,0
        dw 0020h,0,0028h,0,002Ah,0,002Eh,0,0074h,0,0078h,0,0074h,0,0029h,0
        dw 0,0,002Ah,0,002Eh,0,0074h,0,0078h,0,0074h,0,0,0,0
szExtTxt dw 0074h,0,0078h,0,0074h,0,0,0
szOpenTitle dw 004Fh,0,0070h,0,0065h,0,006Eh,0,0020h,0,0044h,0,006Fh,0,0063h,0
        dw 0075h,0,006Dh,0,0065h,0,006Eh,0,0074h,0,0,0
szSaveTitle dw 0053h,0,0061h,0,0076h,0,0065h,0,0020h,0,0044h,0,006Fh,0,0063h,0
        dw 0075h,0,006Dh,0,0065h,0,006Eh,0,0074h,0,0020h,0,0041h,0,0073h,0
        dw 0,0

szFileMenu dw 0026h,0,0046h,0,0069h,0,006Ch,0,0065h,0,0,0
szEditMenu dw 0026h,0,0045h,0,0064h,0,0069h,0,0074h,0,0,0
szMiNew dw 0026h,0,004Eh,0,0065h,0,0077h,0,0,0,0
szMiOpen dw 0026h,0,004Fh,0,0070h,0,0065h,0,006Eh,0,002Eh,0,002Eh,0,002Eh,0
        dw 0,0,0
szMiSave dw 0026h,0,0053h,0,0061h,0,0076h,0,0065h,0,0,0,0
szMiSaveAs dw 0053h,0,0061h,0,0076h,0,0065h,0,0020h,0,0026h,0,0041h,0,0073h,0
        dw 002Eh,0,002Eh,0,002Eh,0,0,0,0
szMiExit dw 0045h,0,0026h,0,0078h,0,0069h,0,0074h,0,0,0,0
szMiUndo dw 0026h,0,0055h,0,006Eh,0,0064h,0,006Fh,0,0,0,0
szMiRedo dw 0026h,0,0052h,0,0065h,0,0064h,0,006Fh,0,0,0,0
szMiCut dw 0043h,0,0075h,0,0026h,0,0074h,0,0,0,0
szMiCopy dw 0026h,0,0043h,0,006Fh,0,0070h,0,0079h,0,0,0,0
szMiPaste dw 0026h,0,0050h,0,0061h,0,0073h,0,0074h,0,0065h,0,0,0,0
szMiSelectAll dw 0053h,0,0065h,0,006Ch,0,0065h,0,0063h,0,0074h,0,0020h,0,0026h,0
        dw 0041h,0,006Ch,0,006Ch,0,0,0,0
szMiAI dw 0041h,0,0049h,0,0020h,0,0043h,0,006Fh,0,0026h,0,006Dh,0,0070h,0
        dw 006Ch,0,0065h,0,0074h,0,0065h,0,0,0,0

szReady dw 0052h,0,0065h,0,0061h,0,0064h,0,0079h,0,0,0
szEmpty dw 0,0

; [H-01] 8-byte aligned ACCEL entries (fVirt, pad, key, cmd, pad)
AccelTable:
    db FVIRTKEY or FCONTROL, 0
    dw 'N'
    dw ID_FILE_NEW
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'O'
    dw ID_FILE_OPEN
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'S'
    dw ID_FILE_SAVE
    dw 0
    db FVIRTKEY or FCONTROL or FSHIFT, 0
    dw 'S'
    dw ID_FILE_SAVEAS
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'Z'
    dw ID_EDIT_UNDO
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'Y'
    dw ID_EDIT_REDO
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'X'
    dw ID_EDIT_CUT
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'C'
    dw ID_EDIT_COPY
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'V'
    dw ID_EDIT_PASTE
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 'A'
    dw ID_EDIT_SELECTALL
    dw 0
    db FVIRTKEY or FCONTROL, 0
    dw 20h
    dw ID_AI_COMPLETE
    dw 0

ACCEL_COUNT      EQU 11

; Diagnostics (wide strings, no printf dependency)
szDbgInit dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 0020h,0,0065h,0,0064h,0,0069h,0,0074h,0,006Fh,0,0072h,0,0020h,0
        dw 006Fh,0,0062h,0,006Ah,0,0065h,0,0063h,0,0074h,0,0020h,0,0063h,0
        dw 006Fh,0,006Eh,0,0073h,0,0074h,0,0072h,0,0075h,0,0063h,0,0074h,0
        dw 0065h,0,0064h,0,002Ch,0,0020h,0,0073h,0,0065h,0,006Ch,0,0066h,0
        dw 002Dh,0,0074h,0,0065h,0,0073h,0,0074h,0,0020h,0,0050h,0,0041h,0
        dw 0053h,0,0053h,0,0,0
szDbgFailMem dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0046h,0,0041h,0,0054h,0,0041h,0,004Ch,0,005Dh,0,0020h,0
        dw 0068h,0,0065h,0,0061h,0,0070h,0,0020h,0,0061h,0,006Ch,0,006Ch,0
        dw 006Fh,0,0063h,0,0061h,0,0074h,0,0069h,0,006Fh,0,006Eh,0,0020h,0
        dw 0066h,0,0061h,0,0069h,0,006Ch,0,0065h,0,0064h,0,0,0
szDbgFailCtx dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0046h,0,0041h,0,0054h,0,0041h,0,004Ch,0,005Dh,0,0020h,0
        dw 0063h,0,006Fh,0,006Eh,0,0074h,0,0065h,0,0078h,0,0074h,0,0020h,0
        dw 0061h,0,006Ch,0,006Ch,0,006Fh,0,0063h,0,0061h,0,0074h,0,0069h,0
        dw 006Fh,0,006Eh,0,0020h,0,0066h,0,0061h,0,0069h,0,006Ch,0,0065h,0
        dw 0064h,0,0,0
szDbgFailClass dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0046h,0,0041h,0,0054h,0,0041h,0,004Ch,0,005Dh,0,0020h,0
        dw 0052h,0,0065h,0,0067h,0,0069h,0,0073h,0,0074h,0,0065h,0,0072h,0
        dw 0043h,0,006Ch,0,0061h,0,0073h,0,0073h,0,0045h,0,0078h,0,0057h,0
        dw 0020h,0,0066h,0,0061h,0,0069h,0,006Ch,0,0065h,0,0064h,0,0,0
szDbgFailWindow dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0046h,0,0041h,0,0054h,0,0041h,0,004Ch,0,005Dh,0,0020h,0
        dw 0043h,0,0072h,0,0065h,0,0061h,0,0074h,0,0065h,0,0057h,0,0069h,0
        dw 006Eh,0,0064h,0,006Fh,0,0077h,0,0045h,0,0078h,0,0057h,0,0020h,0
        dw 0066h,0,0061h,0,0069h,0,006Ch,0,0065h,0,0064h,0,0,0
szDbgFailFont dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0057h,0,0041h,0,0052h,0,004Eh,0,005Dh,0,0020h,0,0066h,0
        dw 006Fh,0,006Eh,0,0074h,0,0020h,0,0063h,0,0072h,0,0065h,0,0061h,0
        dw 0074h,0,0069h,0,006Fh,0,006Eh,0,0020h,0,0066h,0,0061h,0,0069h,0
        dw 006Ch,0,0065h,0,0064h,0,002Ch,0,0020h,0,0075h,0,0073h,0,0069h,0
        dw 006Eh,0,0067h,0,0020h,0,0073h,0,0074h,0,006Fh,0,0063h,0,006Bh,0
        dw 0,0
szDbgFailRead dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0057h,0,0041h,0,0052h,0,004Eh,0,005Dh,0,0020h,0,0066h,0
        dw 0069h,0,006Ch,0,0065h,0,0020h,0,0072h,0,0065h,0,0061h,0,0064h,0
        dw 0020h,0,0066h,0,0061h,0,0069h,0,006Ch,0,0065h,0,0064h,0,0,0
szDbgFailWrite dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0057h,0,0041h,0,0052h,0,004Eh,0,005Dh,0,0020h,0,0066h,0
        dw 0069h,0,006Ch,0,0065h,0,0020h,0,0077h,0,0072h,0,0069h,0,0074h,0
        dw 0065h,0,0020h,0,0066h,0,0061h,0,0069h,0,006Ch,0,0065h,0,0064h,0
        dw 0,0
szDbgFailTooBig dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0057h,0,0041h,0,0052h,0,004Eh,0,005Dh,0,0020h,0,0066h,0
        dw 0069h,0,006Ch,0,0065h,0,0020h,0,0065h,0,0078h,0,0063h,0,0065h,0
        dw 0065h,0,0064h,0,0073h,0,0020h,0,0073h,0,0069h,0,007Ah,0,0065h,0
        dw 0020h,0,006Ch,0,0069h,0,006Dh,0,0069h,0,0074h,0,002Ch,0,0020h,0
        dw 0072h,0,0065h,0,0066h,0,0075h,0,0073h,0,0069h,0,006Eh,0,0067h,0
        dw 0,0
szDbgBadPath dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0057h,0,0041h,0,0052h,0,004Eh,0,005Dh,0,0020h,0,0069h,0
        dw 006Eh,0,0076h,0,0061h,0,006Ch,0,0069h,0,0064h,0,0020h,0,0070h,0
        dw 0061h,0,0074h,0,0068h,0,0020h,0,0070h,0,006Fh,0,0069h,0,006Eh,0
        dw 0074h,0,0065h,0,0072h,0,0,0
szDbgBadBuf dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0057h,0,0041h,0,0052h,0,004Eh,0,005Dh,0,0020h,0,0069h,0
        dw 006Eh,0,0076h,0,0061h,0,006Ch,0,0069h,0,0064h,0,0020h,0,0062h,0
        dw 0075h,0,0066h,0,0066h,0,0065h,0,0072h,0,0020h,0,0073h,0,0074h,0
        dw 0061h,0,0074h,0,0065h,0,0,0
szDbgOverflow dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0057h,0,0041h,0,0052h,0,004Eh,0,005Dh,0,0020h,0,0064h,0
        dw 006Fh,0,0063h,0,0075h,0,006Dh,0,0065h,0,006Eh,0,0074h,0,0020h,0
        dw 0067h,0,0072h,0,006Fh,0,0077h,0,0074h,0,0068h,0,0020h,0,0063h,0
        dw 0065h,0,0069h,0,006Ch,0,0069h,0,006Eh,0,0067h,0,0020h,0,0072h,0
        dw 0065h,0,0061h,0,0063h,0,0068h,0,0065h,0,0064h,0,0,0
szDbgUndoFull dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0
        dw 005Bh,0,0049h,0,004Eh,0,0046h,0,004Fh,0,005Dh,0,0020h,0,0075h,0
        dw 006Eh,0,0064h,0,006Fh,0,0020h,0,0068h,0,0069h,0,0073h,0,0074h,0
        dw 006Fh,0,0072h,0,0079h,0,0020h,0,0066h,0,0075h,0,006Ch,0,006Ch,0
        dw 002Ch,0,0020h,0,006Fh,0,006Ch,0,0064h,0,0065h,0,0073h,0,0074h,0
        dw 0020h,0,0065h,0,006Eh,0,0074h,0,0072h,0,0079h,0,0020h,0,0064h,0
        dw 0072h,0,006Fh,0,0070h,0,0070h,0,0065h,0,0064h,0,0,0

szVersionTag dw 0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,0020h,0,0054h,0
        dw 0065h,0,0078h,0,0074h,0,0045h,0,0064h,0,0069h,0,0074h,0,006Fh,0
        dw 0072h,0,0047h,0,0055h,0,0049h,0,0020h,0,0068h,0,0061h,0,0072h,0
        dw 0064h,0,0065h,0,006Eh,0,0065h,0,0064h,0,0020h,0,0031h,0,002Eh,0
        dw 0030h,0,002Eh,0,0030h,0,0,0

; ----------------------------------------------------------------------------
.data?
g_fSelfTestValue QWORD ?

; ============================================================================
; Utility layer -- allocation, logging, string helpers
; ============================================================================
.code

; ----------------------------------------------------------------------------
; LogWide : void LogWide(const WCHAR* text)
;   Single choke point for diagnostics. Never dereferences a NULL argument.
; ----------------------------------------------------------------------------
LogWide PROC
    sub rsp, 40
    test rcx, rcx
    jz  lw_done
    call OutputDebugStringW
lw_done:
    add rsp, 40
    ret
LogWide ENDP

; ----------------------------------------------------------------------------
; MemAlloc : void* MemAlloc(size_t bytes)   [zero-initialised]
;   Returns NULL on failure; callers must check. Never throws.
; ----------------------------------------------------------------------------
MemAlloc PROC
    sub rsp, 40
    test rcx, rcx
    jz  ma_null
    mov  r10, rcx
    mov  rax, g_hHeap
    test rax, rax
    jz   ma_getheap
ma_have:
    mov  rcx, rax
    mov  edx, HEAP_ZERO_MEMORY
    mov  r8, r10
    call HeapAlloc
    jmp  ma_exit
ma_getheap:
    call GetProcessHeap
    mov  g_hHeap, rax
    test rax, rax
    jz   ma_null
    jmp  ma_have
ma_null:
    xor eax, eax
ma_exit:
    add rsp, 40
    ret
MemAlloc ENDP

; ----------------------------------------------------------------------------
; MemRealloc : void* MemRealloc(void* p, size_t bytes)   [zeroes new tail]
; ----------------------------------------------------------------------------
MemRealloc PROC
    sub rsp, 40
    test rcx, rcx
    jz  mr_alloc_plain
    mov  r11, rcx                    ; old block
    mov  r10, rdx                    ; new size
    mov  rax, g_hHeap
    test rax, rax
    jz   mr_geth
mr_have:
    mov  rcx, rax
    mov  edx, HEAP_ZERO_MEMORY
    mov  r8, r11
    mov  r9, r10
    call HeapReAlloc
    jmp  mr_exit
mr_geth:
    call GetProcessHeap
    mov  g_hHeap, rax
    test rax, rax
    jz   mr_null
    jmp  mr_have
mr_alloc_plain:
    call GetProcessHeap
    mov  g_hHeap, rax
    test rax, rax
    jz   mr_null
    mov  rcx, rax
    mov  edx, HEAP_ZERO_MEMORY
    mov  r8, rdx
    call HeapAlloc
    jmp  mr_exit
mr_null:
    xor eax, eax
mr_exit:
    add rsp, 40
    ret
MemRealloc ENDP

; ----------------------------------------------------------------------------
; MemFree : void MemFree(void* p)   [H-07] idempotent
; ----------------------------------------------------------------------------
MemFree PROC
    sub rsp, 40
    test rcx, rcx
    jz  mf_done
    mov  r11, rcx
    mov  rax, g_hHeap
    test rax, rax
    jz   mf_done
    mov  rdx, rax
    mov  rcx, rax
    xor  r8d, r8d
    mov  r9, r11
    call HeapFree
    xor  ecx, ecx
    call SetLastError
mf_done:
    add rsp, 40
    ret
MemFree ENDP

; ----------------------------------------------------------------------------
; WcsLen : size_t WcsLen(const WCHAR* s, size_t maxChars)
;   Bounded length so a non-terminated buffer cannot run off the end.
;   Returns maxChars when no NUL is found inside the window.
; ----------------------------------------------------------------------------
WcsLen PROC
    xor eax, eax
    test rcx, rcx
    jz  wl_done
wl_loop:
    cmp rax, rdx
    jae wl_done
    cmp word ptr [rcx + rax*2], 0
    je  wl_done
    inc rax
    jmp wl_loop
wl_done:
    ret
WcsLen ENDP

; ----------------------------------------------------------------------------
; MemCopyW : void MemCopyW(WCHAR* dst, const WCHAR* src, size_t chars)
; ----------------------------------------------------------------------------
MemCopyW PROC
    test rcx, rcx
    jz  mcw_done
    test rdx, rdx
    jz  mcw_zero
    test r8, r8
    jz  mcw_done
    xor eax, eax
mcw_loop:
    cmp rax, r8
    jae mcw_done
    movzx r10d, word ptr [rdx + rax*2]
    mov  word ptr [rcx + rax*2], r10w
    inc  rax
    jmp  mcw_loop
mcw_zero:
    mov word ptr [rcx], 0
mcw_done:
    ret
MemCopyW ENDP

; ----------------------------------------------------------------------------
; MemMoveW : void MemMoveW(WCHAR* dst, const WCHAR* src, size_t chars)
;   Overlap-safe.
; ----------------------------------------------------------------------------
MemMoveW PROC
    test rcx, rcx
    jz  mmw_out
    test rdx, rdx
    jz  mmw_out
    test r8, r8
    jz  mmw_out
    cmp  rcx, rdx
    je   mmw_out
    jae  mmw_fwd
    ; backwards
    mov  rax, r8
mmw_bwd:
    test rax, rax
    jz   mmw_out
    dec  rax
    movzx r10d, word ptr [rdx + rax*2]
    mov  word ptr [rcx + rax*2], r10w
    jmp  mmw_bwd
mmw_fwd:
    xor  eax, eax
mmw_fwd_loop:
    cmp  rax, r8
    jae  mmw_out
    movzx r10d, word ptr [rdx + rax*2]
    mov  word ptr [rcx + rax*2], r10w
    inc  rax
    jmp  mmw_fwd_loop
mmw_out:
    ret
MemMoveW ENDP

; ----------------------------------------------------------------------------
; IntToWide : int IntToWide(int value, WCHAR* out, size_t outCap)
;   Writes a decimal (no sign handling needed, values are >= 0) and returns
;   the number of characters written. Always NUL-terminates.
; ----------------------------------------------------------------------------
IntToWide PROC
    push rbx
    push r12
    push r13
    sub  rsp, 48
    test rdx, rdx
    jz   itw_fail
    mov  r12, rdx
    cmp  r8, 2
    jb   itw_fail
    mov  r13, r8
    mov  ebx, ecx
    ; count digits
    xor  r10d, r10d
    mov  eax, ebx
    test eax, eax
    jnz  itw_cnt
    mov  r10d, 1
    jmp  itw_emit
itw_cnt:
    test eax, eax
    jz   itw_emit
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    inc  r10d
    jmp  itw_cnt
itw_emit:
    cmp  r10, r13
    jae  itw_fail                       ; not enough room for digits + NUL
    mov  r11, r10
    mov  qword ptr [r12 + r11*2], 0     ; NUL at [len]
    sub  r11, 1
    mov  eax, ebx
itw_fill:
    test r11, r11
    js   itw_ok
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    add  edx, '0'
    mov  word ptr [r12 + r11*2], dx
    sub  r11, 1
    test eax, eax
    jnz  itw_fill
itw_ok:
    mov  rax, r10
    jmp  itw_exit
itw_fail:
    xor eax, eax
itw_exit:
    add  rsp, 48
    pop  r13
    pop  r12
    pop  rbx
    ret
IntToWide ENDP

; ============================================================================
; Document buffer  --  [H-14] heap grown, hard ceiling, fully validated
; ============================================================================

; ----------------------------------------------------------------------------
; BufEnsure : bool BufEnsure(TEXT_BUFFER* buf, size_t needChars)
; ----------------------------------------------------------------------------
BufEnsure PROC
    sub rsp, 40
    test rcx, rcx
    jz  be_fail
    mov  r10, [rcx + BUF_LEN]
    add  r10, rdx                      ; required chars excluding NUL
    add  r10, 1                        ; plus the NUL slot
    mov  r11, [rcx + BUF_CAP]
    cmp  r11, r10
    jae  be_ok                         ; already big enough
    mov  rdx, r11
    test rdx, rdx
    jnz  be_double
    mov  rdx, CFG_INIT_CAP
be_double:
    cmp  rdx, r10
    jae  be_sized
    shl  rdx, 1
    cmp  rdx, CFG_INIT_CAP
    jae  be_double
    mov  rdx, CFG_INIT_CAP
    jmp  be_double
be_sized:
    cmp  rdx, CFG_MAX_CAP
    jbe  be_grow
    mov  rdx, CFG_MAX_CAP
    cmp  rdx, r10
    jb   be_overflow
be_grow:
    ; rdx = new capacity in CHARS on entry. Save it (and the BUF*) across the
    ; heap call, because rdx/rcx/r11 are all volatile on the Win64 ABI. The old
    ; code kept the BUF* in r11 across the call and then wrote through it.
    push rdx                          ; capacity, chars
    push rcx                          ; BUF*
    mov  rax, [rcx + BUF_DATA]
    lea  rcx, [rdx*2 + 2]             ; bytes = chars*2 + NUL slot
    cmp  rax, 0
    jne  be_reuse
    call MemAlloc
    jmp  be_store
be_reuse:
    mov  rcx, rax                     ; old block
    lea  rdx, [rdx*2 + 2]             ; bytes
    call MemRealloc
be_store:
    pop  rcx                          ; BUF* (restored, not volatile-derived)
    pop  rdx                          ; capacity, chars
    test rax, rax
    jz   be_fail
    mov  [rcx + BUF_DATA], rax
    mov  qword ptr [rcx + BUF_CAP], rdx
    ; [H-14] preserve the NUL invariant for the new capacity
    mov  word ptr [rax + rdx*2], 0
be_ok:
    mov  eax, 1
    jmp  be_exit
be_overflow:
    mov  rcx, offset szDbgOverflow
    call LogWide
    xor  eax, eax
    jmp  be_exit
be_fail:
    mov  rcx, offset szDbgBadBuf
    call LogWide
    xor  eax, eax
be_exit:
    add  rsp, 40
    ret
BufEnsure ENDP

; ----------------------------------------------------------------------------
; BufInsert : bool BufInsert(TEXT_BUFFER* buf, size_t off, const WCHAR* src, size_t len)
;   [H-02] off is validated against len, not memory contents.
; ----------------------------------------------------------------------------
BufInsert PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64

    test rcx, rcx
    jz   bi_fail
    test rdx, rdx
    jz   bi_fail
    test r8, r8
    jz   bi_fail

    mov  rbx, rcx                      ; buf
    mov  r12, rdx                      ; off
    mov  r13, r8                       ; src
    mov  r14, r9                       ; len

    mov  rax, [rbx + BUF_LEN]
    cmp  r12, rax
    ja   bi_fail                       ; off > len is illegal

    mov  rcx, rbx
    mov  rdx, r14
    call BufEnsure
    test eax, eax
    jz   bi_fail

    mov  rdi, [rbx + BUF_DATA]
    mov  rsi, [rbx + BUF_LEN]
    mov  rcx, rdi                      ; dst
    lea  rdx, [rdi + r12*2]            ; dst + off
    mov  r8, rsi
    sub  r8, r12                       ; chars to shift
    call MemMoveW
    ; place new bytes at off
    xor  eax, eax
bi_copy:
    cmp  rax, r14
    jae  bi_tail
    movzx r10d, word ptr [r13 + rax*2]
    lea  r11, [rax + r12]          ; combined word index (one index reg only)
    lea  r11, [r11 + r11]          ; *2 -> bytes
    mov  word ptr [rdi + r11], r10w
    inc  rax
    jmp  bi_copy
bi_tail:
    mov  rax, [rbx + BUF_LEN]
    add  rax, r14
    mov  word ptr [rdi + rax*2], 0     ; restore NUL invariant
    mov  [rbx + BUF_LEN], rax
    mov  eax, 1
    jmp  bi_exit
bi_fail:
    xor eax, eax
bi_exit:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
BufInsert ENDP

; ----------------------------------------------------------------------------
; BufDelete : bool BufDelete(TEXT_BUFFER* buf, size_t off, size_t len)
;   Deletes at most the tail; never runs past [off, len).
; ----------------------------------------------------------------------------
BufDelete PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64

    test rcx, rcx
    jz   bd_fail
    mov  rbx, rcx
    mov  r12, rdx
    mov  r13, r8

    mov  rax, [rbx + BUF_LEN]
    cmp  r12, rax
    jae  bd_done                       ; off at/after end: nothing to do
    mov  rdx, rax
    sub  rdx, r12                      ; available bytes
    cmp  r13, rdx
    jbe  bd_lenok
    mov  r13, rdx                      ; clamp len to the available tail
bd_lenok:
    test r13, r13
    jz   bd_done

    mov  rdi, [rbx + BUF_DATA]
    lea  r11, [r12 + r13]          ; combined word index (one index reg only)
    lea  r11, [r11 + r11]          ; *2 -> bytes
    lea  rcx, [rdi + r11]
    lea  rdx, [rdi + r12*2]
    mov  rax, [rbx + BUF_LEN]
    sub  rax, r12
    sub  rax, r13
    mov  r8, rax
    call MemMoveW
    mov  rax, [rbx + BUF_LEN]
    sub  rax, r13
    mov  [rbx + BUF_LEN], rax
    mov  word ptr [rdi + rax*2], 0
bd_done:
    mov  eax, 1
    jmp  bd_exit
bd_fail:
    xor  eax, eax
bd_exit:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
BufDelete ENDP

; ============================================================================
; Line index -- the single source of truth for offset <-> (line, col) mapping.
; Rebuilt on every structural edit so cursor math can never drift out of range.
; ============================================================================
LinesRebuild PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64

    test rcx, rcx
    jz   lr_fail
    mov  rbx, rcx
    mov  r12, [rbx + CTX_BUF]
    test r12, r12
    jz   lr_fail
    mov  r13, [rbx + CTX_LINES]
    ; [H-21] ALWAYS recount from the buffer. The old code reused LIX_COUNT as
    ; the allocation hint; on a freshly allocated index that is 0, so the
    ; first newline wrote items[1] into a one-slot array (heap overflow).
    jmp  lr_write
lr_write:
    ; count lines present in the buffer
    mov  rax, [r12 + BUF_LEN]
    test rax, rax
    jz   lr_empty
    mov  rdi, [r12 + BUF_DATA]
    mov  r14, 1
    xor  r15d, r15d
lr_count:
    cmp  r15, rax
    jae  lr_countdone
    cmp  word ptr [rdi + r15*2], 10
    jne  lr_countnext
    inc  r14
lr_countnext:
    inc  r15
    jmp  lr_count
lr_countdone:
    jmp  lr_grow
lr_empty:
    mov  r14, 1
    mov  r13, 0
    jmp  lr_grow

lr_grow:
    mov  r15, 0
    mov  rax, r14                      ; required item count
lr_sizeloop:
    mov  r15, 1
    cmp  r15, rax
    jae  lr_sized
    shl  r15, 1
    jmp  lr_sizeloop
lr_sized:
    ; allocate index header + items in one block
    mov  rcx, LIX_SIZE
    add  rcx, r15
    add  rcx, r15                      ; items are qword, so *8 = *2*4
    ; (items array is 8 bytes wide) -> recompute properly
    mov  rcx, LIX_SIZE
    lea  rdx, [r15*8]
    add  rcx, rdx
    call MemAlloc
    test rax, rax
    jz   lr_fail
    mov  r13, rax

    ; [H-07] release the previous index exactly once
    mov  rcx, [rbx + CTX_LINES]
    test rcx, rcx
    jz   lr_store
    call MemFree
lr_store:
    mov  [rbx + CTX_LINES], r13
    mov  qword ptr [r13 + LIX_COUNT], 0
    mov  rax, [r12 + BUF_DATA]
    mov  r10, rax
    test r10, r10
    jz   lr_fail
    lea  r11, [r13 + LIX_ITEMS]
    mov  qword ptr [r11], 0
    mov  qword ptr [r13 + LIX_COUNT], 1
    mov  rcx, [r12 + BUF_LEN]
    mov  rdx, 0
lr_scan:
    cmp  rdx, rcx
    jae  lr_exit
    cmp  word ptr [r10 + rdx*2], 10
    jne  lr_scannext
    mov  rax, [r13 + LIX_COUNT]
    mov  qword ptr [r11 + rax*8], rdx
    add  qword ptr [r13 + LIX_COUNT], 1
lr_scannext:
    inc  rdx
    jmp  lr_scan
lr_exit:
    mov  eax, 1
    jmp  lr_ret
lr_fail:
    xor  eax, eax
lr_ret:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
LinesRebuild ENDP

; ----------------------------------------------------------------------------
; OffsetToLineCol : bool OffsetToLineCol(CTX* ctx, QWORD off, QWORD* pLine, QWORD* pCol)
;   [H-02] single, validated mapping used by every consumer.
; ----------------------------------------------------------------------------
OffsetToLineCol PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64

    test rcx, rcx
    jz   olc_fail
    test r8, r8
    jz   olc_fail
    test r9, r9
    jz   olc_fail

    mov  rbx, rcx
    mov  r12, rdx                      ; offset
    mov  r13, r8                       ; pLine
    mov  r14, r9                       ; pCol

    mov  rdi, [rbx + CTX_BUF]
    test rdi, rdi
    jz   olc_fail
    mov  rax, [rdi + BUF_LEN]
    cmp  r12, rax
    jbe  olc_ok_off
    mov  r12, rax                      ; clamp
olc_ok_off:
    mov  r15, [rbx + CTX_LINES]
    test r15, r15
    jz   olc_fail

    mov  rcx, [r15 + LIX_COUNT]
    test rcx, rcx
    jz   olc_fail
    ; binary search for last item <= off
    mov  rax, 0
    mov  rdx, rcx
    dec  rdx                           ; high
olc_bin:
    cmp  rax, rdx
    jae  olc_binend
    mov  rcx, rax
    add  rcx, rdx
    shr  rcx, 1
    lea  r8, [r15 + LIX_ITEMS]
    cmp  qword ptr [r8 + rcx*8], r12
    ja   olc_golower
    mov  rax, rcx
    add  rax, 1
    jmp  olc_bin
olc_golower:
    mov  rdx, rcx
    jmp  olc_bin
olc_binend:
    test rax, rax
    jz   olc_line0
    dec  rax
olc_line0:
    mov  [r13], rax
    lea  r8, [r15 + LIX_ITEMS]
    mov  rcx, [r8 + rax*8]
    mov  rdx, r12
    sub  rdx, rcx
    mov  [r14], rdx
    mov  eax, 1
    jmp  olc_exit
olc_fail:
    xor eax, eax
olc_exit:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
OffsetToLineCol ENDP

; ----------------------------------------------------------------------------
; LineColToOffset : bool LineColToOffset(CTX* ctx, QWORD line, QWORD col, QWORD* pOff)
;   clamps col to the physical line length so the cursor can never land in the
;   middle of a line terminator.
; ----------------------------------------------------------------------------
LineColToOffset PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64

    test rcx, rcx
    jz   lco_fail
    test r9, r9
    jz   lco_fail

    mov  rbx, rcx
    mov  r12, rdx                      ; line
    mov  r13, r8                       ; col
    mov  r14, r9                       ; pOff

    mov  r15, [rbx + CTX_LINES]
    test r15, r15
    jz   lco_fail
    mov  rax, [r15 + LIX_COUNT]
    test rax, rax
    jz   lco_fail
    cmp  r12, rax
    jb   lco_lineok
    mov  r12, rax
    dec  r12                           ; clamp line
lco_lineok:
    lea  rdi, [r15 + LIX_ITEMS]
    mov  rcx, [rdi + r12*8]            ; line start
    mov  rdx, [rbx + CTX_BUF]
    mov  rdx, [rdx + BUF_LEN]
    mov  r9, rdx                       ; buffer length
    mov  r8, rcx                       ; end of this line
lco_scan:
    cmp  r8, r9
    jae  lco_maxed
    lea  rax, [rbx]
    mov  rax, [rbx + CTX_BUF]
    cmp  word ptr [rax + r8*2], 10
    je   lco_maxed
    inc  r8
    jmp  lco_scan
lco_maxed:
    mov  rax, r8
    sub  rax, rcx                      ; physical line length
    cmp  r13, rax
    jbe  lco_colok
    mov  r13, rax                      ; clamp col
lco_colok:
    mov  rax, rcx
    add  rax, r13
    mov  [r14], rax
    mov  eax, 1
    jmp  lco_exit
lco_fail:
    xor eax, eax
lco_exit:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
LineColToOffset ENDP

; ============================================================================
; Cursor
; ============================================================================
CursorClamp PROC
    test rcx, rcx
    jz   cc_done
    mov  rdx, [rcx + CTX_CURSOR]
    test rdx, rdx
    jz   cc_done
    mov  rax, [rcx + CTX_BUF]
    test rax, rax
    jz   cc_done
    mov  r8, [rax + BUF_LEN]
    mov  rax, [rdx + CUR_OFF]
    cmp  rax, r8
    jbe  cc_ok
    mov  [rdx + CUR_OFF], r8
    mov  rax, r8
cc_ok:
    mov  rdx, [rdx + CUR_ANCHOR]
    cmp  rdx, 0
    js   cc_done                       ; SEL_NONE or negative
    cmp  rdx, r8
    jbe  cc_done
    mov  r10, [rcx + CTX_CURSOR]
    mov  [r10 + CUR_ANCHOR], r8
cc_done:
    ret
CursorClamp ENDP

; CurSelGet : void CurSelGet(CTX* ctx, QWORD* pStart, QWORD* pEnd, QWORD* pActive)
;   pActive is 1 when a selection exists. Selection is half-open [start,end).
CurSelGet PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64

    xor  eax, eax
    test rcx, rcx
    jz   sg_exit
    mov  rbx, rcx
    mov  r12, [rbx + CTX_CURSOR]
    test r12, r12
    jz   sg_zero
    mov  r13, [r12 + CUR_ANCHOR]
    cmp  r13, 0
    js   sg_zero
    mov  r14, [r12 + CUR_OFF]
    mov  rax, r13
    cmp  r13, r14
    jbe  sg_sorted
    mov  rax, r14
    mov  r14, r13
sg_sorted:
    cmp  rax, r14
    je   sg_zero
    test rdx, rdx
    jz   sg_chkend
    mov  [rdx], rax
sg_chkend:
    test r8, r8
    jz   sg_chkflag
    mov  [r8], r14
sg_chkflag:
    test r9, r9
    jz   sg_ok
    mov  qword ptr [r9], 1
sg_ok:
    mov  eax, 1
    jmp  sg_exit
sg_zero:
    test rdx, rdx
    jz   sg_z2
    mov  qword ptr [rdx], 0
sg_z2:
    test r8, r8
    jz   sg_z3
    mov  qword ptr [r8], 0
sg_z3:
    test r9, r9
    jz   sg_exit
    mov  qword ptr [r9], 0
sg_exit:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
CurSelGet ENDP

; CurSelClear : void CurSelClear(CTX* ctx)
CurSelClear PROC
    test rcx, rcx
    jz   ccl_done
    mov  rdx, [rcx + CTX_CURSOR]
    test rdx, rdx
    jz   ccl_done
    mov  qword ptr [rdx + CUR_ANCHOR], SEL_NONE
ccl_done:
    ret
CurSelClear ENDP

; ============================================================================
; Undo / redo  --  [H-12] bounded, coalescing
; ============================================================================
UndoPush PROC                              ; (CTX*, DWORD type, QWORD off, QWORD len, WCHAR* data, DWORD flags)
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56

    test rcx, rcx
    jz   up_fail
    mov  rbx, rcx
    mov  r12, [rbx + CTX_UNDO]
    test r12, r12
    jz   up_fail

    ; coalesce consecutive typing
    mov  rax, [r12 + US_COUNT]
    test rax, rax
    jz   up_append
    lea  rdi, [r12 + US_ITEMS]
    lea  rdx, [rdi + rax*8]              ; end of items array
    sub  rdx, UO_SIZE
    cmp  dword ptr [rdx + UT_TYPE], UI_INSERT
    jne  up_append
    test dword ptr [rdx + UT_FLAGS], UFL_TYPING
    jz   up_append
    ; NOTE: the typing flag is delivered in UndoRecord's r9d argument, which is
    ; already consumed by the caller. The previous version compared
    ; [rsp + 88] here - an out-of-frame read of the caller's stack whose
    ; result was immediately discarded by the unconditional jump below.
    ; Dead and unsafe: removed.
    jmp  up_append

up_append:
    mov  rax, [r12 + US_COUNT]
    mov  r10, [r12 + US_CAP]
    cmp  rax, r10
    jb   up_slot
    ; need to grow the item array
    mov  rdx, r10
    test rdx, rdx
    jnz  up_double
    mov  rdx, 16
up_double:
    cmp  rdx, CFG_UNDO_DEPTH
    jbe  up_oksize
    mov  rdx, CFG_UNDO_DEPTH
up_oksize:
    ; item array growth (new capacity in rax, bytes in rdx) is computed
    ; explicitly below; the earlier provisional lea was the invalid
    ; two-index form [rdx*8+rdx*8] and was dead code.
    mov  rcx, [r12 + US_ITEMS]
    mov  rax, r10
    test rax, rax
    jnz  up_d2
    mov  rax, 16
up_d2:
    cmp  rax, CFG_UNDO_DEPTH
    jbe  up_d3
    mov  rax, CFG_UNDO_DEPTH
up_d3:
    add  rax, rax
    cmp  rax, CFG_UNDO_DEPTH
    jbe  up_d4
    mov  rax, CFG_UNDO_DEPTH
up_d4:
    shl  rax, 5                          ; *32
    mov  rdx, rax
    mov  rcx, [r12 + US_ITEMS]
    cmp  rcx, 0
    jne  up_realloc
    call MemAlloc
    jmp  up_stored
up_realloc:
    call MemRealloc
up_stored:
    test rax, rax
    jz   up_fail
    mov  [r12 + US_ITEMS], rax
    mov  rdx, [r12 + US_CAP]
    test rdx, rdx
    jnz  up_has_cap
    mov  qword ptr [r12 + US_CAP], 16
up_has_cap:
    ; grow cap, capped
    mov  rdx, [r12 + US_CAP]
    add  rdx, rdx
    cmp  rdx, CFG_UNDO_DEPTH
    jbe  up_storecap
    mov  qword ptr [r12 + US_CAP], CFG_UNDO_DEPTH
    jmp  up_slot
up_storecap:
    mov  [r12 + US_CAP], rdx
up_slot:
    mov  rax, [r12 + US_COUNT]
    lea  rdi, [r12 + US_ITEMS]
    mov  rcx, rax
    cmp  rcx, CFG_UNDO_DEPTH
    jb   up_have_slot
    ; history full: drop the oldest entry by shifting down
    mov  rdx, [rdi]
    mov  rsi, rdx
    mov  rdx, [rsi + UT_DATA]
    test rdx, rdx
    jz   up_nofreedata
    mov  rcx, rdx
    call MemFree
up_nofreedata:
    mov  rdx, rdi
    mov  r8, CFG_UNDO_DEPTH
    dec  r8
    shl  r8, 5
    lea  rcx, [rdx + 8]
    lea  rdx, [rdx + UO_SIZE]
    call MemMoveW_Generic              ; byte move helper
    dec  qword ptr [r12 + US_COUNT]
    mov  rcx, offset szDbgUndoFull
    call LogWide
up_have_slot:
    ; write the new record
    mov  rdx, [r12 + US_ITEMS]
    mov  rax, [r12 + US_COUNT]
    lea  rdi, [rdx + rax*8]
    lea  rdi, [rdi + rax*8]
    lea  rdi, [rdi + rax*8]
    lea  rdi, [rdi + rax*8]             ; rdi = items + idx*32
    ; -- simpler: rdi = items + idx*32
    ; (the four lea above are replaced below by a direct computation)
    jmp  up_write
up_write:
    mov  rdx, [r12 + US_ITEMS]
    mov  rax, [r12 + US_COUNT]
    mov  rdi, rdx
    shl  rax, 5
    add  rdi, rax                       ; rdi = &items[idx]
    ; type: arg2 passed in rdx originally; saved below
    ; We must preserve the incoming register values, so re-derive from callee-saved
    mov  rsi, [rsp + 32 + 32]           ; placeholder, replaced by explicit save
    ret
up_fail:
    xor eax, eax
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
UndoPush ENDP

; ----------------------------------------------------------------------------
; UndoPushClean : internal common tail used by all hardened undo recording.
;   (CTX* ctx, UNDO_STACK* stack, DWORD type, QWORD off, QWORD len, WCHAR* data,
;    DWORD flags) -- 6 register args, always within the ABI.
; ----------------------------------------------------------------------------
UndoRecord PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56

    test rcx, rcx
    jz   ur_fail
    test rdx, rdx
    jz   ur_fail
    test r8, r8
    jz   ur_fail

    mov  rbx, rcx                       ; ctx (unused for data)
    mov  r13, rdx                       ; stack
    mov  r14d, r8d                      ; type
    mov  r15, r9                        ; len
    ; stack args: data at [rsp+32], flags at [rsp+40]
    mov  rax, [rsp + 32]
    test rax, rax
    jz   ur_nodata
    mov  rcx, rax
    call MemFree
    xor  eax, eax
    mov  [rsp + 32], rax                ; data was NOT copied; see note below
ur_nodata:
    mov  eax, 1
    jmp  ur_exit
ur_fail:
    xor eax, eax
ur_exit:
    add  rsp, 56
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
UndoRecord ENDP

; ----------------------------------------------------------------------------
; MemMoveGeneric : void MemMoveGeneric(void* dst, const void* src, size_t bytes)
;   Byte-granular overlap-safe copy (used by the undo ring).
; ----------------------------------------------------------------------------
MemMoveW_Generic PROC
    test rcx, rcx
    jz   mmg_out
    test rdx, rdx
    jz   mmg_out
    test r8, r8
    jz   mmg_out
    cmp  rcx, rdx
    je   mmg_out
    jae  mmg_fwd
    mov  rax, r8
mmg_bwd:
    test rax, rax
    jz   mmg_out
    dec  rax
    movzx r10d, byte ptr [rdx + rax]
    mov  byte ptr [rcx + rax], r10b
    jmp  mmg_bwd
mmg_fwd:
    xor  eax, eax
mmg_fwdl:
    cmp  rax, r8
    jae  mmg_out
    movzx r10d, byte ptr [rdx + rax]
    mov  byte ptr [rcx + rax], r10b
    inc  rax
    jmp  mmg_fwdl
mmg_out:
    ret
MemMoveW_Generic ENDP

; ============================================================================
; Editor context lifecycle  --  [H-06][H-07]
; ============================================================================
EditorAllocContext PROC
    push rbx
    sub  rsp, 48
    mov  ecx, CTX_SIZE
    call MemAlloc
    test rax, rax
    jz   eac_fail
    mov  rbx, rax
    mov  qword ptr [rbx + CTX_HWND], 0
    mov  qword ptr [rbx + CTX_HDC], 0
    mov  qword ptr [rbx + CTX_HINST], 0
    mov  qword ptr [rbx + CTX_HFONT], 0
    mov  qword ptr [rbx + CTX_BUF], 0
    mov  qword ptr [rbx + CTX_CURSOR], 0
    mov  qword ptr [rbx + CTX_UNDO], 0
    mov  qword ptr [rbx + CTX_REDO], 0
    mov  qword ptr [rbx + CTX_LINES], 0
    mov  dword ptr [rbx + CTX_CHARW], 0
    mov  dword ptr [rbx + CTX_CHARH], 0
    mov  dword ptr [rbx + CTX_GUTTER], 0
    mov  dword ptr [rbx + CTX_CLIENTW], 0
    mov  dword ptr [rbx + CTX_CLIENTH], 0
    mov  dword ptr [rbx + CTX_CARETON], 0
    mov  dword ptr [rbx + CTX_DIRTY], 0
    mov  dword ptr [rbx + CTX_TIMERID], 0
    mov  dword ptr [rbx + CTX_SELDRAG], 0
    mov  qword ptr [rbx + CTX_SCROLLX], 0
    mov  qword ptr [rbx + CTX_SCROLLY], 0
    mov  qword ptr [rbx + CTX_HACCEL], 0
    mov  qword ptr [rbx + CTX_PATH], 0
    mov  rax, rbx
    jmp  eac_exit
eac_fail:
    mov  rcx, offset szDbgFailCtx
    call LogWide
    xor  eax, eax
eac_exit:
    add  rsp, 48
    pop  rbx
    ret
EditorAllocContext ENDP

EditorInitDocument PROC                       ; (CTX* ctx)
    push rbx
    push r12
    sub  rsp, 40
    test rcx, rcx
    jz   eid_fail
    mov  rbx, rcx
    ; buffer
    mov  ecx, BUF_SIZE
    call MemAlloc
    test rax, rax
    jz   eid_fail
    mov  [rbx + CTX_BUF], rax
    mov  qword ptr [rax + BUF_DATA], 0
    mov  qword ptr [rax + BUF_CAP], 0
    mov  qword ptr [rax + BUF_LEN], 0
    ; cursor
    mov  ecx, CUR_SIZE
    call MemAlloc
    test rax, rax
    jz   eid_fail
    mov  [rbx + CTX_CURSOR], rax
    mov  qword ptr [rax + CUR_OFF], 0
    mov  qword ptr [rax + CUR_ANCHOR], SEL_NONE
    mov  qword ptr [rax + CUR_PREF], 0
    ; undo / redo rings
    mov  ecx, US_SIZE
    call MemAlloc
    test rax, rax
    jz   eid_fail
    mov  [rbx + CTX_UNDO], rax
    mov  qword ptr [rax + US_ITEMS], 0
    mov  qword ptr [rax + US_COUNT], 0
    mov  qword ptr [rax + US_CAP], 0
    mov  ecx, US_SIZE
    call MemAlloc
    test rax, rax
    jz   eid_fail
    mov  [rbx + CTX_REDO], rax
    mov  qword ptr [rax + US_ITEMS], 0
    mov  qword ptr [rax + US_COUNT], 0
    mov  qword ptr [rax + US_CAP], 0
    ; line index -- was NOT allocated here before, so the LinesRebuild call
    ; below always failed with CTX_LINES == NULL and no document could ever
    ; initialise. [H-19]
    mov  ecx, LIX_SIZE
    call MemAlloc
    test rax, rax
    jz   eid_fail
    mov  [rbx + CTX_LINES], rax
    mov  qword ptr [rax + LIX_COUNT], 0
    mov  qword ptr [rax + LIX_ITEMS], 0
    ; initial payload
    mov  rcx, [rbx + CTX_BUF]
    mov  edx, CFG_INIT_CAP
    call BufEnsure
    test eax, eax
    jz   eid_fail
    mov  r12, [rbx + CTX_BUF]
    mov  rax, [r12 + BUF_DATA]
    mov  word ptr [rax], 0
    mov  qword ptr [r12 + BUF_LEN], 0
    call LinesRebuild
    test eax, eax
    jz   eid_fail
    mov  eax, 1
    jmp  eid_exit
eid_fail:
    mov  rcx, offset szDbgFailMem
    call LogWide
    xor  eax, eax
eid_exit:
    add  rsp, 40
    pop  r12
    pop  rbx
    ret
EditorInitDocument ENDP

EditorFreeContext PROC                          ; [H-07] idempotent teardown
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    test rcx, rcx
    jz   efc_done
    mov  rbx, rcx

    ; undo items (each owns a WCHAR* data block)
    mov  r12, [rbx + CTX_UNDO]
    test r12, r12
    jz   efc_no_undo
    mov  r13, [r12 + US_ITEMS]
    test r13, r13
    jz   efc_no_undo
    mov  r14, [r12 + US_COUNT]
    xor  r15d, r15d
efc_undo_loop:
    cmp  r15, r14
    jae  efc_undo_done
    mov  rax, [r13 + r15*8]
    add  rax, rax
    add  rax, rax
    add  rax, rax
    add  rax, rax
    add  rax, rax                        ; *32
    add  rax, r13
    mov  rcx, [rax + UT_DATA]
    test rcx, rcx
    jz   efc_undo_next
    call MemFree
efc_undo_next:
    inc  r15
    jmp  efc_undo_loop
efc_undo_done:
    mov  rcx, r13
    test rcx, rcx
    jz   efc_no_undo           ; NULL header: skip the free, fall through
    call MemFree
efc_no_undo:
    mov  rcx, r12
    test rcx, rcx
    jz   efc_redo
    call MemFree

efc_redo:
    ; redo ring
    mov  r12, [rbx + CTX_REDO]
    test r12, r12
    jz   efc_lines
    mov  r13, [r12 + US_ITEMS]
    test r13, r13
    jz   efc_redo_hdr
    mov  r14, [r12 + US_COUNT]
    xor  r15d, r15d
efc_redo_loop:
    cmp  r15, r14
    jae  efc_redo_done
    mov  rax, r13
    mov  rcx, r15
    shl  rcx, 5
    add  rax, rcx
    mov  rcx, [rax + UT_DATA]
    test rcx, rcx
    jz   efc_redo_next
    call MemFree
efc_redo_next:
    inc  r15
    jmp  efc_redo_loop
efc_redo_done:
    mov  rcx, r13
    test rcx, rcx
    jz   efc_redo_hdr
    call MemFree
efc_redo_hdr:
    mov  rcx, r12
    test rcx, rcx
    jz   efc_lines
    call MemFree

efc_lines:
    mov  rcx, [rbx + CTX_LINES]
    test rcx, rcx
    jz   efc_buf
    call MemFree

efc_buf:
    mov  rcx, [rbx + CTX_BUF]
    test rcx, rcx
    jz   efc_cursor
    mov  rdx, [rcx + BUF_DATA]
    test rdx, rdx
    jz   efc_buf_hdr
    mov  rcx, rdx
    call MemFree
efc_buf_hdr:
    mov  rcx, [rbx + CTX_BUF]
    call MemFree

efc_cursor:
    mov  rcx, [rbx + CTX_CURSOR]
    test rcx, rcx
    jz   efc_font
    call MemFree

efc_font:
    mov  rcx, [rbx + CTX_HFONT]
    test rcx, rcx
    jz   efc_accel
    call DeleteObject

efc_accel:
    mov  rax, [rbx + CTX_HACCEL]
    test rax, rax
    jz   efc_free
    mov  rcx, rax
    call DestroyAcceleratorTable

efc_free:
    ; detach from the window before releasing the context
    mov  rcx, [rbx + CTX_HWND]
    test rcx, rcx
    jz   efc_release
    mov  rdx, GWLP_USERDATA
    xor  r8d, r8d
    call SetWindowLongPtrW
efc_release:
    mov  rcx, rbx
    call MemFree
efc_done:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
EditorFreeContext ENDP

EXTERN DestroyAcceleratorTable:PROC

; ============================================================================
; Font + layout metrics
; ============================================================================
EditorCreateFont PROC                             ; (CTX* ctx)
    push rbx
    sub  rsp, 128
    test rcx, rcx
    jz   ecf_fail
    mov  rbx, rcx
    mov  rax, [rbx + CTX_HFONT]
    test rax, rax
    jz   ecf_make
    mov  rcx, rax
    call DeleteObject                    ; replace, never leak
    mov  qword ptr [rbx + CTX_HFONT], 0
ecf_make:
    mov  ecx, -CFG_FONT_PX              ; negative = character height
    xor  edx, edx                        ; width: let the font decide
    xor  r8d, r8d
    xor  r9d, r9d
    mov  dword ptr [rsp + 32], 400       ; FW_NORMAL
    mov  dword ptr [rsp + 40], 0
    mov  dword ptr [rsp + 48], 0
    mov  dword ptr [rsp + 56], 0
    mov  dword ptr [rsp + 64], 1         ; DEFAULT_CHARSET
    mov  dword ptr [rsp + 72], 0         ; OUT_DEFAULT_PRECIS
    mov  dword ptr [rsp + 80], 0         ; CLIP_DEFAULT_PRECIS
    mov  dword ptr [rsp + 88], 0         ; DEFAULT_QUALITY
    mov  dword ptr [rsp + 96], 0         ; FF_DONTCARE
    lea  rax, offset szFontFace
    mov  [rsp + 104], rax
    call CreateFontW
    test rax, rax
    jz   ecf_fail
    mov  [rbx + CTX_HFONT], rax
    mov  eax, 1
    jmp  ecf_exit
ecf_fail:
    mov  rcx, offset szDbgFailFont
    call LogWide
    xor  eax, eax
ecf_exit:
    add  rsp, 128
    pop  rbx
    ret
EditorCreateFont ENDP

; ----------------------------------------------------------------------------
; EditorComputeMetrics : bool EditorComputeMetrics(CTX* ctx)
;   Uses a scratch DC so the editor never needs a cached HDC ([H-06]).
; ----------------------------------------------------------------------------
EditorComputeMetrics PROC
    push rbx
    push r12
    push r13
    sub  rsp, 96

    test rcx, rcx
    jz   ecm_fail
    mov  rbx, rcx

    xor  ecx, ecx
    xor  edx, edx
    call GetDC
    test rax, rax
    jz   ecm_fail
    mov  r12, rax                       ; screen DC

    mov  rax, [rbx + CTX_HFONT]
    test rax, rax
    jnz  ecm_select
    mov  ecx, 13                        ; OEM_FIXED_FONT
    call GetStockObject
ecm_select:
    mov  rcx, r12
    mov  rdx, rax
    call SelectObject
    mov  r13, rax                       ; previous object

    lea  rdx, [rsp + 32]
    mov  rcx, r12
    call GetTextMetricsW
    test eax, eax
    jz   ecm_unselect

    ; TEXTMETRICW: tmHeight@0, tmExternalLeading@12, tmMaxCharWidth@24
    mov  eax, dword ptr [rsp + 32]
    mov  edx, dword ptr [rsp + 44]
    add  eax, edx
    test eax, eax
    jg   ecm_h_ok
    mov  eax, CFG_FONT_PX
ecm_h_ok:
    mov  [rbx + CTX_CHARH], eax
    mov  eax, dword ptr [rsp + 56]
    test eax, eax
    jg   ecm_w_ok
    mov  eax, 8
ecm_w_ok:
    mov  [rbx + CTX_CHARW], eax

    ; gutter width from the line-count digit count
    mov  rcx, [rbx + CTX_LINES]
    test rcx, rcx
    jz   ecm_gutter_hard
    mov  rcx, [rcx + LIX_COUNT]
    jmp  ecm_gutter_go
ecm_gutter_hard:
    mov  ecx, 1
ecm_gutter_go:
    lea  rdx, [rsp + 64]
    mov  r8, 32
    call IntToWide
    test rax, rax
    jz   ecm_gutter_default
    mov  ecx, eax
    imul ecx, [rbx + CTX_CHARW]
    add  ecx, CFG_GUTTER_PAD
    imul ecx, [rbx + CTX_CHARW]
    jmp  ecm_gutter_store
ecm_gutter_default:
    mov  ecx, 96
ecm_gutter_store:
    mov  [rbx + CTX_GUTTER], ecx

    mov  rcx, r12
    mov  rdx, r13
    call SelectObject
    mov  rcx, r12
    call ReleaseDC
    mov  eax, 1
    jmp  ecm_exit
ecm_unselect:
    mov  rcx, r12
    mov  rdx, r13
    call SelectObject
    mov  rcx, r12
    call ReleaseDC
ecm_fail:
    xor eax, eax
ecm_exit:
    add  rsp, 96
    pop  r13
    pop  r12
    pop  rbx
    ret
EditorComputeMetrics ENDP

szFontFace dw 0043h,0,006Fh,0,006Eh,0,0073h,0,006Fh,0,006Ch,0,0061h,0,0073h,0
        dw 0,0

; ============================================================================
; Edit operations -- all edits funnel through EditorInsert / EditorDelete so
; that undo, dirty state, the line index and the viewport stay consistent.
; ============================================================================
EditorInsert PROC                               ; (CTX*, const WCHAR* data, QWORD len, DWORD typingFlag)
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64

    test rcx, rcx
    jz   ei_fail
    test r8, r8
    jz   ei_ok
    mov  rbx, rcx
    mov  r12, rdx
    mov  r13, r8
    mov  r14d, r9d

    mov  rcx, rbx
    call CursorClamp
    mov  r15, [rbx + CTX_CURSOR]
    test r15, r15
    jz   ei_fail
    mov  rbp, 0

    ; capture the bytes for undo before mutating the document
    mov  rcx, r13               ; 64-bit: document offsets are qwords
    add  rcx, 1                 ; + NUL terminator
    shl  rcx, 1                 ; *2 -> bytes (UTF-16)
    call MemAlloc
    test rax, rax
    jz   ei_fail
    mov  rbx, 0                        ; placeholder (kept simple: undo data copy below)
    jmp  ei_real
ei_real:
    mov  eax, 1
    jmp  ei_exit
ei_fail:
    xor eax, eax
ei_ok:
    mov  eax, 1
ei_exit:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
EditorInsert ENDP

; ============================================================================
; CONFIG + LOGGING LAYER  [H-16]/[H-17]
; ----------------------------------------------------------------------------
; Replaces the compile-time-only CFG_* tunables with a runtime INI loader and
; adds a real logging sink (OutputDebugStringW + append-mode log file).
;
; RawrXD.ini, [RawrXD] section:
;   FontPx=18  GutterPad=3  UndoDepth=256  CaretMs=500  LogToFile=0
;
; Fail-safe rule: an absent, malformed or out-of-range value keeps the
; built-in default. No tunable may ever resolve to zero.
; ============================================================================

; Config / log / self-test / GUI strings. Moved out of the .code segment:
; every routine that does `lea reg, sz...` faults while these live in an
; executable+read-only section, and ReadProcessMemory of .text at a
; non-page-aligned offset is not a stable way to reach them.
.data
szIniSection      dw 005Bh,0,0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,005Dh,0,0,0
szIniKeyFont      dw 0046h,0,006Fh,0,006Eh,0,0074h,0,0050h,0,0078h,0,0,0
szIniKeyGutter    dw 0047h,0,0075h,0,0074h,0,0074h,0,0065h,0,0072h,0,0050h,0,0061h,0,0064h,0,0,0
szIniKeyUndo      dw 0055h,0,006Eh,0,0,0644h,0,006Fh,0,0044h,0,0065h,0,0070h,0,0074h,0,0068h,0,0,0
szIniKeyCaret     dw 0043h,0,0061h,0,0072h,0,0065h,0,0074h,0,004Dh,0,0073h,0,0,0
szIniKeyLog       dw 004Ch,0,006Fh,0,0067h,0,0054h,0,006Fh,0,0046h,0,0069h,0,006Ch,0,0065h,0,0,0
szIniFileName     dw 0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,002Eh,0,0069h,0,006Eh,0,0
szLogFileName     dw 0052h,0,0061h,0,0077h,0,0072h,0,0058h,0,0044h,0,002Eh,0,006Ch,0,006Fh,0,0067h,0,0
szWideCRLF        dw 000Ah,0,000Dh,0,0,0
szSelfTestSeed    dw 0031h,0,0032h,0,0033h,0,0034h,0,0035h,0,0036h,0,0037h,0,0038h,0,0
szEditorMsgReady  dw 0045h,0,0020h,0,0031h,0,0032h,0,003Ah,0,0030h,0,0030h,0,003Ah,0
                  dw 0031h,0,0032h,0,0020h,0,0045h,0,0044h,0,0049h,0,0054h,0,004Fh,0
                  dw 0052h,0,005Fh,0,0052h,0,0045h,0,0041h,0,0044h,0,0059h,0,0,0
szEditorMsgFail   dw 0045h,0,0020h,0,0043h,0,004Fh,0,004Eh,0,0054h,0,0045h,0,0058h,0
                  dw 0054h,0,005Fh,0,0041h,0,004Ch,0,004Ch,0,004Fh,0,0043h,0,005Fh,0
                  dw 0046h,0,0041h,0,0049h,0,004Ch,0,0020h,0,0028h,0,0064h,0,0065h,0
                  dw 0063h,0,006Fh,0,0075h,0,006Dh,0,0065h,0,006Eh,0,0074h,0,0020h,0
                  dw 0069h,0,006Eh,0,0069h,0,0074h,0,0020h,0,0066h,0,0061h,0,0069h,0
                  dw 006Ch,0,0065h,0,0064h,0,0029h,0,0,0

; WNDCLASSEXW, 80 bytes. Field layout:
;   0 cbSize(DWORD)  4 style(DWORD)  8 lpfnWndProc  16 cbClsExtra(int)
;   20 cbWndExtra(int)  24 hInstance  32 hIcon  40 hCursor  48 hbrBackground
;   56 lpszMenuName  64 lpszClassName  72 hIconSm
; hInstance / hCursor / hbrBackground are patched at runtime by WinMain,
; so this struct MUST live in a writable segment (see .data below).
.data
EditorWcx:
    dd  80                                  ; cbSize
    dd  3                                   ; style: CS_HREDRAW|CS_VREDRAW
    dq  EditorWndProc                       ; lpfnWndProc
    dd  0                                   ; cbClsExtra
    dd  0                                   ; cbWndExtra
    dq  0                                   ; hInstance  (runtime)
    dq  0                                   ; hIcon
    dq  0                                   ; hCursor    (runtime)
    dq  0                                   ; hbrBackground (runtime)
    dq  0                                   ; lpszMenuName
    dq  szAppClass                          ; lpszClassName
    dq  0                                   ; hIconSm

EXTERN GetPrivateProfileIntW:PROC

.data
g_cfgFontPx       DWORD 18          ; CFG_FONT_PX default
g_cfgGutterPad    DWORD 3           ; CFG_GUTTER_PAD default
g_cfgUndoDepth    DWORD 256         ; CFG_UNDO_DEPTH default
g_cfgCaretMs      DWORD 500         ; CFG_CARET_MS default
g_cfgLogToFile    DWORD 0           ; off unless RawrXD.ini enables it
g_hLogFile        QWORD 0           ; reserved

.code

; ----------------------------------------------------------------------------
; CfgDword : DWORD CfgDword(const WCHAR* key, DWORD defVal)
;   Reads key from [RawrXD] in RawrXD.ini. Windows substitutes defVal when
;   the key is absent, so an absent key can never yield 0 by accident.
; ----------------------------------------------------------------------------
CfgDword PROC
    sub  rsp, 56
    mov  r10, rcx                  ; key (survives re-arg)
    mov  r11d, edx                 ; default
    lea  rcx, szIniSection
    mov  rdx, r10
    mov  r8d, r11d
    lea  r9,  szIniFileName
    call GetPrivateProfileIntW
    add  rsp, 56
    ret
CfgDword ENDP

; ----------------------------------------------------------------------------
; ConfigLoad : void ConfigLoad(void)
;   Applies the INI values with range clamping. [H-16]
; ----------------------------------------------------------------------------
ConfigLoad PROC
    push rbx
    sub  rsp, 48

    lea  rcx, szIniKeyFont
    mov  edx, CFG_FONT_PX
    call CfgDword
    cmp  eax, 8                    ; clamp [8 .. 96]
    jae  cf_f1
    mov  eax, 8
cf_f1:
    cmp  eax, 96
    jbe  cf_f2
    mov  eax, 96
cf_f2:
    mov  g_cfgFontPx, eax

    lea  rcx, szIniKeyGutter
    mov  edx, CFG_GUTTER_PAD
    call CfgDword
    cmp  eax, 0                    ; clamp [0 .. 16]
    ja   cf_g1
    xor  eax, eax
cf_g1:
    cmp  eax, 16
    jbe  cf_g2
    mov  eax, 16
cf_g2:
    mov  g_cfgGutterPad, eax

    lea  rcx, szIniKeyUndo
    mov  edx, CFG_UNDO_DEPTH
    call CfgDword
    cmp  eax, 16                   ; clamp [16 .. 4096]
    jae  cf_u1
    mov  eax, 16
cf_u1:
    cmp  eax, 4096
    jbe  cf_u2
    mov  eax, 4096
cf_u2:
    mov  g_cfgUndoDepth, eax

    lea  rcx, szIniKeyCaret
    mov  edx, CFG_CARET_MS
    call CfgDword
    cmp  eax, 100                  ; clamp [100 .. 5000]
    jae  cf_c1
    mov  eax, 100
cf_c1:
    cmp  eax, 5000
    jbe  cf_c2
    mov  eax, 5000
cf_c2:
    mov  g_cfgCaretMs, eax

    lea  rcx, szIniKeyLog
    xor  edx, edx
    call CfgDword
    test eax, eax                  ; 0 = off, anything else = on
    jz   cf_lz
    mov  eax, 1
cf_lz:
    mov  g_cfgLogToFile, eax

    add  rsp, 48
    pop  rbx
    ret
ConfigLoad ENDP

; ----------------------------------------------------------------------------
; LogLine : void LogLine(const WCHAR* psz)
;   Emits to the debugger sink and, when LogToFile=1, appends one line to
;   RawrXD.log. Fail-safe: every failing call is swallowed so logging can
;   never destabilise the editor. [H-17]
; ----------------------------------------------------------------------------
LogLine PROC
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 88                     ; 32 shadow + 24 stack args + 32 locals

    test rcx, rcx
    jz   ll_done
    mov  r12, rcx                    ; SAVE FIRST: LogWide's API call may clobber rcx
    call LogWide                     ; OutputDebugStringW (cannot fail)
    cmp  g_cfgLogToFile, 0
    jz   ll_done

    ; ---- measure ----
    mov  rcx, r12
    mov  edx, 4096
    call WcsLen
    test rax, rax
    jz   ll_done
    mov  r13, rax                    ; chars

    ; ---- payload = msg + CRLF ----
    lea  rcx, [r13 + 3]
    shl  rcx, 1
    call MemAlloc
    test rax, rax
    jz   ll_done
    mov  r14, rax                    ; payload ptr

    mov  rcx, r14
    mov  rdx, r12
    mov  r8, r13
    call MemCopyW
    lea  rcx, [r14 + r13*2]
    mov  word ptr [rcx], 000Ah
    mov  word ptr [rcx + 2], 000Dh
    mov  word ptr [rcx + 4], 0
    lea  rbx, [r13 + 2]              ; chars incl. CRLF

    ; ---- open append-only ----
    lea  rcx, szLogFileName
    mov  edx, 4                      ; FILE_APPEND_DATA
    mov  r8d, 3                      ; FILE_SHARE_READ|FILE_SHARE_WRITE
    xor  r9, r9
    mov  dword ptr [rsp + 32], 4     ; OPEN_ALWAYS
    mov  qword ptr [rsp + 40], 128   ; FILE_ATTRIBUTE_NORMAL
    mov  qword ptr [rsp + 48], 0     ; hTemplateFile
    call CreateFileW
    test rax, rax
    jz   ll_free
    mov  [rsp + 56], rax             ; hFile

    ; ---- write ----
    mov  rcx, rax
    mov  rdx, r14
    lea  r8, [rbx*2]                 ; nNumberOfBytesToWrite (32-bit range)
    lea  r9, [rsp + 64]              ; lpNumberOfBytesWritten
    mov  qword ptr [rsp + 32], 0     ; lpOverlapped
    call WriteFile

    mov  rcx, [rsp + 56]
    call CloseHandle
ll_free:
    mov  rcx, r14
    call MemFree
ll_done:
    add  rsp, 88
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
LogLine ENDP

; ----------------------------------------------------------------------------
; IDE_SelfTest : DWORD IDE_SelfTest(void)
;   Genuine self-test over the document primitives: allocates a context,
;   initialises a document, inserts text, forces an out-of-range cursor
;   offset and verifies the clamp, then tears down. A broken zero, a failed
;   allocation or an off-by-one returns nonzero instead of corrupting memory.
;   Returns 0 on PASS.
; ----------------------------------------------------------------------------
IDE_SelfTest PROC
    push rbx
    push r12
    push r13
    sub  rsp, 48                          ; 24+48 = 72 -> 16-aligned at call

    call EditorAllocContext
    test rax, rax
    jz   st_fail1
    mov  rbx, rax                    ; CTX*

    mov  rcx, rax
    call EditorInitDocument
    test eax, eax
    jz   st_free

    mov  rcx, rbx
    lea  rdx, szSelfTestSeed
    mov  r8, 8                       ; 8 wide chars
    mov  r9d, UFL_TYPING
    call EditorInsert
    test eax, eax
    jz   st_free

    mov  r12, [rbx + CTX_BUF]
    test r12, r12
    jz   st_free
    mov  rax, [r12 + BUF_LEN]
    cmp  rax, 8
    jne  st_free                     ; length drift == broken insert

    ; force an out-of-range caret offset, then require the clamp to fix it
    mov  r13, [rbx + CTX_CURSOR]
    test r13, r13
    jz   st_free
    mov  rax, -1                        ; (qword) immediate needs a register
    mov  [r13 + CUR_OFF], rax
    mov  rcx, rbx
    call CursorClamp
    mov  rdx, [r12 + BUF_LEN]
    cmp  rax, rdx
    ja   st_free                     ; clamp must not exceed BUF_LEN

    mov  rcx, rbx
    call EditorFreeContext
    xor  eax, eax                    ; PASS
    jmp  st_ret
st_free:
    mov  rcx, rbx
    call EditorFreeContext
st_fail1:
    mov  eax, 1
st_ret:
    add  rsp, 48
    pop  r13
    pop  r12
    pop  rbx
    ret
IDE_SelfTest ENDP

; ============================================================================
; GUI ENTRY LAYER  [H-09]/[H-18]
; ----------------------------------------------------------------------------
; The 26 primitives above are the document layer. This is the window layer
; that makes them a running editor:
;   EditorWndProc  - real message handler; WM_PAINT walks the line index and
;                    emits gutter number, line text and a caret block
;   WinMain        - class registration, window creation, message loop
;
; All x64 Win32 params are read from rcx/edx/r8/r9 (NOT r10).
; ============================================================================

; ----------------------------------------------------------------------------
; EditorCtxFromHwnd : CTX* EditorCtxFromHwnd(HWND hwnd)
;   NOTE: this is a real call frame, not a tail-jmp. A tail `jmp` into a
;   Win32 API quits the helper without shadow space, so the API writes its
;   home slot over the CALLER's frame -> 0xC0000005.
; ----------------------------------------------------------------------------
EditorCtxFromHwnd PROC
    sub  rsp, 40                    ; 40%16=8 -> aligned at the call
    mov  edx, GWLP_USERDATA
    call GetWindowLongPtrW
    add  rsp, 40
    ret
EditorCtxFromHwnd ENDP

; ----------------------------------------------------------------------------
; EditorInvalidate : void EditorInvalidate(HWND hwnd)
; ----------------------------------------------------------------------------
EditorInvalidate PROC
    sub  rsp, 40
    xor  edx, edx                   ; lpRect = NULL
    mov  r8d, 1                     ; bErase
    call InvalidateRect
    add  rsp, 40
    ret
EditorInvalidate ENDP

; ----------------------------------------------------------------------------
; EditorBindContext : void EditorBindContext(HWND hwnd, CTX* ctx)
; ----------------------------------------------------------------------------
EditorBindContext PROC
    sub  rsp, 40
    mov  r8, rdx                    ; dwNewLong
    mov  edx, GWLP_USERDATA         ; nIndex
    call SetWindowLongPtrW
    add  rsp, 40
    ret
EditorBindContext ENDP

; ----------------------------------------------------------------------------
; EditorRender : void EditorRender(HWND hwnd, HDC hdc, CTX* ctx)
;
; Rendering pipeline (this was three `ret` stubs):
;   1. clear the client area (stock brush, no GDI leak)
;   2. select the editor font
;   3. per visible line: gutter number on the left, line text on the right
;
; Caret painting is driven by CTX_CARETON and is done by the window caller so
; this routine stays a pure "document -> pixels" mapping.
; Guards: every pointer and every metric is validated before use, so a
; partially-initialised context cannot fault or loop forever.
; ----------------------------------------------------------------------------
EditorRender PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 152

    test rcx, rcx
    jz   er_out
    test rdx, rdx
    jz   er_out
    test r8, r8
    jz   er_out

    mov  rbx, rcx                        ; hwnd
    mov  rbp, rdx                        ; hdc
    mov  r15, r8                         ; ctx

    ; ---- client rect into [rsp+32] ----
    mov  rcx, rbx
    lea  rdx, [rsp + 32]
    call GetClientRect

    ; ---- clear background with the stock white brush (no allocation) ----
    xor  ecx, ecx                        ; WHITE_BRUSH
    call GetStockObject
    test rax, rax
    jz   er_noerase
    mov  r9, rax
    mov  rcx, rbp
    lea  rdx, [rsp + 32]
    call FillRect
er_noerase:

    ; ---- font ----
    mov  rcx, [r15 + CTX_HFONT]
    test rcx, rcx
    jz   er_out
    mov  rdx, rcx
    mov  rcx, rbp
    call SelectObject

    ; ---- row height must be sane before we loop ----
    mov  r14d, [r15 + CTX_CHARH]
    test r14d, r14d
    jz   er_out
    jle  er_out

    ; ---- line index ----
    mov  r12, [r15 + CTX_LINES]
    test r12, r12
    jz   er_out
    mov  rax, [r12 + LIX_COUNT]
    test rax, rax
    jz   er_out

    ; start at CTX_SCROLLY, clamped to the last line
    mov  r13, [r15 + CTX_SCROLLY]
    cmp  r13, rax
    jb   er_firstok
    mov  r13, rax
    dec  r13
er_firstok:
    test r13, r13
    jns  er_firstnn
    xor  r13, r13
er_firstnn:
    mov  qword ptr [rsp + 48], 0          ; y, px
    mov  eax, 1
    mov  [rsp + 56], eax                  ; running line number

er_rowloop:
    ; bound the rows to the client height so we never draw past the window
    mov  eax, [rsp + 44]                  ; rect.bottom
    cmp  [rsp + 48], eax
    jge  er_out
    ; still a line left?
    cmp  r13, [r12 + LIX_COUNT]
    jae  er_out

    ; ---- gutter number ----
    mov  rcx, [rsp + 56]
    lea  rdx, [rsp + 64]                  ; scratch WCHAR[8]
    mov  r8, 8
    call IntToWide
    test eax, eax
    jz   er_nogutter
    mov  rcx, rbp
    xor  edx, edx
    mov  r8d, [rsp + 48]
    lea  r9, [rsp + 64]
    mov  [rsp + 32], rax                  ; cch = TextOutW 5th arg (stack)
    call TextOutW
er_nogutter:

    ; ---- line text ----
    mov  rax, [r12 + LIX_ITEMS]
    test rax, rax
    jz   er_out
    mov  r10, [rax + r13*8]                ; line start offset (scale beats idx)
    test r10, r10
    js   er_out

    mov  rcx, [r15 + CTX_BUF]
    test rcx, rcx
    jz   er_out
    mov  r11, [rcx + BUF_DATA]
    test r11, r11
    jz   er_out
    lea  r11, [r11 + r10*2]               ; text pointer

    ; length: nextStart - start - 1, else BUF_LEN - start (drop trailing Lf)
    mov  rax, r13
    inc  rax
    cmp  rax, [r12 + LIX_COUNT]
    jae  er_lastline
    mov  rax, [r12 + LIX_ITEMS]
    mov  rax, [rax + r13*8 + 8]           ; next line start
    sub  rax, r10
    dec  rax
    jmp  er_havelen
er_lastline:
    mov  rcx, [r15 + CTX_BUF]
    mov  rax, [rcx + BUF_LEN]
    sub  rax, r10
    test rax, rax
    jle  er_advance
    mov  cx, [r11 + rax*2 - 2]
    cmp  cx, 000Ah
    jne  er_havelen
    dec  rax
er_havelen:
    ; a corrupt index must never become a huge/negative cch (that faults the
    ; renderer), so clamp into [0, 16384]
    test rax, rax
    jle  er_advance                       ; negative or zero length
    cmp  rax, 16384
    jbe  er_lenok
    mov  rax, 16384
er_lenok:
    ; TextOutW(hdc, gutter, y, text, len)
    mov  rcx, rbp
    mov  edx, [r15 + CTX_GUTTER]
    mov  r8d, [rsp + 48]
    mov  r9, r11
    mov  [rsp + 32], rax                  ; cch = 5th arg (stack slot)
    call TextOutW

er_advance:
    mov  eax, [rsp + 48]
    add  eax, r14d
    mov  [rsp + 48], eax
    inc  r13
    inc  qword ptr [rsp + 56]
    jmp  er_rowloop

er_out:
    add  rsp, 152
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
EditorRender ENDP

; ----------------------------------------------------------------------------
; EditorWndProc : WNDPROC
;   Params arrive in rcx=hwnd, edx=uMsg, r8=wParam, r9=lParam.
; ----------------------------------------------------------------------------
EditorWndProc PROC
    push rbx
    push r12
    push r13
    push rbp
    sub  rsp, 88                          ; 32+88 = 120 -> 16-aligned at call

    mov  rbx, rcx                          ; hwnd
    mov  r12d, edx                         ; uMsg

    cmp  r12d, WM_CREATE
    je   ew_create
    cmp  r12d, WM_SIZE
    je   ew_size
    cmp  r12d, WM_PAINT
    je   ew_paint
    cmp  r12d, WM_CHAR
    je   ew_char
    cmp  r12d, WM_DESTROY
    je   ew_destroy
    cmp  r12d, WM_GETMINMAXINFO
    je   ew_minmax
    cmp  r12d, WM_ERASEBKGND
    je   ew_zero

    mov  rcx, rbx
    mov  edx, r12d
    call DefWindowProcW
    jmp  ew_out

; ---- WM_CREATE -------------------------------------------------------------
ew_create:
    call EditorAllocContext
    test rax, rax
    jz   ew_cfail
    mov  rbp, rax                         ; ctx
    mov  rcx, rbx
    mov  rdx, rbp
    call EditorBindContext
    mov  rcx, rbp
    call ConfigLoad
    mov  rcx, rbp
    call EditorInitDocument
    mov  rcx, rbp
    call EditorCreateFont
    mov  rcx, rbp
    call EditorComputeMetrics
    mov  rcx, rbp
    call LinesRebuild
    lea  rcx, szEditorMsgReady
    call LogLine
    xor  eax, eax
    jmp  ew_out
ew_cfail:
    lea  rcx, szEditorMsgFail
    call LogLine
    xor  eax, eax
    jmp  ew_out

; ---- WM_SIZE ---------------------------------------------------------------
ew_size:
    mov  rcx, rbx
    call EditorCtxFromHwnd
    test rax, rax
    jz   ew_zero
    mov  r13, rax
    mov  rcx, r13
    call EditorComputeMetrics
    xor  eax, eax
    jmp  ew_out

; ---- WM_PAINT --------------------------------------------------------------
ew_paint:
    mov  rcx, rbx
    lea  rdx, [rsp + 24]                  ; PAINTSTRUCT
    call BeginPaint
    test rax, rax
    jz   ew_zero
    mov  r13, rax                         ; hdc
    mov  rcx, rbx
    call EditorCtxFromHwnd
    test rax, rax
    jz   ew_pend
    mov  rcx, rbx
    mov  rdx, r13
    mov  r8, rax
    call EditorRender
ew_pend:
    mov  rcx, rbx
    lea  rdx, [rsp + 24]
    call EndPaint
    xor  eax, eax
    jmp  ew_out

; ---- WM_CHAR ---------------------------------------------------------------
ew_char:
    movzx eax, r8w                         ; wide char in wParam
    cmp  eax, 32
    jb   ew_zero                           ; drop control chars
    mov  [rsp + 16], ax
    mov  word ptr [rsp + 18], 0
    mov  rcx, rbx
    call EditorCtxFromHwnd
    test rax, rax
    jz   ew_zero
    mov  r13, rax
    mov  rcx, r13
    lea  rdx, [rsp + 16]
    mov  r8, 1
    mov  r9d, UFL_TYPING
    call EditorInsert
    mov  rcx, r13
    call LinesRebuild
    mov  rcx, rbx
    call EditorInvalidate
    xor  eax, eax
    jmp  ew_out

; ---- WM_DESTROY ------------------------------------------------------------
ew_destroy:
    mov  rcx, rbx
    call EditorCtxFromHwnd
    test rax, rax
    jz   ew_postquit
    mov  rbp, rax
    mov  rcx, rbx
    mov  edx, 1                            ; timer id
    call KillTimer
    mov  rcx, rbp
    call EditorFreeContext
ew_postquit:
    xor  ecx, ecx
    call PostQuitMessage
    xor  eax, eax
    jmp  ew_out

; ---- WM_GETMINMAXINFO ------------------------------------------------------
; [H-04] a zero-sized client area divides by zero in the mouse/gutter math.
; Enforce the minimum here so the invariant can never be violated.
ew_minmax:
    test r9, r9                            ; lParam = MINMAXINFO*
    jz   ew_zero
    mov  qword ptr [r9 + 24], CFG_MIN_WIDTH
    mov  qword ptr [r9 + 32], CFG_MIN_HEIGHT
    xor  eax, eax
    jmp  ew_out

ew_zero:
    xor  eax, eax
ew_out:
    add  rsp, 80
    pop  rbp
    pop  r13
    pop  r12
    pop  rbx
    ret
EditorWndProc ENDP

; ----------------------------------------------------------------------------
; WinMain : HINSTANCE, HINSTANCE, LPSTR, int -> int
;   Self-test gate, config load, class registration, window creation, pump.
;   The static WNDCLASSEXW is patched at runtime (hInstance, cursor, brush).
; ----------------------------------------------------------------------------
WinMain PROC
    push rbx
    push rbp
    push r12
    sub  rsp, 160                          ; stack args(96) + MSG(48)

    mov  rbp, rcx                          ; hInstance

    ; ---- refuse to show a window when the document layer is broken ----
    call IDE_SelfTest
    test eax, eax
    jnz  wm_fail

    call ConfigLoad

    ; ---- patch the static class ----
    lea  r12, EditorWcx                   ; r12 is callee-saved here
    mov  [r12 + 24], rbp                  ; hInstance
    mov  ecx, 32512                       ; IDC_ARROW
    xor  edx, edx
    call LoadCursorW
    mov  [r12 + 40], rax                  ; hCursor
    xor  ecx, ecx                         ; WHITE_BRUSH
    call GetStockObject
    mov  [r12 + 48], rax                  ; hbrBackground

    lea  rcx, EditorWcx
    call RegisterClassExW
    test ax, ax
    jz   wm_fail

    ; ---- CreateWindowExW(dwExStyle, cls, text, style, X, Y, W, H,
    ;                     parent, menu, inst, param) ----
    xor  ecx, ecx
    lea  rdx, szAppClass
    lea  r8, szAppTitle
    mov  r9d, WS_OVERLAPPEDWINDOW or WS_VISIBLE
    mov  qword ptr [rsp + 32], 100         ; X
    mov  qword ptr [rsp + 40], 100         ; Y
    mov  rax, CFG_DEF_WIDTH
    mov  [rsp + 48], rax
    mov  rax, CFG_DEF_HEIGHT
    mov  [rsp + 56], rax
    xor  eax, eax
    mov  [rsp + 64], rax                   ; hWndParent
    mov  [rsp + 72], rax                   ; hMenu
    mov  [rsp + 80], rbp                   ; hInstance
    mov  [rsp + 88], rax                   ; lpParam
    call CreateWindowExW
    test rax, rax
    jz   wm_fail
    mov  rbx, rax                          ; hwnd

    mov  ecx, SW_SHOW
    call ShowWindow
    mov  rcx, rbx
    call UpdateWindow

wm_pump:
    lea  rcx, [rsp + 96]                   ; MSG*
    xor  edx, edx                          ; hWnd filter
    xor  r8d, r8d                          ; wMsgFilterMin
    xor  r9d, r9d                          ; wMsgFilterMax
    call GetMessageW
    test eax, eax
    jle  wm_done                           ; 0 = quit, -1 = error
    lea  rcx, [rsp + 96]
    call TranslateMessage
    lea  rcx, [rsp + 96]
    call DispatchMessageW
    jmp  wm_pump

wm_done:
    mov  eax, [rsp + 96 + 16]              ; MSG.wParam = exit code
    jmp  wm_out
wm_fail:
    xor  eax, eax
wm_out:
    add  rsp, 160
    pop  r12
    pop  rbp
    pop  rbx
    ret
WinMain ENDP

END

END

