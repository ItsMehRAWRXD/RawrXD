; Minimal windows.inc stub for assembly samples
; NOTE: This is a small stub to allow assembling the example modules in this repo.
; For production builds, replace with a full SDK-provided include set (MASM/UASM headers).

; Types
HWND        typedef QWORD
HINSTANCE   typedef QWORD
HMODULE     typedef QWORD
WPARAM      typedef QWORD
LPARAM      typedef QWORD
UINT        typedef DWORD
HANDLE      typedef QWORD
LPVOID      typedef QWORD
LPCSTR      typedef QWORD

; File operation constants
INVALID_HANDLE_VALUE EQU -1
GENERIC_READ         EQU 80000000h
GENERIC_WRITE        EQU 40000000h
FILE_SHARE_READ      EQU 00000001h
FILE_SHARE_WRITE     EQU 00000002h
OPEN_EXISTING        EQU 3
CREATE_ALWAYS        EQU 2
FILE_ATTRIBUTE_NORMAL EQU 80h

; Common constants
WM_CREATE        EQU 0001h
WM_DESTROY       EQU 0002h
WM_SIZE          EQU 0005h
WM_SETTEXT       EQU 000Ch
WM_GETTEXT       EQU 000Dh
WM_GETTEXTLENGTH EQU 000Eh
WM_COMMAND       EQU 0111h
WM_USER          EQU 0400h
EM_SETSEL        EQU 00B1h
EM_REPLACESEL    EQU 00C2h
EM_SETCHARFORMAT EQU 0444h
EM_GETTEXTRANGE  EQU 044Bh
EM_FINDTEXT      EQU 0438h
SCF_SELECTION    EQU 0001h
SCF_ALL          EQU 0004h

FINDTEXTA STRUCT
    cpMin           DWORD ?
    cpMax           DWORD ?
    lpstrText       QWORD ?
FINDTEXTA ENDS

CFM_COLOR        EQU 40000000h
CFE_AUTOCOLOR    EQU 40000000h

CHARFORMAT2 STRUCT
    cbSize          DWORD ?
    dwMask          DWORD ?
    dwEffects       DWORD ?
    yHeight         DWORD ?
    yOffset         DWORD ?
    crTextColor     DWORD ?
    bCharSet        BYTE ?
    bPitchAndFamily BYTE ?
    szFaceName      BYTE 32 DUP (?)
    wWeight         WORD ?
    sSpacing        WORD ?
    crBackColor     DWORD ?
    lcid            DWORD ?
    dwReserved      DWORD ?
    sStyle          WORD ?
    wKerning        WORD ?
    bUnderlineType  BYTE ?
    bAnimation      BYTE ?
    bRevAuthor      BYTE ?
    bReserved1      BYTE ?
CHARFORMAT2 ENDS

TEXTRANGE STRUCT
    cpMin           DWORD ?
    cpMax           DWORD ?
    lpstrText       QWORD ?
TEXTRANGE ENDS

GENERIC_READ     EQU 80000000h
GENERIC_WRITE    EQU 40000000h
FILE_SHARE_READ  EQU 00000001h
OPEN_EXISTING    EQU 3
CREATE_ALWAYS    EQU 2
FILE_ATTRIBUTE_NORMAL EQU 00000080h

WS_OVERLAPPEDWINDOW EQU 00CF0000h
WS_POPUP         EQU 80000000h
WS_BORDER        EQU 00800000h
WS_VISIBLE       EQU 10000000h
WS_CHILD         EQU 40000000h
WS_VSCROLL       EQU 00200000h
WS_CAPTION       EQU 00C00000h
WS_SYSMENU       EQU 00080000h

WS_EX_CLIENTEDGE EQU 00000200h
WS_EX_TOOLWINDOW EQU 00000080h

ES_MULTILINE     EQU 0004h
ES_READONLY      EQU 0800h
ES_AUTOHSCROLL   EQU 0080h

LBS_NOTIFY       EQU 0001h
BS_PUSHBUTTON    EQU 0h

MB_OK            EQU 0h
MB_OKCANCEL      EQU 1h
MB_ICONERROR     EQU 10h
IDCANCEL         EQU 2
IDOK             EQU 1

; Menu flags
MFT_STRING       EQU 0h
MF_STRING        EQU 0h
MF_POPUP         EQU 00000010h

; Window Class Styles
CS_VREDRAW       EQU 0001h
CS_HREDRAW       EQU 0002h

; Colors
COLOR_BTNFACE    EQU 15

; Cursors and Icons
IDC_ARROW        EQU 32512
IDI_APPLICATION  EQU 32512

; ShowWindow commands
SW_SHOWNORMAL    EQU 1

; CreateWindow constants
CW_USEDEFAULT    EQU 80000000h

; Font flags
DEFAULT_CHARSET       EQU 1
OUT_DEFAULT_PRECIS    EQU 0
CLIP_DEFAULT_PRECIS   EQU 0
DEFAULT_QUALITY       EQU 0
FIXED_PITCH           EQU 10h
FF_MODERN             EQU 30h
FW_NORMAL             EQU 400

HEAP_ZERO_MEMORY      EQU 00000008h
HANDLE_FLAG_INHERIT   EQU 00000001h
STARTF_USESTDHANDLES  EQU 00000100h
STARTF_USESHOWWINDOW  EQU 00000001h
SW_HIDE               EQU 0
CREATE_NEW_CONSOLE    EQU 00000010h
CREATE_NO_WINDOW      EQU 08000000h
TRUE                  EQU 1
FALSE                 EQU 0
NULL                  EQU 0

; IDC placeholders
IDC_CMDK_SEARCH       EQU 1001
IDC_CMDK_LIST         EQU 1002

; Memory-map flags
PAGE_READONLY       EQU 02h
FILE_MAP_READ       EQU 04h

; File search
MAX_PATH            EQU 260
INVALID_HANDLE_VALUE EQU -1

WIN32_FIND_DATA STRUCT
    dwFileAttributes    DWORD   ?
    ftCreationTime      QWORD   ?
    ftLastAccessTime    QWORD   ?
    ftLastWriteTime     QWORD   ?
    nFileSizeHigh       DWORD   ?
    nFileSizeLow        DWORD   ?
    dwReserved0         DWORD   ?
    dwReserved1         DWORD   ?
    cFileName           BYTE    260 DUP (?)
    cAlternateFileName  BYTE    14 DUP (?)
WIN32_FIND_DATA ENDS

SECURITY_ATTRIBUTES STRUCT
    nLength             DWORD   ?
    lpSecurityDescriptor QWORD  ?
    bInheritHandle      DWORD   ?
SECURITY_ATTRIBUTES ENDS

STARTUPINFO STRUCT
    cb                  DWORD   ?
    _pad_cb             DWORD   ?
    lpReserved          QWORD   ?
    lpDesktop           QWORD   ?
    lpTitle             QWORD   ?
    dwX                 DWORD   ?
    dwY                 DWORD   ?
    dwXSize             DWORD   ?
    dwYSize             DWORD   ?
    dwXCountChars       DWORD   ?
    dwYCountChars       DWORD   ?
    dwFillAttribute     DWORD   ?
    dwFlags             DWORD   ?
    wShowWindow         WORD    ?
    cbReserved2         WORD    ?
    lpReserved2         QWORD   ?
    hStdInput           QWORD   ?
    hStdOutput          QWORD   ?
    hStdError           QWORD   ?
STARTUPINFO ENDS

PROCESS_INFORMATION STRUCT
    hProcess            QWORD   ?
    hThread             QWORD   ?
    dwProcessId         DWORD   ?
    dwThreadId          DWORD   ?
PROCESS_INFORMATION ENDS

WndClassEx STRUCT 8 ; Align to 8 bytes for x64
    cbSize              DWORD   ?
    style               DWORD   ?
    lpfnWndProc         QWORD   ?
    cbClsExtra          DWORD   ?
    cbWndExtra          DWORD   ?
    hInstance           QWORD   ?
    hIcon               QWORD   ?
    hCursor             QWORD   ?
    hbrBackground       QWORD   ?
    lpszMenuName        QWORD   ?
    lpszClassName       QWORD   ?
    hIconSm             QWORD   ?
WndClassEx ENDS

; Standard Windows name
WNDCLASSEX EQU WndClassEx

MSG STRUCT
    hwnd                QWORD   ?
    message             DWORD   ?
    _padding            DWORD   ?
    wParam              QWORD   ?
    lParam              QWORD   ?
    time                DWORD   ?
    pt                  QWORD   ? ; POINT struct is 2 DWORDS
    _padding2           DWORD   ?
MSG ENDS

; Prototypes
EXTERN GetModuleHandleA:PROC
EXTERN GetCommandLineA:PROC
EXTERN ExitProcess:PROC
EXTERN CreateFileA:PROC
EXTERN GetFileSize:PROC
EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN CloseHandle:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN GetFileSizeEx:PROC
EXTERN MessageBoxA:PROC
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN lstrlenA:PROC
EXTERN lstrcpyA:PROC
EXTERN lstrcatA:PROC
EXTERN lstrcmpA:PROC
EXTERN CreateWindowExA:PROC
EXTERN CreateFontA:PROC
EXTERN SendMessageA:PROC
EXTERN SetWindowTextA:PROC
EXTERN GetWindowTextA:PROC
EXTERN GetWindowTextLengthA:PROC
EXTERN OutputDebugStringA:PROC
EXTERN LoadLibraryA:PROC
EXTERN GetDlgItem:PROC
EXTERN SetFocus:PROC
EXTERN DestroyWindow:PROC
EXTERN InvalidateRect:PROC
EXTERN PostQuitMessage:PROC
EXTERN DefWindowProcA:PROC
EXTERN RegisterClassExA:PROC
EXTERN GetClassInfoExA:PROC
EXTERN GetMessageA:PROC
EXTERN TranslateMessage:PROC
EXTERN DispatchMessageA:PROC
EXTERN LoadCursorA:PROC
EXTERN LoadIconA:PROC
EXTERN GetClientRect:PROC
EXTERN MoveWindow:PROC
EXTERN CreateMenu:PROC
EXTERN CreatePopupMenu:PROC
EXTERN AppendMenuA:PROC
EXTERN SetMenu:PROC
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN GetLastError:PROC
EXTERN GetTickCount:PROC
EXTERN FreeLibrary:PROC
EXTERN ShowWindow:PROC
EXTERN UpdateWindow:PROC
EXTERN RtlZeroMemory:PROC
EXTERN VirtualProtect:PROC

; Additional UI helpers for designer agent
EXTERN GetWindowLongPtrA:PROC
EXTERN GetClassNameA:PROC
EXTERN GetParent:PROC
EXTERN ScreenToClient:PROC
EXTERN EnumChildWindows:PROC

EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN GetClientRect:PROC
EXTERN PostMessageA:PROC
EXTERN GetDesktopWindow:PROC
EXTERN SetWindowPos:PROC
EXTERN GetWindowRect:PROC
EXTERN FindFirstFileA:PROC
EXTERN FindNextFileA:PROC
EXTERN FindClose:PROC
EXTERN LoadLibraryA:PROC
EXTERN GetProcAddress:PROC
EXTERN CreatePipe:PROC
EXTERN SetHandleInformation:PROC
EXTERN DuplicateHandle:PROC
EXTERN GetCurrentProcess:PROC
EXTERN CreateProcessA:PROC

; GDI and Modern UI APIs
EXTERN CreateDIBSection:PROC
EXTERN SelectObject:PROC
EXTERN BitBlt:PROC
EXTERN DwmExtendFrameIntoClientArea:PROC
EXTERN BeginBufferedPaint:PROC
EXTERN EndBufferedPaint:PROC
EXTERN D2D1CreateFactory:PROC
EXTERN DWriteCreateFactory:PROC

; Modern UI Constants
D2D1_FACTORY_TYPE_SINGLE_THREADED EQU 0
DWRITE_FACTORY_TYPE_SHARED        EQU 0

; GUIDs (as bytes for convenience)
.data
    IID_ID2D1Factory    BYTE 057h, 048h, 02fh, 006h, 06eh, 05eh, 0d1h, 046h, 0b6h, 0d6h, 006h, 0d3h, 056h, 0a0h, 070h, 028h
    IID_IDWriteFactory  BYTE 025h, 0e1h, 0d1h, 0b8h, 016h, 09fh, 049h, 04bh, 08bh, 077h, 0c1h, 034h, 011h, 0b9h, 062h, 092h
.code
