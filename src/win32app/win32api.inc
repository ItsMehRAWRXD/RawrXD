; Win32 API declarations for MASM

; Kernel32 functions
ExitProcess PROTO :DWORD
GetModuleHandleA PROTO :DWORD
GetCommandLineA PROTO
GetCurrentDirectoryA PROTO :DWORD, :DWORD
SetCurrentDirectoryA PROTO :DWORD
CreateFileA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ReadFile PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WriteFile PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle PROTO :DWORD
GetFileSize PROTO :DWORD, :DWORD

; User32 functions
RegisterClassExA PROTO :DWORD
CreateWindowExA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ShowWindow PROTO :DWORD, :DWORD
UpdateWindow PROTO :DWORD
GetMessageA PROTO :DWORD, :DWORD, :DWORD, :DWORD
TranslateMessage PROTO :DWORD
DispatchMessageA PROTO :DWORD
DefWindowProcA PROTO :DWORD, :DWORD, :DWORD, :DWORD
PostQuitMessage PROTO :DWORD
DestroyWindow PROTO :DWORD
LoadIconA PROTO :DWORD, :DWORD
LoadCursorA PROTO :DWORD, :DWORD
GetStockObject PROTO :DWORD
BeginPaint PROTO :DWORD, :DWORD
EndPaint PROTO :DWORD, :DWORD
GetClientRect PROTO :DWORD, :DWORD
InvalidateRect PROTO :DWORD, :DWORD, :DWORD
SetWindowTextA PROTO :DWORD, :DWORD
GetWindowTextA PROTO :DWORD, :DWORD, :DWORD
SendMessageA PROTO :DWORD, :DWORD, :DWORD, :DWORD
PostMessageA PROTO :DWORD, :DWORD, :DWORD, :DWORD
MessageBoxA PROTO :DWORD, :DWORD, :DWORD, :DWORD

; GDI32 functions
CreateSolidBrush PROTO :DWORD
DeleteObject PROTO :DWORD
SelectObject PROTO :DWORD, :DWORD
GetDC PROTO :DWORD
ReleaseDC PROTO :DWORD, :DWORD
CreateCompatibleDC PROTO :DWORD
CreateCompatibleBitmap PROTO :DWORD, :DWORD, :DWORD
BitBlt PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
TextOutA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
SetTextColor PROTO :DWORD, :DWORD
SetBkColor PROTO :DWORD, :DWORD

; Constants
NULL                    EQU 0
TRUE                    EQU 1
FALSE                   EQU 0

; Window messages
WM_DESTROY              EQU 2
WM_PAINT                EQU 15
WM_CLOSE                EQU 16
WM_COMMAND              EQU 273
WM_LBUTTONDOWN          EQU 513
WM_RBUTTONDOWN          EQU 516
WM_KEYDOWN              EQU 256

; Window styles
WS_OVERLAPPEDWINDOW     EQU 0CF0000h
WS_VISIBLE              EQU 10000000h
WS_CHILD                EQU 40000000h

; Show window constants
SW_HIDE                 EQU 0
SW_SHOW                 EQU 5
SW_MINIMIZE             EQU 6
SW_MAXIMIZE             EQU 3

; File constants
GENERIC_READ            EQU 80000000h
GENERIC_WRITE           EQU 40000000h
CREATE_ALWAYS           EQU 2
OPEN_EXISTING           EQU 3
FILE_ATTRIBUTE_NORMAL   EQU 80h
INVALID_HANDLE_VALUE    EQU -1

; Message box types
MB_OK                   EQU 0
MB_YESNO                EQU 4
MB_ICONINFORMATION      EQU 40h
MB_ICONERROR            EQU 10h

; Colors
COLOR_WINDOW            EQU 5
WHITE_BRUSH             EQU 0
BLACK_BRUSH             EQU 4

; Virtual key codes
VK_ESCAPE               EQU 1Bh
VK_RETURN               EQU 0Dh
VK_SPACE                EQU 20h
