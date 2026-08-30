; GuiRe_Proto.inc — Win32 imports (no MASM32 wrappers; link user32+kernel32 only)
EXTRN WindowFromPoint:PROC
EXTRN GetParent:PROC
EXTRN GetWindow:PROC
EXTRN GetAncestor:PROC
EXTRN GetWindowLongPtrA:PROC
EXTRN GetWindowRect:PROC
EXTRN GetClassNameA:PROC
EXTRN GetWindowTextA:PROC
EXTRN IsWindow:PROC
EXTRN IsWindowVisible:PROC
EXTRN IsWindowEnabled:PROC
EXTRN IsWindowUnicode:PROC
EXTRN FindWindowA:PROC
EXTRN EnumChildWindows:PROC
EXTRN GetDlgCtrlID:PROC
EXTRN SetWindowTextA:PROC
EXTRN EnableWindow:PROC
EXTRN ShowWindow:PROC
EXTRN SendMessageA:PROC
EXTRN GetMenu:PROC
EXTRN GetMenuItemCount:PROC
EXTRN GetMenuStringA:PROC
EXTRN GetSubMenu:PROC
EXTRN CreateFileA:PROC
EXTRN WriteFile:PROC
EXTRN CloseHandle:PROC
EXTRN GetLastError:PROC

GWLP_ID             EQU -12
GWLP_STYLE          EQU -16
GWLP_EXSTYLE        EQU -20
GMEM_FIXED          EQU 0000h
GENERIC_WRITE       EQU 40000000h
CREATE_ALWAYS       EQU 2
FILE_ATTRIBUTE_NORMAL EQU 80h
INVALID_HANDLE_VALUE EQU -1
MF_BYPOSITION       EQU 0400h
