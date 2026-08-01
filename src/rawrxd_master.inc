; rawrxd_master.inc — Master include for RawrXD Widget System
; Provides common macros, structures, and extern declarations
; SOVEREIGN EDITION

OPTION CASEMAP:NONE

; ===========================================================================
; Common constants
; ===========================================================================
NULL            equ 0
TRUE            equ 1
FALSE           equ 0
INVALID_HANDLE_VALUE equ -1

; ===========================================================================
; Windows API type aliases
; ===========================================================================
HANDLE          EQU 0
DWORD           EQU 0
BOOL            EQU 0
LPVOID          EQU 0
LPCSTR          EQU 0
LPSTR           EQU 0

; ===========================================================================
; Common Windows constants
; ===========================================================================
STD_INPUT_HANDLE    equ -10
STD_OUTPUT_HANDLE   equ -11
STD_ERROR_HANDLE    equ -12

GENERIC_READ        equ 80000000h
GENERIC_WRITE       equ 40000000h
OPEN_EXISTING       equ 3
OPEN_ALWAYS         equ 4
FILE_SHARE_READ     equ 1
FILE_SHARE_WRITE    equ 2

PIPE_ACCESS_DUPLEX  equ 3
PIPE_TYPE_MESSAGE   equ 4
PIPE_READMODE_MESSAGE equ 2
PIPE_WAIT           equ 0
PIPE_UNLIMITED_INSTANCES equ 255

; ===========================================================================
; Extern declarations for kernel32 functions
; ===========================================================================
EXTERN CreateFileA:PROC
EXTERN CloseHandle:PROC
EXTERN WriteFile:PROC
EXTERN ReadFile:PROC
EXTERN CreateNamedPipeA:PROC
EXTERN ConnectNamedPipe:PROC
EXTERN DisconnectNamedPipe:PROC
EXTERN GetLastError:PROC
EXTERN GetStdHandle:PROC
EXTERN SetStdHandle:PROC
EXTERN ExitProcess:PROC
EXTERN GetModuleHandleA:PROC
EXTERN GetProcAddress:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN GetProcessHeap:PROC
EXTERN Sleep:PROC
EXTERN WaitForSingleObject:PROC
EXTERN CreateThread:PROC
EXTERN TerminateThread:PROC
EXTERN GetCurrentThreadId:PROC
EXTERN GetCurrentProcessId:PROC
EXTERN QueryPerformanceCounter:PROC
EXTERN QueryPerformanceFrequency:PROC
EXTERN GetSystemInfo:PROC
EXTERN GlobalMemoryStatusEx:PROC
