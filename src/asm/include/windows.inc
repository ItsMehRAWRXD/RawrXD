TRUE equ 1
FALSE equ 0
WAIT_OBJECT_0 equ 0L
FILE_ATTRIBUTE_NORMAL equ 80h
INVALID_HANDLE_VALUE equ -1
GENERIC_WRITE equ 40000000h
GENERIC_READ equ 80000000h
FILE_SHARE_READ equ 1
CREATE_ALWAYS equ 2
CREATE_NEW equ 1
OPEN_EXISTING equ 3
OPEN_ALWAYS equ 4

SYSTEM_INFO STRUCT
    union
        dwOemId DWORD ?
        struct
            wProcessorArchitecture WORD ?
            wReserved WORD ?
        ends
    ends
    dwPageSize DWORD ?
    lpMinimumApplicationAddress QWORD ?
    lpMaximumApplicationAddress QWORD ?
    dwActiveProcessorMask QWORD ?
    dwNumberOfProcessors DWORD ?
    dwProcessorType DWORD ?
    dwAllocationGranularity DWORD ?
    wProcessorLevel WORD ?
    wProcessorRevision WORD ?
SYSTEM_INFO ENDS

