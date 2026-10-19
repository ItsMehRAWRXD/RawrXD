option casemap:none

R671_OK                equ 0
R671_E_INVALID         equ 1
R671_E_OPEN            equ 2
R671_E_SIZE            equ 3
R671_E_MAPPING         equ 4
R671_E_VIEW            equ 5
R671_E_RANGE           equ 6
R671_E_STATE           equ 7

R671_STAGE_NONE        equ 0
R671_STAGE_CREATEFILE  equ 1
R671_STAGE_GETFILESIZE equ 2
R671_STAGE_MAPPING     equ 3
R671_STAGE_SYSINFO     equ 4
R671_STAGE_READY       equ 5

GENERIC_READ           equ 80000000h
FILE_SHARE_READ        equ 00000001h
FILE_SHARE_WRITE       equ 00000002h
OPEN_EXISTING          equ 3
FILE_ATTRIBUTE_NORMAL  equ 00000080h
PAGE_READONLY          equ 02h
INVALID_HANDLE_VALUE   equ -1

R671ContextDiag STRUCT
    file_handle         QWORD ?
    mapping_handle      QWORD ?
    file_bytes          QWORD ?
    allocation_gran     QWORD ?

    open_stage          DWORD ?
    open_rc             DWORD ?
    win32_last_error    DWORD ?
    reserved0           DWORD ?
R671ContextDiag ENDS

r671_open_diag PROTO
