; GuiRe.inc — leaf→root GUI self-RE contract (x64 MASM, Win32 EXTRN only)
; End-side-out: visible leaf HWND → parent/owner → main → menu authority.
OPTION CASEMAP:NONE

GUIRE_MAX_NODES     EQU 256
GUIRE_CLASS_CAP     EQU 64
GUIRE_TEXT_CAP      EQU 128

GUIRE_F_VISIBLE     EQU 00000001h
GUIRE_F_ENABLED     EQU 00000002h
GUIRE_F_UNICODE     EQU 00000004h
GUIRE_F_LEAF        EQU 00000008h

; Packed node — agent-readable snapshot (same role as a model “seeing” a control).
GUINODE STRUCT 8
    hwnd        QWORD ?
    parent      QWORD ?
    owner       QWORD ?
    ctrlId      DWORD ?
    style       DWORD ?
    exStyle     DWORD ?
    left        DWORD ?
    top         DWORD ?
    right       DWORD ?
    bottom      DWORD ?
    flags       DWORD ?
    depth       DWORD ?
    classA      BYTE  GUIRE_CLASS_CAP DUP(?)
    textA       BYTE  GUIRE_TEXT_CAP DUP(?)
GUINODE ENDS

GUIRE_HDR STRUCT 8
    magic       DWORD ?          ; 'GuIR'
    version     DWORD ?          ; 1
    count       DWORD ?
    rootHwnd    QWORD ?
    leafHwnd    QWORD ?
GUIRE_HDR ENDS

GW_OWNER            EQU 4
GA_ROOT             EQU 2
WM_GETTEXT          EQU 000Dh
WM_SETTEXT          EQU 000Ch
SW_HIDE             EQU 0
SW_SHOW             EQU 5
