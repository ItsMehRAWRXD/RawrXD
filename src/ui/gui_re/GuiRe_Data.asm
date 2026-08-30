; GuiRe_Data.asm — ring + strings (≤99 lines)
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc

PUBLIC g_guiReHdr
PUBLIC g_guiReNodes
PUBLIC g_guiReCount
PUBLIC g_guiReWalkBuf
PUBLIC szGuiReMagic
PUBLIC szMainClass
PUBLIC szDumpPath

.DATA
ALIGN 8
g_guiReHdr      GUIRE_HDR < >
g_guiReCount    DWORD 0
g_guiReWalkBuf  QWORD GUIRE_MAX_NODES DUP(0)   ; leaf→root hwnd chain
ALIGN 8
g_guiReNodes    GUINODE GUIRE_MAX_NODES DUP(<>)

szGuiReMagic    DB "GuIR", 0
szMainClass     DB "RawrXD_IDE_MainWindow", 0
szDumpPath      DB "GuiRe_DUMP.txt", 0
szNl            DB 13, 10, 0
szHdrFmt        DB "GUIRE leaf-out count=", 0

.CODE
; no code — data only
END
