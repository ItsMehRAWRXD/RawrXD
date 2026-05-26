; ==============================================================================
; Sovereign_API_Bridge.asm - Dynamic API Linkage Bridge
; ==============================================================================

include Sovereign_Common.inc

.DATA
; Pointers to be resolved by PEB_Loader
PUBLIC pGetCurrentProcess
PUBLIC pGetCurrentThread
PUBLIC pSetPriorityClass
PUBLIC pSetThreadPriority
PUBLIC pSetProcessAffinityMask
PUBLIC pSetThreadAffinityMask
PUBLIC pGetTickCount64
PUBLIC pCreateFileW
PUBLIC pSetFilePointerEx
PUBLIC pGetFileSizeEx
PUBLIC pCreateFileMappingW
PUBLIC pUnmapViewOfFile
PUBLIC pFlushInstructionCache
PUBLIC pGetCommandLineW

pGetCurrentProcess      DQ 0
pGetCurrentThread       DQ 0
pSetPriorityClass       DQ 0
pSetThreadPriority      DQ 0
pSetProcessAffinityMask DQ 0
pSetThreadAffinityMask  DQ 0
pGetTickCount64         DQ 0
pCreateFileW            DQ 0
pSetFilePointerEx       DQ 0
pGetFileSizeEx          DQ 0
pCreateFileMappingW     DQ 0
pUnmapViewOfFile        DQ 0
pFlushInstructionCache  DQ 0
pGetCommandLineW        DQ 0

.CODE

; Bridge implementations that call the resolved pointers
Sovereign_GetTickCount64 PROC
    mov rax, [pGetTickCount64]
    jmp rax
Sovereign_GetTickCount64 ENDP

; ... others as needed ...

END
