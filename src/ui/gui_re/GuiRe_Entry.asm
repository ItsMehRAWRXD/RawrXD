; GuiRe_Entry.asm — drop-in driver: find main → enum tree → dump
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

EXTRN GuiRe_EnumTree:PROC
EXTRN GuiRe_DumpFile:PROC
EXTRN GuiRe_FromPoint:PROC
EXTRN GuiRe_DumpMenu:PROC
EXTRN ExitProcess:PROC

PUBLIC GuiRe_ScanSelf
PUBLIC GuiRe_ScanPoint
PUBLIC mainCRTStartup
PUBLIC main

.DATA
szMainCls DB "RawrXD_IDE_MainWindow", 0

.CODE

; Find live IDE main → EnumTree (leaf-out DFS) → GuiRe_DUMP.txt
GuiRe_ScanSelf PROC FRAME
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    sub     rsp, 28h
    .allocstack 28h
    .endprolog
    lea     rcx, szMainCls
    xor     edx, edx
    call    FindWindowA
    test    rax, rax
    jz      miss
    mov     rbx, rax                  ; main HWND
    mov     rcx, rbx
    call    GuiRe_EnumTree
    mov     r12d, eax                 ; count
    mov     rcx, rbx
    call    GuiRe_DumpMenu
    xor     ecx, ecx
    call    GuiRe_DumpFile
    mov     eax, r12d
    jmp     done
miss:
    xor     eax, eax
done:
    add     rsp, 28h
    pop     r12
    pop     rbx
    ret
GuiRe_ScanSelf ENDP

GuiRe_ScanPoint PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 30h
    .allocstack 30h
    .endprolog
    call    GuiRe_FromPoint
    mov     ebx, eax
    xor     ecx, ecx
    call    GuiRe_DumpFile
    mov     eax, ebx
    add     rsp, 30h
    pop     rbx
    ret
GuiRe_ScanPoint ENDP

main PROC
    call    GuiRe_ScanSelf
    ret
main ENDP

mainCRTStartup PROC
    call    main
    xor     ecx, ecx
    call    ExitProcess
mainCRTStartup ENDP

END
