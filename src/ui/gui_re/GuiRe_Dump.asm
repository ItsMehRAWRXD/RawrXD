; GuiRe_Dump.asm — serialize node table to GuiRe_DUMP.txt (agent-readable)
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

EXTRN g_guiReNodes:BYTE
EXTRN g_guiReCount:DWORD
EXTRN g_guiReHdr:BYTE
EXTRN szDumpPath:BYTE

PUBLIC GuiRe_DumpFile

.DATA
szLine DB "hwnd=%p id=%u class=%s text=%s flags=%08X depth=%u", 13, 10, 0
; Minimal dump without CRT printf: hand-roll hex + ascii lines into stack buf.

.CODE

; Write one ASCII line from RSI=GUINODE* into RDI buffer; returns RAX=len
; Simplified: class + ctrlId + hwnd hex only (no libc).
GuiRe_FormatNode PROC
    ; RCX=node RDX=dst R8=cap → RAX bytes written (truncated)
    push    rbx
    push    rsi
    push    rdi
    mov     rsi, rcx
    mov     rdi, rdx
    mov     rbx, r8
    ; prefix "N "
    mov     byte ptr [rdi], 'N'
    mov     byte ptr [rdi+1], ' '
    add     rdi, 2
    ; copy classA
    lea     rax, [rsi].GUINODE.classA
    xor     ecx, ecx
cpy:
    mov     dl, [rax + rcx]
    test    dl, dl
    jz      cpy_done
    cmp     rcx, 60
    jae     cpy_done
    mov     [rdi + rcx], dl
    inc     ecx
    jmp     cpy
cpy_done:
    add     rdi, rcx
    mov     word ptr [rdi], 0A0Dh
    add     rdi, 2
    mov     rax, rdi
    sub     rax, rdx
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GuiRe_FormatNode ENDP

; RCX = optional pathA (null → szDumpPath)
GuiRe_DumpFile PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    sub     rsp, 4A0h
    .allocstack 4A0h
    .endprolog

    test    rcx, rcx
    jnz     @f
    lea     rcx, szDumpPath
@@:
    mov     rdx, GENERIC_WRITE
    xor     r8, r8
    xor     r9, r9
    mov     qword ptr [rsp+20h], CREATE_ALWAYS
    mov     dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+30h], 0
    call    CreateFileA
    cmp     rax, INVALID_HANDLE_VALUE
    je      fail
    mov     r12, rax

    xor     ebx, ebx
    lea     rsi, g_guiReNodes
loopn:
    cmp     ebx, g_guiReCount
    jae     close
    mov     rcx, rsi
    lea     rdx, [rsp+40h]
    mov     r8d, 400h
    call    GuiRe_FormatNode
    mov     rcx, r12
    lea     rdx, [rsp+40h]
    mov     r8, rax
    lea     r9, [rsp+38h]
    mov     qword ptr [rsp+20h], 0
    call    WriteFile
    add     rsi, SIZEOF GUINODE
    inc     ebx
    jmp     loopn

close:
    mov     rcx, r12
    call    CloseHandle
    xor     eax, eax
    jmp     done
fail:
    mov     eax, 1
done:
    add     rsp, 4A0h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GuiRe_DumpFile ENDP

END
