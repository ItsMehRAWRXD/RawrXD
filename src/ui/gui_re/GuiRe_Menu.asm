; GuiRe_Menu.asm — mirror HMENU from main (end-side command surface)
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

PUBLIC GuiRe_DumpMenu

.DATA
szMenuPath DB "GuiRe_MENU.txt", 0
ALIGN 8
menuBuf    DB 256 DUP(0)

.CODE

; RCX = main HWND — write top-level + one submenu level to GuiRe_MENU.txt
GuiRe_DumpMenu PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    sub     rsp, 60h
    .allocstack 60h
    .endprolog

    mov     rbx, rcx
    call    GetMenu
    test    rax, rax
    jz      fail
    mov     r12, rax

    lea     rcx, szMenuPath
    mov     rdx, GENERIC_WRITE
    xor     r8, r8
    xor     r9, r9
    mov     qword ptr [rsp+20h], CREATE_ALWAYS
    mov     dword ptr [rsp+28h], FILE_ATTRIBUTE_NORMAL
    mov     qword ptr [rsp+30h], 0
    call    CreateFileA
    cmp     rax, INVALID_HANDLE_VALUE
    je      fail
    mov     r13, rax

    mov     rcx, r12
    call    GetMenuItemCount
    mov     esi, eax
    xor     edi, edi
top:
    cmp     edi, esi
    jge     close
    mov     rcx, r12
    mov     edx, edi
    lea     r8, menuBuf
    mov     r9d, 255
    mov     dword ptr [rsp+20h], MF_BYPOSITION
    call    GetMenuStringA
    mov     rcx, r13
    lea     rdx, menuBuf
    mov     r8d, eax
    lea     r9, [rsp+38h]
    mov     qword ptr [rsp+20h], 0
    call    WriteFile
    ; newline
    mov     byte ptr [rsp+40h], 13
    mov     byte ptr [rsp+41h], 10
    mov     rcx, r13
    lea     rdx, [rsp+40h]
    mov     r8d, 2
    lea     r9, [rsp+38h]
    mov     qword ptr [rsp+20h], 0
    call    WriteFile
    inc     edi
    jmp     top
close:
    mov     rcx, r13
    call    CloseHandle
    xor     eax, eax
    jmp     done
fail:
    mov     eax, 1
done:
    add     rsp, 60h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GuiRe_DumpMenu ENDP

END
