; GuiRe_Capture.asm — fill one GUINODE from HWND (end-side atom)
OPTION CASEMAP:NONE
INCLUDE GuiRe.inc
INCLUDE GuiRe_Proto.inc

EXTRN g_guiReNodes:BYTE
EXTRN g_guiReCount:DWORD

PUBLIC GuiRe_CaptureHwnd

.CODE

; RCX=HWND  RDX=depth
; RAX=0 ok, 1 bad hwnd, 2 full
GuiRe_CaptureHwnd PROC FRAME
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

    mov     rbx, rcx                 ; hwnd
    mov     r12d, edx                ; depth
    test    rbx, rbx
    jz      bad
    mov     rcx, rbx
    call    IsWindow
    test    eax, eax
    jz      bad

    mov     eax, g_guiReCount
    cmp     eax, GUIRE_MAX_NODES
    jae     full
    mov     esi, eax
    inc     eax
    mov     g_guiReCount, eax
    imul    eax, esi, SIZEOF GUINODE
    lea     rdi, g_guiReNodes
    add     rdi, rax                 ; rdi = &node

    mov     [rdi].GUINODE.hwnd, rbx
    mov     [rdi].GUINODE.depth, r12d

    mov     rcx, rbx
    call    GetParent
    mov     [rdi].GUINODE.parent, rax

    mov     rcx, rbx
    mov     edx, GW_OWNER
    call    GetWindow
    mov     [rdi].GUINODE.owner, rax

    mov     rcx, rbx
    call    GetDlgCtrlID
    mov     [rdi].GUINODE.ctrlId, eax

    mov     rcx, rbx
    mov     edx, GWLP_STYLE
    call    GetWindowLongPtrA
    mov     [rdi].GUINODE.style, eax

    mov     rcx, rbx
    mov     edx, GWLP_EXSTYLE
    call    GetWindowLongPtrA
    mov     [rdi].GUINODE.exStyle, eax

    lea     rdx, [rdi].GUINODE.left
    mov     rcx, rbx
    call    GetWindowRect

    xor     r13d, r13d
    mov     rcx, rbx
    call    IsWindowVisible
    test    eax, eax
    jz      @f
    or      r13d, GUIRE_F_VISIBLE
@@:
    mov     rcx, rbx
    call    IsWindowEnabled
    test    eax, eax
    jz      @f
    or      r13d, GUIRE_F_ENABLED
@@:
    mov     rcx, rbx
    call    IsWindowUnicode
    test    eax, eax
    jz      @f
    or      r13d, GUIRE_F_UNICODE
@@:
    mov     [rdi].GUINODE.flags, r13d

    lea     rdx, [rdi].GUINODE.classA
    mov     r8d, GUIRE_CLASS_CAP
    mov     rcx, rbx
    call    GetClassNameA

    lea     rdx, [rdi].GUINODE.textA
    mov     r8d, GUIRE_TEXT_CAP
    mov     rcx, rbx
    call    GetWindowTextA

    xor     eax, eax
    jmp     done
bad:
    mov     eax, 1
    jmp     done
full:
    mov     eax, 2
done:
    add     rsp, 60h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GuiRe_CaptureHwnd ENDP

END
