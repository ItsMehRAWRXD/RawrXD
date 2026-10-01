OPTION CASEMAP:NONE
include remote.inc
EXTERN OpenClipboard:PROC
EXTERN CloseClipboard:PROC
EXTERN EmptyClipboard:PROC
EXTERN GetClipboardData:PROC
EXTERN SetClipboardData:PROC
EXTERN GlobalAlloc:PROC
EXTERN GlobalLock:PROC
EXTERN GlobalUnlock:PROC
EXTERN GlobalSize:PROC
EXTERN RtlMoveMemory:PROC
PUBLIC RemoteClipboard_ReadUnicode
PUBLIC RemoteClipboard_WriteUnicode

CF_UNICODETEXT EQU 13
GMEM_MOVEABLE EQU 2

.code
RemoteClipboard_ReadUnicode PROC
    ; rcx=dst, rdx=capacity bytes. rax=bytes copied incl NUL, 0 failure
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rdi, rcx
    mov rsi, rdx
    xor ecx, ecx
    call OpenClipboard
    test eax,eax
    jz cr_fail
    mov ecx, CF_UNICODETEXT
    call GetClipboardData
    test rax,rax
    jz cr_close
    mov rbx,rax
    mov rcx,rbx
    call GlobalSize
    test rax,rax
    jz cr_close
    cmp rax,rsi
    ja cr_close
    mov rsi,rax
    mov rcx,rbx
    call GlobalLock
    test rax,rax
    jz cr_close
    mov rcx,rdi
    mov rdx,rax
    mov r8,rsi
    call RtlMoveMemory
    mov rcx,rbx
    call GlobalUnlock
    mov rbx,rsi
    call CloseClipboard
    mov rax,rbx
    jmp cr_done
cr_close:
    call CloseClipboard
cr_fail:
    xor eax,eax
cr_done:
    add rsp,20h
    pop rdi
    pop rsi
    pop rbx
    ret
RemoteClipboard_ReadUnicode ENDP

RemoteClipboard_WriteUnicode PROC
    ; rcx=src UTF-16, rdx=bytes incl NUL. eax=1 success
    push rbx
    push rsi
    push rdi
    sub rsp,20h
    mov rsi,rcx
    mov rdi,rdx
    mov ecx,GMEM_MOVEABLE
    mov rdx,rdi
    call GlobalAlloc
    test rax,rax
    jz cw_fail
    mov rbx,rax
    mov rcx,rbx
    call GlobalLock
    test rax,rax
    jz cw_fail
    mov rcx,rax
    mov rdx,rsi
    mov r8,rdi
    call RtlMoveMemory
    mov rcx,rbx
    call GlobalUnlock
    xor ecx,ecx
    call OpenClipboard
    test eax,eax
    jz cw_fail
    call EmptyClipboard
    mov ecx,CF_UNICODETEXT
    mov rdx,rbx
    call SetClipboardData
    mov rbx,rax
    call CloseClipboard
    xor eax,eax
    test rbx,rbx
    setnz al
    jmp cw_done
cw_fail:
    xor eax,eax
cw_done:
    add rsp,20h
    pop rdi
    pop rsi
    pop rbx
    ret
RemoteClipboard_WriteUnicode ENDP
END
