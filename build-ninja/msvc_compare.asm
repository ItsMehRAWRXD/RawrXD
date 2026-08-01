; msvc_compare.asm - Simple MessageBoxA for comparison with MSVC
; Assemble with: ml64 msvc_compare.asm /link /subsystem:windows /entry:main user32.lib kernel32.lib

extern MessageBoxA: proc
extern ExitProcess: proc

.data
msg_text    db "Hi", 0
msg_title   db "RawrXD", 0

.code
main proc
    sub     rsp, 28h                    ; Shadow space + alignment
    
    ; MessageBoxA(NULL, "Hi", "RawrXD", MB_OK)
    xor     rcx, rcx                    ; hWnd = NULL
    lea     rdx, msg_text               ; lpText = "Hi"
    lea     r8, msg_title                 ; lpCaption = "RawrXD"
    xor     r9, r9                      ; uType = MB_OK (0)
    call    MessageBoxA
    
    ; Clean exit
    xor     rcx, rcx                    ; uExitCode = 0
    call    ExitProcess
    
    ; Should never reach here
    add     rsp, 28h
    ret
main endp

end
