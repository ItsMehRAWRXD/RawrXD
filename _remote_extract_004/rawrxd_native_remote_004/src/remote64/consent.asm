OPTION CASEMAP:NONE
EXTERN MessageBoxW:PROC
PUBLIC RemoteConsent_RequestControl
MB_ICONQUESTION EQU 20h
MB_YESNO EQU 4
MB_DEFBUTTON2 EQU 100h
IDYES EQU 6
.data
consentTitle dw 'R','a','w','r','X','D',' ','R','e','m','o','t','e',0
consentText dw 'A','l','l','o','w',' ','r','e','m','o','t','e',' ','m','o','u','s','e','/','k','e','y','b','o','a','r','d',' ','c','o','n','t','r','o','l','?',0
.code
RemoteConsent_RequestControl PROC
    ; rcx=owner HWND
    sub rsp,28h
    lea rdx,consentText
    lea r8,consentTitle
    mov r9d,MB_ICONQUESTION or MB_YESNO or MB_DEFBUTTON2
    call MessageBoxW
    cmp eax,IDYES
    sete al
    movzx eax,al
    add rsp,28h
    ret
RemoteConsent_RequestControl ENDP
END
