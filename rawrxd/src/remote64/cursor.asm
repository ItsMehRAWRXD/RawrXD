OPTION CASEMAP:NONE
include remote.inc
EXTERN GetCursorInfo:PROC
PUBLIC RemoteCursorRead
CURSOR_SHOWING EQU 1
.code
RemoteCursorRead PROC
 ; rcx=REMOTE_CURSOR*, uses CURSORINFO temp
 push rbx
 sub rsp,40h
 mov rbx,rcx
 mov DWORD PTR [rsp+20h],24
 lea rcx,[rsp+20h]
 call GetCursorInfo
 test eax,eax
 jz rcr_fail
 mov eax,[rsp+28h]
 mov [rbx].REMOTE_CURSOR.cursorX,eax
 mov eax,[rsp+2Ch]
 mov [rbx].REMOTE_CURSOR.cursorY,eax
 mov eax,[rsp+24h]
 and eax,CURSOR_SHOWING
 setnz al
 movzx eax,al
 mov [rbx].REMOTE_CURSOR.visible,eax
 xor eax,eax
 jmp rcr_done
rcr_fail: mov eax,R_ERR
rcr_done: add rsp,40h
 pop rbx
 ret
RemoteCursorRead ENDP
END
