OPTION CASEMAP:NONE
include remote.inc
PUBLIC RemoteHeaderWrite,RemoteHeaderValidate
.code
RemoteHeaderWrite PROC
 ; rcx=header edx=type r8=seq r9d=payload
 mov DWORD PTR [rcx].REMOTE_HEADER.magic,RAWR_MAGIC
 mov WORD PTR [rcx].REMOTE_HEADER.version,RAWR_VERSION
 mov WORD PTR [rcx].REMOTE_HEADER.type,dx
 mov DWORD PTR [rcx].REMOTE_HEADER.flags,0
 mov [rcx].REMOTE_HEADER.sequence,r8
 mov [rcx].REMOTE_HEADER.payloadSize,r9d
 mov DWORD PTR [rcx].REMOTE_HEADER.reserved,0
 xor eax,eax
 ret
RemoteHeaderWrite ENDP
RemoteHeaderValidate PROC
 ; rcx=header, rdx=minimum sequence; eax 0 valid
 cmp DWORD PTR [rcx].REMOTE_HEADER.magic,RAWR_MAGIC
 jne rhv_bad
 cmp WORD PTR [rcx].REMOTE_HEADER.version,RAWR_VERSION
 jne rhv_bad
 cmp DWORD PTR [rcx].REMOTE_HEADER.payloadSize,RAWR_MAX_PAYLOAD
 ja rhv_bad
 movzx eax,WORD PTR [rcx].REMOTE_HEADER.type
 cmp eax,MSG_HELLO
 je rhv_typeok
 cmp eax,MSG_CHALLENGE
 je rhv_typeok
 cmp eax,MSG_AUTH_PROOF
 je rhv_typeok
 cmp eax,MSG_AUTH_RESULT
 je rhv_typeok
 cmp eax,MSG_FRAME_BEGIN
 je rhv_typeok
 cmp eax,MSG_TILE
 je rhv_typeok
 cmp eax,MSG_FRAME_END
 je rhv_typeok
 cmp eax,MSG_CURSOR
 je rhv_typeok
 cmp eax,MSG_DISPLAY
 je rhv_typeok
 cmp eax,MSG_MOUSE
 je rhv_typeok
 cmp eax,MSG_KEYBOARD
 je rhv_typeok
 cmp eax,MSG_PING
 je rhv_typeok
 cmp eax,MSG_PONG
 je rhv_typeok
 cmp eax,MSG_CLOSE
 jne rhv_bad
rhv_typeok:
 mov rax,[rcx].REMOTE_HEADER.sequence
 cmp rax,rdx
 jb rhv_bad
 xor eax,eax
 ret
rhv_bad: mov eax,R_BOUNDS
 ret
RemoteHeaderValidate ENDP
END
