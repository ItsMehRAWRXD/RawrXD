OPTION CASEMAP:NONE
include remote.inc
EXTERN RemoteAlloc:PROC
EXTERN RemoteFree:PROC
EXTERN StretchDIBits:PROC
PUBLIC RemoteViewerInit,RemoteViewerDestroy,RemoteViewerPutTile,RemoteViewerPaint
DIB_RGB_COLORS EQU 0
SRCCOPY EQU 00CC0020h
.code
RemoteViewerInit PROC
 ; rcx=v edx=w r8d=h
 push rbx
 sub rsp,20h
 mov rbx,rcx
 mov [rbx].REMOTE_VIEWER.frameW,edx
 mov [rbx].REMOTE_VIEWER.frameH,r8d
 mov eax,edx
 shl eax,2
 mov [rbx].REMOTE_VIEWER.stride,eax
 mov ecx,eax
 imul rcx,r8
 mov [rbx].REMOTE_VIEWER.bytes,rcx
 call RemoteAlloc
 mov [rbx].REMOTE_VIEWER.pixels,rax
 test rax,rax
 jz rvi_fail
 mov DWORD PTR [rbx].REMOTE_VIEWER.initialized,1
 xor eax,eax
 jmp rvi_done
rvi_fail: mov eax,R_ERR
rvi_done: add rsp,20h
 pop rbx
 ret
RemoteViewerInit ENDP
RemoteViewerDestroy PROC
 push rbx
 sub rsp,20h
 mov rbx,rcx
 mov rcx,[rbx].REMOTE_VIEWER.pixels
 call RemoteFree
 mov DWORD PTR [rbx].REMOTE_VIEWER.initialized,0
 add rsp,20h
 pop rbx
 ret
RemoteViewerDestroy ENDP
RemoteViewerPutTile PROC
 ; rcx=v rdx=tilehdr r8=rawBGRA
 push rbx
 push rsi
 push rdi
 mov rbx,rcx
 mov eax,[rdx].REMOTE_TILE_HEADER.tileX
 mov r9d,[rdx].REMOTE_TILE_HEADER.tileY
 mov r10d,[rdx].REMOTE_TILE_HEADER.tileW
 mov r11d,[rdx].REMOTE_TILE_HEADER.tileH
 mov ecx,eax
 add ecx,r10d
 cmp ecx,[rbx].REMOTE_VIEWER.frameW
 ja rvpt_fail
 mov ecx,r9d
 add ecx,r11d
 cmp ecx,[rbx].REMOTE_VIEWER.frameH
 ja rvpt_fail
 mov rsi,r8
 mov rdi,[rbx].REMOTE_VIEWER.pixels
 mov ecx,r9d
 imul rcx,QWORD PTR [rbx].REMOTE_VIEWER.stride
 add rdi,rcx
 lea rdi,[rdi+rax*4]
 mov r9d,r10d
 shl r9d,2
rvpt_row: test r11d,r11d
 jz rvpt_ok
 mov ecx,r9d
rvpt_copy: test ecx,ecx
 jz rvpt_next
 mov al,[rsi]
 mov [rdi],al
 inc rsi
 inc rdi
 dec ecx
 jmp rvpt_copy
rvpt_next: sub rdi,r9
 mov eax,[rbx].REMOTE_VIEWER.stride
 add rdi,rax
 dec r11d
 jmp rvpt_row
rvpt_ok: xor eax,eax
 jmp rvpt_done
rvpt_fail: mov eax,R_BOUNDS
rvpt_done: pop rdi
 pop rsi
 pop rbx
 ret
RemoteViewerPutTile ENDP
RemoteViewerPaint PROC
 ; rcx=v rdx=HDC r8d=destW r9d=destH
 push rbx
 sub rsp,80h
 mov rbx,rcx
 cmp DWORD PTR [rbx].REMOTE_VIEWER.initialized,1
 jne rvp_fail
 lea r10,[rsp+50h]
 xor eax,eax
 mov QWORD PTR [r10],rax
 mov QWORD PTR [r10+8],rax
 mov QWORD PTR [r10+16],rax
 mov QWORD PTR [r10+24],rax
 mov QWORD PTR [r10+32],rax
 mov DWORD PTR [r10],40
 mov eax,[rbx].REMOTE_VIEWER.frameW
 mov [r10+4],eax
 mov eax,[rbx].REMOTE_VIEWER.frameH
 neg eax
 mov [r10+8],eax
 mov WORD PTR [r10+12],1
 mov WORD PTR [r10+14],32
 mov rcx,rdx
 xor edx,edx
 xor r8d,r8d
 ; destW/destH are lost from r8/r9 after overwrite; save before in production integration
 ; paint native size to guarantee valid ABI here
 mov r9d,[rbx].REMOTE_VIEWER.frameW
 mov eax,[rbx].REMOTE_VIEWER.frameH
 mov [rsp+20h],eax
 mov DWORD PTR [rsp+28h],0
 mov DWORD PTR [rsp+30h],0
 mov eax,[rbx].REMOTE_VIEWER.frameW
 mov [rsp+38h],eax
 mov eax,[rbx].REMOTE_VIEWER.frameH
 mov [rsp+40h],eax
 mov rax,[rbx].REMOTE_VIEWER.pixels
 mov [rsp+48h],rax
 mov [rsp+50h],r10
 mov DWORD PTR [rsp+58h],DIB_RGB_COLORS
 mov DWORD PTR [rsp+60h],SRCCOPY
 call StretchDIBits
 xor eax,eax
 jmp rvp_done
rvp_fail: mov eax,R_STATE
rvp_done: add rsp,80h
 pop rbx
 ret
RemoteViewerPaint ENDP
END
