OPTION CASEMAP:NONE
include remote.inc
PUBLIC RemoteTileChanged,RemoteCopyTile,RemoteFrameCommit
.code
RemoteTileChanged PROC
 ; rcx=current rdx=previous r8=stride r9=x, stack y,w,h
 push rbx
 push rsi
 push rdi
 mov eax,DWORD PTR [rsp+20h+24]
 mov r10d,DWORD PTR [rsp+28h+24]
 mov r11d,DWORD PTR [rsp+30h+24]
 mov ebx,DWORD PTR [rsp+38h+24]
 ; offset y*stride + x*4
 mov esi,eax
 imul rsi,r8
 lea rsi,[rsi+r9*4]
 add rcx,rsi
 add rdx,rsi
 mov edi,r10d
 shl edi,2
rtc_row: test ebx,ebx
 jz rtc_same
 mov rsi,rdi
rtc_cmp: test rsi,rsi
 jz rtc_next
 mov al,[rcx]
 cmp al,[rdx]
 jne rtc_dirty
 inc rcx
 inc rdx
 dec rsi
 jmp rtc_cmp
rtc_next:
 sub rcx,rdi
 sub rdx,rdi
 add rcx,r8
 add rdx,r8
 dec ebx
 jmp rtc_row
rtc_dirty: mov eax,1
 jmp rtc_done
rtc_same: xor eax,eax
rtc_done: pop rdi
 pop rsi
 pop rbx
 ret
RemoteTileChanged ENDP
RemoteCopyTile PROC
 ; rcx=dst contiguous, rdx=frame, r8=stride, r9=x, stack y,w,h
 push rbx
 push rsi
 push rdi
 mov eax,DWORD PTR [rsp+20h+24]
 mov r10d,DWORD PTR [rsp+28h+24]
 mov r11d,DWORD PTR [rsp+30h+24]
 mov ebx,DWORD PTR [rsp+38h+24]
 mov esi,eax
 imul rsi,r8
 lea rsi,[rsi+r9*4]
 add rdx,rsi
 mov edi,r10d
 shl edi,2
rct_row: test ebx,ebx
 jz rct_done
 mov esi,edi
rct_copy: test esi,esi
 jz rct_next
 mov al,[rdx]
 mov [rcx],al
 inc rcx
 inc rdx
 dec esi
 jmp rct_copy
rct_next: sub rdx,rdi
 add rdx,r8
 dec ebx
 jmp rct_row
rct_done: xor eax,eax
 pop rdi
 pop rsi
 pop rbx
 ret
RemoteCopyTile ENDP
RemoteFrameCommit PROC
 ; rcx=capture; copies current -> previous
 mov r8,[rcx].REMOTE_CAPTURE.bytes
 mov rdx,[rcx].REMOTE_CAPTURE.pixels
 mov rcx,[rcx].REMOTE_CAPTURE.previous
 test r8,r8
 jz rfc_done
rfc_loop: mov al,[rdx]
 mov [rcx],al
 inc rcx
 inc rdx
 dec r8
 jnz rfc_loop
rfc_done: xor eax,eax
 ret
RemoteFrameCommit ENDP
END
