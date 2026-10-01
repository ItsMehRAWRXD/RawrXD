OPTION CASEMAP:NONE
include remote.inc
EXTERN GetDC:PROC
EXTERN ReleaseDC:PROC
EXTERN CreateCompatibleDC:PROC
EXTERN CreateCompatibleBitmap:PROC
EXTERN SelectObject:PROC
EXTERN DeleteObject:PROC
EXTERN DeleteDC:PROC
EXTERN GetSystemMetrics:PROC
EXTERN BitBlt:PROC
EXTERN GetDIBits:PROC
EXTERN RemoteAlloc:PROC
EXTERN RemoteFree:PROC
PUBLIC RemoteCaptureInit,RemoteCaptureFrame,RemoteCaptureDestroy
SM_CXSCREEN EQU 0
SM_CYSCREEN EQU 1
SRCCOPY EQU 00CC0020h
CAPTUREBLT EQU 40000000h
DIB_RGB_COLORS EQU 0
.code
RemoteCaptureInit PROC
 push rbx
 sub rsp,40h
 mov rbx,rcx
 mov ecx,SM_CXSCREEN
 call GetSystemMetrics
 test eax,eax
 jle rci_fail
 mov [rbx].REMOTE_CAPTURE.width,eax
 mov ecx,SM_CYSCREEN
 call GetSystemMetrics
 test eax,eax
 jle rci_fail
 mov [rbx].REMOTE_CAPTURE.height,eax
 mov ecx,[rbx].REMOTE_CAPTURE.width
 shl ecx,2
 mov [rbx].REMOTE_CAPTURE.stride,ecx
 mov eax,ecx
 mov ecx,[rbx].REMOTE_CAPTURE.height
 imul rax,rcx
 mov [rbx].REMOTE_CAPTURE.bytes,rax
 xor ecx,ecx
 call GetDC
 test rax,rax
 jz rci_fail
 mov [rbx].REMOTE_CAPTURE.screenDC,rax
 mov rcx,rax
 call CreateCompatibleDC
 test rax,rax
 jz rci_fail
 mov [rbx].REMOTE_CAPTURE.memoryDC,rax
 mov rcx,[rbx].REMOTE_CAPTURE.screenDC
 mov edx,[rbx].REMOTE_CAPTURE.width
 mov r8d,[rbx].REMOTE_CAPTURE.height
 call CreateCompatibleBitmap
 test rax,rax
 jz rci_fail
 mov [rbx].REMOTE_CAPTURE.bitmap,rax
 mov rcx,[rbx].REMOTE_CAPTURE.memoryDC
 mov rdx,rax
 call SelectObject
 mov [rbx].REMOTE_CAPTURE.oldBitmap,rax
 mov rcx,[rbx].REMOTE_CAPTURE.bytes
 call RemoteAlloc
 test rax,rax
 jz rci_fail
 mov [rbx].REMOTE_CAPTURE.pixels,rax
 mov rcx,[rbx].REMOTE_CAPTURE.bytes
 call RemoteAlloc
 test rax,rax
 jz rci_fail
 mov [rbx].REMOTE_CAPTURE.previous,rax
 mov DWORD PTR [rbx].REMOTE_CAPTURE.initialized,1
 xor eax,eax
 jmp rci_done
rci_fail: mov eax,R_ERR
rci_done: add rsp,40h
 pop rbx
 ret
RemoteCaptureInit ENDP

RemoteCaptureFrame PROC
 push rbx
 sub rsp,0A0h
 mov rbx,rcx
 cmp DWORD PTR [rbx].REMOTE_CAPTURE.initialized,1
 jne rcf_fail
 mov rcx,[rbx].REMOTE_CAPTURE.memoryDC
 xor edx,edx
 xor r8d,r8d
 mov r9d,[rbx].REMOTE_CAPTURE.width
 mov eax,[rbx].REMOTE_CAPTURE.height
 mov [rsp+20h],eax
 mov rax,[rbx].REMOTE_CAPTURE.screenDC
 mov [rsp+28h],rax
 mov DWORD PTR [rsp+30h],0
 mov DWORD PTR [rsp+38h],0
 mov DWORD PTR [rsp+40h],SRCCOPY or CAPTUREBLT
 call BitBlt
 test eax,eax
 jz rcf_fail
 ; BITMAPINFOHEADER (40 bytes) at rsp+50h
 lea r10,[rsp+50h]
 xor eax,eax
 mov QWORD PTR [r10],rax
 mov QWORD PTR [r10+8],rax
 mov QWORD PTR [r10+16],rax
 mov QWORD PTR [r10+24],rax
 mov QWORD PTR [r10+32],rax
 mov DWORD PTR [r10],40
 mov eax,[rbx].REMOTE_CAPTURE.width
 mov DWORD PTR [r10+4],eax
 mov eax,[rbx].REMOTE_CAPTURE.height
 neg eax
 mov DWORD PTR [r10+8],eax
 mov WORD PTR [r10+12],1
 mov WORD PTR [r10+14],32
 mov DWORD PTR [r10+16],0
 mov rcx,[rbx].REMOTE_CAPTURE.memoryDC
 mov rdx,[rbx].REMOTE_CAPTURE.bitmap
 xor r8d,r8d
 mov r9d,[rbx].REMOTE_CAPTURE.height
 mov rax,[rbx].REMOTE_CAPTURE.pixels
 mov [rsp+20h],rax
 lea rax,[rsp+50h]
 mov [rsp+28h],rax
 mov DWORD PTR [rsp+30h],DIB_RGB_COLORS
 call GetDIBits
 test eax,eax
 jz rcf_fail
 xor eax,eax
 jmp rcf_done
rcf_fail: mov eax,R_ERR
rcf_done: add rsp,0A0h
 pop rbx
 ret
RemoteCaptureFrame ENDP

RemoteCaptureDestroy PROC
 push rbx
 sub rsp,20h
 mov rbx,rcx
 mov rcx,[rbx].REMOTE_CAPTURE.pixels
 call RemoteFree
 mov rcx,[rbx].REMOTE_CAPTURE.previous
 call RemoteFree
 mov rcx,[rbx].REMOTE_CAPTURE.memoryDC
 test rcx,rcx
 jz @F
 mov rdx,[rbx].REMOTE_CAPTURE.oldBitmap
 call SelectObject
@@: mov rcx,[rbx].REMOTE_CAPTURE.bitmap
 test rcx,rcx
 jz @F
 call DeleteObject
@@: mov rcx,[rbx].REMOTE_CAPTURE.memoryDC
 test rcx,rcx
 jz @F
 call DeleteDC
@@: mov rdx,[rbx].REMOTE_CAPTURE.screenDC
 test rdx,rdx
 jz @F
 xor ecx,ecx
 call ReleaseDC
@@: mov DWORD PTR [rbx].REMOTE_CAPTURE.initialized,0
 add rsp,20h
 pop rbx
 ret
RemoteCaptureDestroy ENDP
END
