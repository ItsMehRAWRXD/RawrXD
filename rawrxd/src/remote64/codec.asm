OPTION CASEMAP:NONE
PUBLIC RemoteRleEncode,RemoteRleDecode
.code
RemoteRleEncode PROC
 ; rcx src rdx bytes r8 dst r9 cap ; [count][byte]
 push rbx
 push rsi
 mov r10,rcx
 mov r11,rdx
 xor eax,eax
 test r11,r11
 jz re_done
re_next: mov bl,[r10]
 mov esi,1
re_run: cmp esi,255
 jae re_emit
 mov edx,esi
 cmp rdx,r11
 jae re_emit
 cmp bl,[r10+rdx]
 jne re_emit
 inc esi
 jmp re_run
re_emit: lea rdx,[rax+2]
 cmp rdx,r9
 ja re_fail
 mov [r8+rax],sil
 mov [r8+rax+1],bl
 add rax,2
 mov edx,esi
 add r10,rdx
 sub r11,rdx
 jnz re_next
re_done: pop rsi
 pop rbx
 ret
re_fail: xor eax,eax
 pop rsi
 pop rbx
 ret
RemoteRleEncode ENDP
RemoteRleDecode PROC
 ; rcx src rdx bytes r8 dst r9 cap
 xor r10,r10
rd_next: test rdx,rdx
 jz rd_done
 cmp rdx,2
 jb rd_fail
 movzx r11d,BYTE PTR [rcx]
 test r11d,r11d
 jz rd_fail
 mov al,[rcx+1]
 mov rax,r10
 add rax,r11
 cmp rax,r9
 ja rd_fail
 mov al,[rcx+1]
rd_write: mov [r8+r10],al
 inc r10
 dec r11d
 jnz rd_write
 add rcx,2
 sub rdx,2
 jmp rd_next
rd_done: mov rax,r10
 ret
rd_fail: xor eax,eax
 ret
RemoteRleDecode ENDP
END
