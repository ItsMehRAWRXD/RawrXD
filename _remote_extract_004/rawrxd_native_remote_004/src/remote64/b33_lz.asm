OPTION CASEMAP:NONE
PUBLIC RemotePackBits_Encode
PUBLIC RemotePackBits_Decode
.code
; PackBits-like literal-only safe fallback: [len:u8][bytes], len 1..255.
RemotePackBits_Encode PROC
    ; rcx src, rdx bytes, r8 dst, r9 cap
    xor r10,r10
pe_loop:
    test rdx,rdx
    jz pe_done
    mov r11,rdx
    cmp r11,255
    jbe @F
    mov r11,255
@@: lea rax,[r10+r11+1]
    cmp rax,r9
    ja pe_fail
    mov [r8+r10],r11b
    inc r10
    xor eax,eax
@@c: cmp rax,r11
    jae @F
    mov r9b,[rcx+rax]
    mov [r8+r10],r9b
    inc r10
    inc rax
    jmp @c
@@: add rcx,r11
    sub rdx,r11
    jmp pe_loop
pe_done: mov rax,r10
    ret
pe_fail: xor eax,eax
    ret
RemotePackBits_Encode ENDP
RemotePackBits_Decode PROC
    ; rcx src, rdx bytes, r8 dst, r9 cap
    xor r10,r10
pd_loop:
    test rdx,rdx
    jz pd_done
    movzx r11d,BYTE PTR [rcx]
    test r11d,r11d
    jz pd_fail
    inc rcx
    dec rdx
    cmp r11,rdx
    ja pd_fail
    lea rax,[r10+r11]
    cmp rax,r9
    ja pd_fail
    xor eax,eax
@@c: cmp rax,r11
    jae @F
    mov r9b,[rcx+rax]
    mov [r8+r10],r9b
    inc r10
    inc rax
    jmp @c
@@: add rcx,r11
    sub rdx,r11
    jmp pd_loop
pd_done: mov rax,r10
    ret
pd_fail: xor eax,eax
    ret
RemotePackBits_Decode ENDP
END
