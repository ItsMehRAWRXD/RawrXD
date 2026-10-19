; g3_masm_matchw.asm — wchar/ascii needle (≤99)
OPTION CASEMAP:NONE
PUBLIC MatchW
.code
; RCX=wchar hay, RDX=ascii needle → EAX=1
MatchW PROC
    push rsi
    push rdi
    mov  rsi, rcx
    mov  rdi, rdx
o1: mov  al, [rdi]
    test al, al
    jz   yes
    xor  r8, r8
i1: mov  al, [rdi+r8]
    test al, al
    jz   yes
    movzx edx, WORD PTR [rsi+r8*2]
    cmp  al, dl
    jne  nxt
    inc  r8
    jmp  i1
nxt: add  rsi, 2
    cmp  WORD PTR [rsi], 0
    jne  o1
    xor  eax, eax
    jmp  dn
yes: mov  eax, 1
dn:  pop  rdi
    pop  rsi
    ret
MatchW ENDP
END
