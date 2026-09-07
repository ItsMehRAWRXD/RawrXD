; Deep2OuterPath.asm — dir + "\\" + name / dir + "\\*.gguf"
OPTION CASEMAP:NONE
INCLUDE Deep2OuterRuntime.inc
EXTERN OuterCopyZ:PROC
EXTERN OuterCatZ:PROC
EXTERN OuterLenA:PROC
PUBLIC OuterJoinPath
PUBLIC OuterMakeGlob

.data
slash_star db "\*.gguf",0
slash_one  db "\",0

.code
; RCX=dir RDX=name R8=dst
OuterJoinPath PROC
    push rsi
    push rdi
    sub rsp, 28h
    mov rsi, rdx
    mov rdi, r8
    mov rdx, rcx
    mov rcx, rdi
    call OuterCopyZ
    mov rcx, rdi
    call OuterLenA
    test eax, eax
    jz JP_Cat
    cmp byte ptr [rdi+rax-1], '\'
    je JP_Name
    cmp byte ptr [rdi+rax-1], '/'
    je JP_Name
    mov rcx, rdi
    lea rdx, slash_one
    call OuterCatZ
JP_Name:
    mov rcx, rdi
    mov rdx, rsi
    call OuterCatZ
    jmp JP_Done
JP_Cat:
    mov rcx, rdi
    mov rdx, rsi
    call OuterCopyZ
JP_Done:
    add rsp, 28h
    pop rdi
    pop rsi
    ret
OuterJoinPath ENDP

; RCX=dir RDX=dst
OuterMakeGlob PROC
    push rdi
    sub rsp, 20h
    mov rdi, rdx
    mov rdx, rcx
    mov rcx, rdi
    call OuterCopyZ
    mov rcx, rdi
    lea rdx, slash_star
    call OuterCatZ
    add rsp, 20h
    pop rdi
    ret
OuterMakeGlob ENDP
END
