option casemap:none
include ..\include\deep2_nodep.inc
PUBLIC Deep2RangeTicketCopy
.code
; rcx=dst, rdx=src. Descriptor only; never reads weight bytes itself.
Deep2RangeTicketCopy PROC
    test rcx, rcx
    jz rtc_fail
    test rdx, rdx
    jz rtc_fail
    mov rax, [rdx+0]
    mov [rcx+0], rax
    mov rax, [rdx+8]
    mov [rcx+8], rax
    mov rax, [rdx+16]
    mov [rcx+16], rax
    mov rax, [rdx+24]
    mov [rcx+24], rax
    mov rax, [rdx+32]
    mov [rcx+32], rax
    mov rax, [rdx+40]
    mov [rcx+40], rax
    mov rax, [rdx+48]
    mov [rcx+48], rax
    mov rax, [rdx+56]
    mov [rcx+56], rax
    mov eax, 1
    ret
rtc_fail:
    xor eax, eax
    ret
Deep2RangeTicketCopy ENDP
END
