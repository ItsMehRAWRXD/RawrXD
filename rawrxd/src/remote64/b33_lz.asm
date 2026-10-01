OPTION CASEMAP:NONE
PUBLIC RemotePackBits_Encode
PUBLIC RemotePackBits_Decode
.code

; Literal-run codec: [count:u8][count bytes], count in 1..255.
; Framing only: guarantees byte-exact round-trip and bounded expansion.
; It performs no run-length search; codec.asm owns actual RLE compression.
;
; Register contract (Win64):
;   rcx = source cursor (advanced as chunks are consumed)
;   rdx = remaining source bytes
;   r8  = destination pointer
;   r9  = destination capacity
;   rbx = inner loop index (non-volatile, saved)
;   r11 = chunk length
;   r10 = output index
;   rax = byte scratch
; Returns rax = bytes written, 0 on any bounds failure.
;
; BUG 61.4: the previous version used rbx as the source base and then reused
; rbx as the byte scratch inside the copy loop, so `add rbx, r11` walked off
; the end of the source buffer and faulted. The cursor now lives in rcx and rbx
; is only the loop counter.

RemotePackBits_Encode PROC
    push rbx
    sub rsp, 28h
    xor r10d, r10d                ; r10 = output index
pe_loop:
    test rdx, rdx
    jz pe_done
    mov r11, rdx
    cmp r11, 255
    jbe pe_len_ok
    mov r11, 255
pe_len_ok:
    mov rax, r10
    add rax, r11
    inc rax                      ; + length prefix byte
    cmp rax, r9                   ; capacity check reads r9, never a scratch
    ja pe_fail
    mov BYTE PTR [r8+r10], r11b
    inc r10
    xor ebx, ebx
pe_copy:
    cmp rbx, r11
    jae pe_copy_done
    mov al, BYTE PTR [rcx+rbx]
    mov [r8+r10], al
    inc r10
    inc rbx
    jmp pe_copy
pe_copy_done:
    add rcx, r11
    sub rdx, r11
    jmp pe_loop
pe_done:
    mov rax, r10
    add rsp, 28h
    pop rbx
    ret
pe_fail:
    xor eax, eax
    add rsp, 28h
    pop rbx
    ret
RemotePackBits_Encode ENDP

RemotePackBits_Decode PROC
    push rbx
    sub rsp, 28h
    xor r10d, r10d                ; r10 = output index
pd_loop:
    test rdx, rdx
    jz pd_done
    movzx r11d, BYTE PTR [rcx]
    test r11d, r11d
    jz pd_fail                    ; zero count is malformed
    cmp r11, rdx
    ja pd_fail                    ; run must fit inside the supplied input
    mov rax, r10
    add rax, r11
    cmp rax, r9
    ja pd_fail
    inc rcx
    sub rdx, r11
    xor ebx, ebx
pd_copy:
    cmp rbx, r11
    jae pd_copy_done
    mov al, BYTE PTR [rcx+rbx]
    mov [r8+r10], al
    inc r10
    inc rbx
    jmp pd_copy
pd_copy_done:
    jmp pd_loop
pd_done:
    mov rax, r10
    add rsp, 28h
    pop rbx
    ret
pd_fail:
    xor eax, eax
    add rsp, 28h
    pop rbx
    ret
RemotePackBits_Decode ENDP
END
