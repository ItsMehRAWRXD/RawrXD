; Deep2Device_Pick.asm — pick highest-score eligible adapter index
INCLUDE Deep2Device.inc

PUBLIC Deep2Device_PickBestIndex

.code

; RCX = scores DWORD*
; RDX = dedicated VRAM QWORD*
; R8  = count
; R9D = minScore
; RAX = index or -1
Deep2Device_PickBestIndex PROC
    push    rbx
    push    rsi
    push    rdi
    mov     rbx, -1             ; best index
    xor     esi, esi            ; best score
    xor     rdi, rdi            ; best vram
    xor     r10, r10            ; i

pick_loop:
    cmp     r10, r8
    jae     pick_done
    mov     eax, dword ptr [rcx + r10*4]
    cmp     eax, r9d
    jb      pick_next
    cmp     rbx, -1
    je      pick_take
    cmp     eax, esi
    ja      pick_take
    jb      pick_next
    mov     rax, qword ptr [rdx + r10*8]
    cmp     rax, rdi
    jbe     pick_next
pick_take:
    mov     esi, dword ptr [rcx + r10*4]
    mov     rdi, qword ptr [rdx + r10*8]
    mov     rbx, r10
pick_next:
    inc     r10
    jmp     pick_loop

pick_done:
    mov     rax, rbx
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Deep2Device_PickBestIndex ENDP

END
