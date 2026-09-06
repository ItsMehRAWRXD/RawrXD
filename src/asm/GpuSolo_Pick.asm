; GpuSolo_Pick.asm — open exactly one matching adapter index
INCLUDE GpuSolo.inc

PUBLIC GpuSolo_PickOpenIndex

.code

; RCX = roles DWORD*
; RDX = dedicated VRAM QWORD*
; R8  = count
; R9D = wanted role
; RAX = index or -1
GpuSolo_PickOpenIndex PROC
    push    rbx
    mov     rbx, -1
    xor     r10, r10
    xor     r11, r11

pick_loop:
    cmp     r10, r8
    jae     pick_done
    cmp     dword ptr [rcx + r10*4], r9d
    jne     pick_next
    mov     rax, qword ptr [rdx + r10*8]
    cmp     rbx, -1
    je      pick_take
    cmp     rax, r11
    jb      pick_next
pick_take:
    mov     r11, rax
    mov     rbx, r10
pick_next:
    inc     r10
    jmp     pick_loop

pick_done:
    mov     rax, rbx
    pop     rbx
    ret
GpuSolo_PickOpenIndex ENDP

END
