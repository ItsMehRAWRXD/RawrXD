; GpuSolo_Score.asm — classify one DXGI adapter (no CRT)
INCLUDE GpuSolo.inc

PUBLIC GpuSolo_ScoreAdapter

.code

; RCX = dedicated VRAM bytes
; RDX = shared VRAM bytes
; R8D = name flags
; EAX = role
GpuSolo_ScoreAdapter PROC
    test    r8d, GPU_SOLO_NF_R9700
    jnz     role_r9700
    test    r8d, GPU_SOLO_NF_7800XT
    jnz     role_xt
    test    r8d, GPU_SOLO_NF_IGPU
    jnz     role_igpu

    mov     rax, GPU_SOLO_1GIB
    cmp     rcx, rax
    jb      role_igpu

    mov     rax, 600000000h
    cmp     rcx, rax
    jae     role_r9700

    mov     eax, GPU_SOLO_ROLE_RX7800XT
    ret

role_r9700:
    mov     eax, GPU_SOLO_ROLE_R9700
    ret

role_xt:
    mov     eax, GPU_SOLO_ROLE_RX7800XT
    ret

role_igpu:
    xor     eax, eax
    ret
GpuSolo_ScoreAdapter ENDP

END
