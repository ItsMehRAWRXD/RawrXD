; Deep2Device_Score.asm — VRAM/capability score (no vendor hard-code)
INCLUDE Deep2Device.inc

PUBLIC Deep2Device_ScoreAdapter

.code

; RCX = dedicated VRAM bytes
; RDX = shared VRAM bytes
; R8D = name flags (optional hints only)
; EAX = score (0 = not useful for compute)
Deep2Device_ScoreAdapter PROC
    ; Integrated / tiny dedicated → low score
    mov     rax, DEV_1GIB
    cmp     rcx, rax
    jb      score_igpu

    ; score = 100 + (dedicated_GiB)
    ; dedicated >> 30 = GiB
    mov     rax, rcx
    shr     rax, 30
    add     eax, DEV_SCORE_DISCRETE_BASE

    ; Optional name hints: tiny boost only (never identity)
    test    r8d, DEV_NF_NAME_HINT_A
    jz      no_a
    add     eax, 2
no_a:
    test    r8d, DEV_NF_NAME_HINT_B
    jz      done
    add     eax, 1
    jmp     done

score_igpu:
    mov     eax, 1
    test    r8d, DEV_NF_IGPU_HINT
    jz      done
    mov     eax, 1
done:
    ret
Deep2Device_ScoreAdapter ENDP

END
