; ============================================================================
; TokenPressure_x64.asm — TOKEN_PRESSURE_VALVE_001
; Cheap hot loop: window hash / repeat / stall / fence pressure.
; No CRT. No heap. Orthogonal to ctx/temp/GPU/path.
; ============================================================================
option casemap:none
include TokenPressure_x64.inc
.code

PUBLIC TokenPressure_Init
PUBLIC TokenPressure_SetSpray
PUBLIC TokenPressure_Update

; void TokenPressure_Init(void* state)
TokenPressure_Init PROC
    test    rcx, rcx
    jz      short ti_done
    mov     r8, rcx
    xor     eax, eax
    mov     edx, TP_STATE_SIZE / 8
ti_z:
    mov     qword ptr [r8], rax
    add     r8, 8
    dec     edx
    jnz     short ti_z
    mov     qword ptr [rcx + TP_OFF_MAGIC], TP_MAGIC
    mov     qword ptr [rcx + TP_OFF_VERSION], TP_VERSION
ti_done:
    ret
TokenPressure_Init ENDP

; void TokenPressure_SetSpray(void* state, uint64_t mode)
TokenPressure_SetSpray PROC
    test    rcx, rcx
    jz      short ts_done
    cmp     qword ptr [rcx + TP_OFF_MAGIC], TP_MAGIC
    jne     short ts_done
    mov     qword ptr [rcx + TP_OFF_SPRAY], rdx
ts_done:
    ret
TokenPressure_SetSpray ENDP

; uint64_t TokenPressure_Update(state, tokenHash, flags)
; RCX=state RDX=hash R8=flags → RAX=action
TokenPressure_Update PROC
    test    rcx, rcx
    jz      tu_fail
    cmp     qword ptr [rcx + TP_OFF_MAGIC], TP_MAGIC
    jne     tu_fail

    ; push hash into 8-slot ring at OFF_WIN0
    mov     r9, qword ptr [rcx + TP_OFF_WIN_COUNT]
    mov     r10, r9
    and     r10, 7
    lea     r11, [rcx + TP_OFF_WIN0]
    mov     qword ptr [r11 + r10*8], rdx
    inc     r9
    mov     qword ptr [rcx + TP_OFF_WIN_COUNT], r9

    ; count matches of current hash in window
    xor     eax, eax
    mov     r10d, 8
    lea     r11, [rcx + TP_OFF_WIN0]
tu_scan:
    cmp     qword ptr [r11], rdx
    jne     short tu_nmatch
    inc     rax
tu_nmatch:
    add     r11, 8
    dec     r10d
    jnz     short tu_scan
    mov     qword ptr [rcx + TP_OFF_REPEAT], rax

    test    r8, TP_FLAG_FILLER
    jz      short tu_nf
    inc     qword ptr [rcx + TP_OFF_STALL]
tu_nf:
    test    r8, TP_FLAG_FENCE
    jz      short tu_nfe
    xor     qword ptr [rcx + TP_OFF_FENCE_OPEN], 1
tu_nfe:
    mov     r10, qword ptr [rcx + TP_OFF_FENCE_OPEN]
    mov     qword ptr [rcx + TP_OFF_CODE], r10

    ; decision
    mov     r9, qword ptr [rcx + TP_OFF_SPRAY]
    cmp     rax, 4
    jb      short tu_chk_stall
    mov     eax, TP_ACT_PENALIZE_REPEAT
    cmp     r9, TP_SPRAY_CUTOFF
    jne     short tu_store
    mov     eax, TP_ACT_STOP_REQUEST
    jmp     short tu_store

tu_chk_stall:
    cmp     qword ptr [rcx + TP_OFF_STALL], 24
    jb      short tu_chk_brace
    cmp     r9, TP_SPRAY_NEEDLE
    je      short tu_stop
    mov     eax, TP_ACT_PREFER_STOP
    jmp     short tu_store
tu_stop:
    mov     eax, TP_ACT_STOP_REQUEST
    jmp     short tu_store

tu_chk_brace:
    test    r8, TP_FLAG_BRACE
    jz      short tu_pass
    cmp     r9, TP_SPRAY_REPAIR
    jne     short tu_pass
    mov     eax, TP_ACT_PREFER_STOP
    jmp     short tu_store

tu_pass:
    xor     eax, eax
tu_store:
    mov     qword ptr [rcx + TP_OFF_LAST_ACTION], rax
    ret
tu_fail:
    xor     eax, eax
    ret
TokenPressure_Update ENDP
END
