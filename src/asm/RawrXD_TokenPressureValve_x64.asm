; TOKEN_PRESSURE_VALVE_001
; RawrXD no-dependency x64 MASM token-flow controller.
;
; Purpose:
;   Pattern pressure on decoded token ids.  This module never changes ctx,
;   temperature, GPU split, model path, or lifecycle.  It returns action bits
;   the existing sampler/streamer can honor.

OPTION CASEMAP:NONE
INCLUDE RawrXD_TokenPressureValve_x64.inc

.code

TPV_Clamp100 MACRO reg32
    cmp     reg32, 100
    jbe     @F
    mov     reg32, 100
@@:
ENDM

PUBLIC TPV_SecureZero
TPV_SecureZero PROC
    ; rcx = ptr, rdx = bytes
    test    rcx, rcx
    jz      tpv_zero_done
    test    rdx, rdx
    jz      tpv_zero_done
tpv_zero_loop:
    mov     byte ptr [rcx], 0
    inc     rcx
    dec     rdx
    jne     tpv_zero_loop
tpv_zero_done:
    ret
TPV_SecureZero ENDP

PUBLIC TPV_InitState
TPV_InitState PROC
    ; rcx = TPV_State*, edx = mode, r8d = flags
    test    rcx, rcx
    jz      tpv_init_bad
    mov     r9d, edx
    mov     r10d, r8d

    xor     eax, eax
    mov     r11, rcx
    mov     edx, TPV_STATE_BYTES / 8
tpv_init_clear_q:
    mov     qword ptr [r11], rax
    add     r11, 8
    dec     edx
    jne     tpv_init_clear_q

    mov     dword ptr [rcx + TPV_OFF_MAGIC], TPV_MAGIC_VALUE
    mov     dword ptr [rcx + TPV_OFF_VERSION], TPV_VERSION_VALUE
    cmp     r9d, TPV_MODE_REPAIR
    jbe     @F
    mov     r9d, TPV_MODE_NEEDLE
@@:
    mov     dword ptr [rcx + TPV_OFF_MODE], r9d
    mov     dword ptr [rcx + TPV_OFF_FLAGS], r10d
    mov     rax, 0CBF29CE484222325h
    mov     qword ptr [rcx + TPV_OFF_SEAL64], rax
    xor     eax, eax
    ret
tpv_init_bad:
    mov     eax, 1
    ret
TPV_InitState ENDP

PUBLIC TPV_Reset
TPV_Reset PROC
    ; rcx = TPV_State*.  Keeps mode/flags, clears dynamic pressure.
    test    rcx, rcx
    jz      tpv_reset_bad
    cmp     dword ptr [rcx + TPV_OFF_MAGIC], TPV_MAGIC_VALUE
    jne     tpv_reset_bad
    mov     r9d, dword ptr [rcx + TPV_OFF_MODE]
    mov     r10d, dword ptr [rcx + TPV_OFF_FLAGS]

    xor     eax, eax
    mov     r11, rcx
    mov     edx, TPV_STATE_BYTES / 8
tpv_reset_clear_q:
    mov     qword ptr [r11], rax
    add     r11, 8
    dec     edx
    jne     tpv_reset_clear_q

    mov     dword ptr [rcx + TPV_OFF_MAGIC], TPV_MAGIC_VALUE
    mov     dword ptr [rcx + TPV_OFF_VERSION], TPV_VERSION_VALUE
    mov     dword ptr [rcx + TPV_OFF_MODE], r9d
    mov     dword ptr [rcx + TPV_OFF_FLAGS], r10d
    mov     rax, 0CBF29CE484222325h
    mov     qword ptr [rcx + TPV_OFF_SEAL64], rax
    xor     eax, eax
    ret
tpv_reset_bad:
    mov     eax, 1
    ret
TPV_Reset ENDP

PUBLIC TPV_SetMode
TPV_SetMode PROC
    ; rcx = TPV_State*, edx = mode
    test    rcx, rcx
    jz      tpv_set_bad
    cmp     dword ptr [rcx + TPV_OFF_MAGIC], TPV_MAGIC_VALUE
    jne     tpv_set_bad
    cmp     edx, TPV_MODE_REPAIR
    ja      tpv_set_bad
    mov     dword ptr [rcx + TPV_OFF_MODE], edx
    xor     eax, eax
    ret
tpv_set_bad:
    mov     eax, 1
    ret
TPV_SetMode ENDP

PUBLIC TPV_UpdateToken
TPV_UpdateToken PROC
    ; rcx = TPV_State*, edx = token id, r8d = token flags, r9 = TPV_Result*
    test    rcx, rcx
    jz      tpv_update_bad
    test    r9, r9
    jz      tpv_update_bad
    cmp     dword ptr [rcx + TPV_OFF_MAGIC], TPV_MAGIC_VALUE
    jne     tpv_update_bad

    ; Count current token occurrences in the existing 64-token ring.
    xor     eax, eax
    mov     r10d, dword ptr [rcx + TPV_OFF_COUNT]
    cmp     r10d, TPV_RING_COUNT
    jbe     @F
    mov     r10d, TPV_RING_COUNT
@@:
    lea     r11, [rcx + TPV_OFF_RING]
    test    r10d, r10d
    jz      tpv_occ_done
tpv_occ_loop:
    cmp     dword ptr [r11], edx
    jne     @F
    inc     eax
@@:
    add     r11, 4
    dec     r10d
    jne     tpv_occ_loop
tpv_occ_done:
    shl     eax, 3
    TPV_Clamp100 eax
    mov     dword ptr [rcx + TPV_OFF_REPEAT], eax

    ; Run pressure: same adjacent token repeatedly.
    cmp     dword ptr [rcx + TPV_OFF_RUN_TOKEN], edx
    jne     tpv_new_run
    mov     eax, dword ptr [rcx + TPV_OFF_RUN_LENGTH]
    inc     eax
    mov     dword ptr [rcx + TPV_OFF_RUN_LENGTH], eax
    jmp     tpv_run_scored
tpv_new_run:
    mov     dword ptr [rcx + TPV_OFF_RUN_TOKEN], edx
    mov     eax, 1
    mov     dword ptr [rcx + TPV_OFF_RUN_LENGTH], eax
tpv_run_scored:
    cmp     eax, 2
    ja      @F
    xor     eax, eax
    jmp     tpv_run_store
@@:
    sub     eax, 2
    imul    eax, eax, 16
    TPV_Clamp100 eax
tpv_run_store:
    mov     dword ptr [rcx + TPV_OFF_RUNPRESS], eax

    ; Stall pressure: filler/whitespace raises, sentence/end/newline bleeds it down.
    mov     eax, dword ptr [rcx + TPV_OFF_STALL]
    test    r8d, TPV_TOK_FILLER
    jz      @F
    add     eax, 18
@@:
    test    r8d, TPV_TOK_WHITESPACE
    jz      @F
    add     eax, 4
@@:
    test    r8d, TPV_TOK_DECAY_STALL
    jz      @F
    cmp     eax, 12
    jb      tpv_stall_zero
    sub     eax, 12
    jmp     @F
tpv_stall_zero:
    xor     eax, eax
@@:
    TPV_Clamp100 eax
    mov     dword ptr [rcx + TPV_OFF_STALL], eax

    ; Structure pressure: braces, fences, and code blocks.
    test    r8d, TPV_TOK_BRACE_OPEN
    jz      @F
    inc     dword ptr [rcx + TPV_OFF_BRACE_DEPTH]
@@:
    test    r8d, TPV_TOK_BRACE_CLOSE
    jz      @F
    cmp     dword ptr [rcx + TPV_OFF_BRACE_DEPTH], 0
    jle     @F
    dec     dword ptr [rcx + TPV_OFF_BRACE_DEPTH]
@@:
    test    r8d, TPV_TOK_FENCE
    jz      @F
    xor     dword ptr [rcx + TPV_OFF_FENCE_PARITY], 1
@@:
    test    r8d, TPV_TOK_NEWLINE
    jz      @F
    inc     dword ptr [rcx + TPV_OFF_LINE_COUNT]
@@:
    xor     eax, eax
    mov     r10d, dword ptr [rcx + TPV_OFF_BRACE_DEPTH]
    test    r10d, r10d
    jle     @F
    lea     eax, [r10d + r10d*2]
@@:
    cmp     dword ptr [rcx + TPV_OFF_FENCE_PARITY], 0
    je      @F
    add     eax, 35
@@:
    test    r8d, TPV_TOK_CODE
    jz      @F
    add     eax, 8
@@:
    TPV_Clamp100 eax
    mov     dword ptr [rcx + TPV_OFF_STRUCT], eax

    ; Repair pressure and approval pressure.
    mov     eax, dword ptr [rcx + TPV_OFF_REPAIR]
    test    r8d, TPV_TOK_ERROR
    jz      tpv_repair_decay
    add     eax, 40
    jmp     tpv_repair_store
tpv_repair_decay:
    test    eax, eax
    jz      tpv_repair_store
    dec     eax
tpv_repair_store:
    TPV_Clamp100 eax
    mov     dword ptr [rcx + TPV_OFF_REPAIR], eax

    mov     eax, dword ptr [rcx + TPV_OFF_APPROVAL]
    test    r8d, TPV_TOK_APPROVAL
    jz      tpv_approval_decay
    mov     eax, 100
    jmp     tpv_approval_store
tpv_approval_decay:
    cmp     eax, 8
    jb      tpv_approval_zero
    sub     eax, 8
    jmp     tpv_approval_store
tpv_approval_zero:
    xor     eax, eax
tpv_approval_store:
    mov     dword ptr [rcx + TPV_OFF_APPROVAL], eax

    ; Insert into ring.
    mov     eax, dword ptr [rcx + TPV_OFF_POS]
    and     eax, TPV_RING_COUNT - 1
    lea     r10, [rcx + TPV_OFF_RING]
    mov     dword ptr [r10 + rax*4], edx
    lea     r10, [rcx + TPV_OFF_RING_FLAGS]
    mov     dword ptr [r10 + rax*4], r8d
    inc     eax
    and     eax, TPV_RING_COUNT - 1
    mov     dword ptr [rcx + TPV_OFF_POS], eax
    cmp     dword ptr [rcx + TPV_OFF_COUNT], TPV_RING_COUNT
    jae     @F
    inc     dword ptr [rcx + TPV_OFF_COUNT]
@@:
    mov     dword ptr [rcx + TPV_OFF_LAST_TOKEN], edx
    inc     qword ptr [rcx + TPV_OFF_TOTAL_TOKENS]

    ; Rolling seal: FNV-1a over token id and supplied flags.
    mov     rax, qword ptr [rcx + TPV_OFF_SEAL64]
    mov     r10, 00000100000001B3h
    mov     r11d, edx
    xor     rax, r11
    imul    rax, r10
    mov     r11d, r8d
    shl     r11, 32
    xor     rax, r11
    imul    rax, r10
    mov     qword ptr [rcx + TPV_OFF_SEAL64], rax

    ; Build action bits from mode and pressures.
    xor     eax, eax
    mov     r10d, dword ptr [rcx + TPV_OFF_MODE]
    cmp     r10d, TPV_MODE_NEEDLE
    jne     @F
    or      eax, TPV_ACT_NARROW
@@:
    cmp     r10d, TPV_MODE_MIST
    jne     @F
    or      eax, TPV_ACT_WIDEN
@@:
    cmp     r10d, TPV_MODE_PULSE
    jne     @F
    mov     r11, qword ptr [rcx + TPV_OFF_TOTAL_TOKENS]
    and     r11d, 7
    cmp     r11d, 4
    jb      tpv_pulse_wide
    or      eax, TPV_ACT_NARROW_COMPRESS
    jmp     @F
tpv_pulse_wide:
    or      eax, TPV_ACT_WIDEN
@@:
    cmp     r10d, TPV_MODE_RINSE
    jne     @F
    or      eax, TPV_ACT_COMPRESS
@@:
    cmp     r10d, TPV_MODE_REPAIR
    jne     @F
    or      eax, TPV_ACT_REPAIR_NARROW
@@:

    cmp     dword ptr [rcx + TPV_OFF_REPEAT], 24
    jb      @F
    or      eax, TPV_ACT_REPEAT_NARROW
@@:
    cmp     dword ptr [rcx + TPV_OFF_RUNPRESS], 48
    jb      @F
    or      eax, TPV_ACT_STOP_HINT
@@:
    cmp     dword ptr [rcx + TPV_OFF_STALL], 72
    jb      @F
    or      eax, TPV_ACT_COMPRESS
@@:
    cmp     dword ptr [rcx + TPV_OFF_STALL], 90
    jb      @F
    or      eax, TPV_ACT_STOP_HINT
@@:
    cmp     dword ptr [rcx + TPV_OFF_STRUCT], 35
    jb      @F
    or      eax, TPV_ACT_CLOSE_STRUCT
@@:
    cmp     dword ptr [rcx + TPV_OFF_REPAIR], 35
    jb      @F
    or      eax, TPV_ACT_REPAIR_NARROW
@@:
    cmp     dword ptr [rcx + TPV_OFF_APPROVAL], 0
    je      @F
    or      eax, TPV_ACT_APPROVAL_STOP
@@:
    test    r8d, TPV_TOK_STOPLIKE
    jz      @F
    or      eax, TPV_ACT_STOP_HINT
@@:
    cmp     r10d, TPV_MODE_CUTOFF
    jne     @F
    cmp     dword ptr [rcx + TPV_OFF_REPEAT], 16
    jae     tpv_cutoff_stop
    cmp     dword ptr [rcx + TPV_OFF_RUNPRESS], 32
    jae     tpv_cutoff_stop
    jmp     @F
tpv_cutoff_stop:
    or      eax, TPV_ACT_STOP_HINT
@@:

    ; Fill result.
    mov     dword ptr [r9 + TPVR_OFF_ACTION], eax
    mov     eax, dword ptr [rcx + TPV_OFF_MODE]
    mov     dword ptr [r9 + TPVR_OFF_MODE], eax
    mov     eax, dword ptr [rcx + TPV_OFF_REPEAT]
    mov     dword ptr [r9 + TPVR_OFF_REPEAT], eax
    mov     eax, dword ptr [rcx + TPV_OFF_RUNPRESS]
    mov     dword ptr [r9 + TPVR_OFF_RUNPRESS], eax
    mov     eax, dword ptr [rcx + TPV_OFF_STALL]
    mov     dword ptr [r9 + TPVR_OFF_STALL], eax
    mov     eax, dword ptr [rcx + TPV_OFF_STRUCT]
    mov     dword ptr [r9 + TPVR_OFF_STRUCT], eax
    mov     eax, dword ptr [rcx + TPV_OFF_REPAIR]
    mov     dword ptr [r9 + TPVR_OFF_REPAIR], eax
    mov     eax, dword ptr [rcx + TPV_OFF_APPROVAL]
    mov     dword ptr [r9 + TPVR_OFF_APPROVAL], eax
    mov     eax, dword ptr [rcx + TPV_OFF_LINE_COUNT]
    mov     dword ptr [r9 + TPVR_OFF_LINE_COUNT], eax
    mov     eax, dword ptr [rcx + TPV_OFF_BRACE_DEPTH]
    mov     dword ptr [r9 + TPVR_OFF_BRACE_DEPTH], eax
    mov     eax, dword ptr [rcx + TPV_OFF_FENCE_PARITY]
    mov     dword ptr [r9 + TPVR_OFF_FENCE_PARITY], eax
    mov     dword ptr [r9 + TPVR_OFF_RESERVED0], 0
    mov     rax, qword ptr [rcx + TPV_OFF_TOTAL_TOKENS]
    mov     qword ptr [r9 + TPVR_OFF_TOTAL_TOKENS], rax
    mov     rax, qword ptr [rcx + TPV_OFF_SEAL64]
    mov     qword ptr [r9 + TPVR_OFF_SEAL64], rax
    xor     eax, eax
    ret
tpv_update_bad:
    mov     eax, 1
    ret
TPV_UpdateToken ENDP

PUBLIC TPV_ProbeWindow
TPV_ProbeWindow PROC
    ; rcx = uint32_t token_ids*, edx = count, r8 = TPV_Result*
    test    r8, r8
    jz      tpv_probe_bad

    ; Zero result.
    xor     eax, eax
    mov     r9, r8
    mov     r10d, TPV_RESULT_BYTES / 8
tpv_probe_clear:
    mov     qword ptr [r9], rax
    add     r9, 8
    dec     r10d
    jne     tpv_probe_clear

    test    rcx, rcx
    jz      tpv_probe_done
    test    edx, edx
    jz      tpv_probe_done

    ; Adjacent-run pressure and seal.
    mov     rax, 0CBF29CE484222325h
    mov     r10, 00000100000001B3h
    xor     r11d, r11d          ; index
    mov     r9d, dword ptr [rcx]
    mov     dword ptr [r8 + TPVR_OFF_TOTAL_TOKENS], edx
    mov     dword ptr [r8 + TPVR_OFF_TOTAL_TOKENS + 4], 0
    mov     dword ptr [r8 + TPVR_OFF_RUNPRESS], 0
    mov     dword ptr [r8 + TPVR_OFF_REPEAT], 0

tpv_probe_loop:
    cmp     r11d, edx
    jae     tpv_probe_after
    mov     r9d, dword ptr [rcx + r11*4]
    xor     rax, r9
    imul    rax, r10
    test    r11d, r11d
    jz      tpv_probe_next
    cmp     r9d, dword ptr [rcx + r11*4 - 4]
    jne     tpv_probe_next
    mov     r9d, dword ptr [r8 + TPVR_OFF_RUNPRESS]
    add     r9d, 16
    TPV_Clamp100 r9d
    mov     dword ptr [r8 + TPVR_OFF_RUNPRESS], r9d
tpv_probe_next:
    inc     r11d
    jmp     tpv_probe_loop

tpv_probe_after:
    mov     qword ptr [r8 + TPVR_OFF_SEAL64], rax
    mov     eax, dword ptr [r8 + TPVR_OFF_RUNPRESS]
    cmp     eax, 48
    jb      tpv_probe_done
    mov     dword ptr [r8 + TPVR_OFF_ACTION], TPV_ACT_REPEAT_STOP
tpv_probe_done:
    xor     eax, eax
    ret
tpv_probe_bad:
    mov     eax, 1
    ret
TPV_ProbeWindow ENDP

PUBLIC TPV_SealState
TPV_SealState PROC
    ; rcx = TPV_State*. Returns FNV-1a over state bytes excluding seal64.
    test    rcx, rcx
    jz      tpv_seal_zero
    mov     rax, 0CBF29CE484222325h
    mov     r8, 00000100000001B3h
    xor     r9d, r9d
tpv_seal_head:
    cmp     r9d, TPV_OFF_SEAL64
    jae     tpv_seal_tail_setup
    movzx   r10, byte ptr [rcx + r9]
    xor     rax, r10
    imul    rax, r8
    inc     r9d
    jmp     tpv_seal_head
tpv_seal_tail_setup:
    mov     r9d, TPV_OFF_SEAL64 + 8
tpv_seal_tail:
    cmp     r9d, TPV_STATE_BYTES
    jae     tpv_seal_done
    movzx   r10, byte ptr [rcx + r9]
    xor     rax, r10
    imul    rax, r8
    inc     r9d
    jmp     tpv_seal_tail
tpv_seal_done:
    ret
tpv_seal_zero:
    xor     eax, eax
    ret
TPV_SealState ENDP

END
