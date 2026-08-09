; MAPM.asm - Memory Addressed Prefetch Map
; emit 12:34 (60/1) - 60 prefetch emissions per 1 inference token
; Maps expert addresses → PCIe DMA schedule → slingshot feed
;
; Ratio: 12:34 = prefetch window : execution window (microseconds)
;        60/1  = 60 address emissions queued per token consumed

OPTION CASEMAP:NONE
.CODE

; ── Constants ────────────────────────────────────────────────────────────────
EMIT_RATIO      EQU 60          ; emissions per token
PREFETCH_WIN    EQU 12          ; prefetch window (us)
EXEC_WIN        EQU 34          ; execution window (us)
CHUNK_SIZE      EQU 67108864    ; 64MB PCIe chunk
MAX_SLOTS       EQU 256         ; max expert address slots

; ── MAPM_Entry: one address map entry ────────────────────────────────────────
; [expert_id: 4][vram_addr: 8][ram_addr: 8][size: 8][state: 4][checksum: 4]
MAPM_ENTRY_SIZE EQU 36

; ── MAPM_Emit: emit 60 prefetch addresses for 1 token ────────────────────────
; rcx = float* gate_logits (n_experts floats)
; rdx = MAPM_Entry* map    (address table)
; r8  = int n_experts
; r9  = int* out_ids       (60 emitted expert ids, caller allocated)
; returns rax = count emitted (≤60)
MAPM_Emit PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 40h            ; shadow space

    mov     r12, rcx            ; gate_logits
    mov     r13, rdx            ; map
    mov     r14d, r8d           ; n_experts
    mov     r15, r9             ; out_ids

    ; ── Pass 1: find top-60 by gate logit (partial selection sort) ───────────
    xor     r11d, r11d          ; emitted count = 0
    mov     ebx, EMIT_RATIO     ; target = 60

.emit_loop:
    cmp     r11d, ebx
    jge     .emit_done
    cmp     r11d, r14d
    jge     .emit_done

    ; find max logit not yet emitted
    vxorps  ymm0, ymm0, ymm0
    vmovss  xmm1, dword ptr [r12]   ; best_val = logits[0]
    xor     esi, esi                 ; best_idx = 0
    xor     edi, edi                 ; i = 0

.find_max:
    cmp     edi, r14d
    jge     .found_max

    ; check if already emitted (scan out_ids[0..r11d-1])
    xor     ecx, ecx
.check_dup:
    cmp     ecx, r11d
    jge     .not_dup
    mov     eax, dword ptr [r15 + rcx*4]
    cmp     eax, edi
    je      .skip_expert
    inc     ecx
    jmp     .check_dup
.not_dup:
    vmovss  xmm2, dword ptr [r12 + rdi*4]
    vucomiss xmm2, xmm1
    jbe     .skip_expert
    vmovss  xmm1, xmm2
    mov     esi, edi
.skip_expert:
    inc     edi
    jmp     .find_max

.found_max:
    ; store best_idx into out_ids[r11d]
    mov     dword ptr [r15 + r11*4], esi

    ; ── emit: stamp MAPM entry with prefetch address ─────────────────────────
    ; map[esi].state = PREFETCHING (1)
    imul    rax, rsi, MAPM_ENTRY_SIZE
    add     rax, r13
    mov     dword ptr [rax + 28], 1     ; state offset = 28

    inc     r11d
    jmp     .emit_loop

.emit_done:
    mov     eax, r11d           ; return count

    add     rsp, 40h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MAPM_Emit ENDP


; ── MAPM_Schedule: apply 12:34 timing window to emitted ids ──────────────────
; rcx = int* emitted_ids
; rdx = int  count
; r8  = MAPM_Entry* map
; r9  = uint64_t* out_timestamps  (rdtsc-based, caller allocated)
; Stamps each entry with: prefetch_start = now + (i * PREFETCH_WIN * tsc_per_us)
; Execution window begins at prefetch_start + PREFETCH_WIN
MAPM_Schedule PROC
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 40h

    mov     r12, rcx            ; emitted_ids
    mov     r13d, edx           ; count
    mov     rbx, r8             ; map
    mov     rdi, r9             ; out_timestamps

    ; get current TSC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rsi, rax            ; base_tsc

    ; approximate TSC ticks per microsecond (~3000 for 3GHz, adjust per CPU)
    mov     ecx, 3000           ; tsc_per_us

    xor     r11d, r11d          ; i = 0
.sched_loop:
    cmp     r11d, r13d
    jge     .sched_done

    ; prefetch_start = base_tsc + i * PREFETCH_WIN * tsc_per_us
    mov     eax, r11d
    imul    eax, PREFETCH_WIN
    imul    rax, rcx            ; * tsc_per_us
    add     rax, rsi            ; + base_tsc

    ; store timestamp
    mov     qword ptr [rdi + r11*8], rax

    ; stamp map entry: offset 0=expert_id already set, use offset 32 for ts
    mov     eax, dword ptr [r12 + r11*4]   ; expert_id
    imul    r10, rax, MAPM_ENTRY_SIZE
    add     r10, rbx
    ; store exec_window_start = prefetch_start + PREFETCH_WIN * tsc_per_us
    mov     r8, rax
    imul    r8, PREFETCH_WIN
    imul    r8, rcx
    add     r8, qword ptr [rdi + r11*8]
    ; (exec window stored at entry+20 if needed — extend struct for full impl)

    inc     r11d
    jmp     .sched_loop

.sched_done:
    add     rsp, 40h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
MAPM_Schedule ENDP


; ── MAPM_Flush: mark all PREFETCHING slots → COLD (reset on crash/corrupt) ───
; rcx = MAPM_Entry* map
; rdx = int n_experts
MAPM_Flush PROC
    xor     eax, eax
.flush_loop:
    cmp     eax, edx
    jge     .flush_done
    imul    r8, rax, MAPM_ENTRY_SIZE
    add     r8, rcx
    mov     ecx, dword ptr [r8 + 28]   ; state
    cmp     ecx, 1                      ; PREFETCHING?
    jne     .flush_next
    mov     dword ptr [r8 + 28], 0      ; → COLD
.flush_next:
    inc     eax
    jmp     .flush_loop
.flush_done:
    ret
MAPM_Flush ENDP

END
