; deep2_lb.asm
; Adaptive same-token dual-GPU row balancer for Deep2.
; Pure integer x64 MASM. No CRT. No allocator. No OS calls.
;
; Windows x64 ABI:
;   D2LbInit(RCX=state*)
;   D2LbPlan(RCX=state*, EDX=totalRows, R8D=alignRows, R9=plan*)
;   D2LbObserve(RCX=state*, RDX=sample*)
;
; Policy:
;   * seed at 80/20 (GPU0/GPU1)
;   * measure actual lane duration and effective ns/row
;   * if GPU1 is the long tail, reduce GPU1 share
;   * if GPU0 is the long tail, increase GPU1 share
;   * near matched durations, use the measured ns/row model only as a settling hint
;   * reject invalid/parity/device-failed samples
;   * retain best critical-path split and pull back toward it after >5% regression

OPTION CASEMAP:NONE
include deep2_lb.inc

.code

; ------------------------------------------------------------
; void D2LbInit(D2LB_STATE *s)
; ------------------------------------------------------------
D2LbInit PROC
    test rcx, rcx
    jz   short init_done

    xor rax, rax
    mov QWORD PTR [rcx+00h], rax
    mov QWORD PTR [rcx+08h], rax
    mov QWORD PTR [rcx+10h], rax
    mov QWORD PTR [rcx+18h], rax
    mov QWORD PTR [rcx+20h], rax
    mov QWORD PTR [rcx+28h], rax
    mov QWORD PTR [rcx+30h], rax
    mov QWORD PTR [rcx+38h], rax
    mov QWORD PTR [rcx+40h], rax
    mov QWORD PTR [rcx+48h], rax
    mov QWORD PTR [rcx+50h], rax
    mov QWORD PTR [rcx+58h], rax
    mov QWORD PTR [rcx+60h], rax
    mov QWORD PTR [rcx+68h], rax

    mov DWORD PTR [rcx].D2LB_STATE.share1_q16,      D2LB_Q16_80_20_LANE1
    mov DWORD PTR [rcx].D2LB_STATE.best_share1_q16, D2LB_Q16_80_20_LANE1
    mov DWORD PTR [rcx].D2LB_STATE.min_share1_q16,  D2LB_Q16_MIN_LANE1
    mov DWORD PTR [rcx].D2LB_STATE.max_share1_q16,  D2LB_Q16_MAX_LANE1
    mov QWORD PTR [rcx].D2LB_STATE.best_critical_ns, -1
init_done:
    ret
D2LbInit ENDP

; ------------------------------------------------------------
; void D2LbPlan(state*, totalRows, alignRows, plan*)
; Produces an aligned, bounded split.
; ------------------------------------------------------------
D2LbPlan PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    .endprolog

    mov rbx, rcx                    ; state
    mov edi, edx                    ; totalRows
    mov esi, r8d                    ; alignRows
    test r9, r9
    jz plan_done

    ; clear plan
    xor rax, rax
    mov QWORD PTR [r9+00h], rax
    mov QWORD PTR [r9+08h], rax
    mov QWORD PTR [r9+10h], rax
    mov QWORD PTR [r9+18h], rax

    test rbx, rbx
    jz short plan_done
    test edi, edi
    jz short plan_done
    test esi, esi
    jnz short align_ok
    mov esi, 1
align_ok:

    ; If totalRows < 2*alignRows, fail closed to one lane.
    mov eax, esi
    add eax, esi
    cmp edi, eax
    jae short dual_possible

    mov DWORD PTR [r9].D2LB_PLAN.rows0, edi
    mov DWORD PTR [r9].D2LB_PLAN.rows1, 0
    mov DWORD PTR [r9].D2LB_PLAN.share1_q16, 0
    mov DWORD PTR [r9].D2LB_PLAN.flags, D2LB_PLAN_SINGLE_FALLBACK
    mov DWORD PTR [rbx].D2LB_STATE.last_plan_flags, D2LB_PLAN_SINGLE_FALLBACK
    jmp plan_done

dual_possible:
    ; rows1 = round(totalRows * share1_q16 / 65536) to nearest alignRows.
    mov eax, DWORD PTR [rbx].D2LB_STATE.share1_q16
    mov ecx, eax
    mov eax, edi
    mul rcx                         ; RDX:RAX = totalRows * share
    shr rax, 16
    mov ecx, eax                    ; candidate rows1

    ; round candidate to nearest alignment: ((x + a/2)/a)*a
    mov eax, esi
    shr eax, 1
    add ecx, eax
    mov eax, ecx
    xor edx, edx
    div esi
    imul eax, esi
    mov ecx, eax

    ; clamp rows1 to [alignRows, totalRows-alignRows]
    cmp ecx, esi
    jae short clamp_hi
    mov ecx, esi
clamp_hi:
    mov eax, edi
    sub eax, esi
    cmp ecx, eax
    jbe short split_ready
    mov ecx, eax
split_ready:
    mov eax, edi
    sub eax, ecx                    ; rows0

    mov DWORD PTR [r9].D2LB_PLAN.rows0, eax
    mov DWORD PTR [r9].D2LB_PLAN.rows1, ecx
    mov edx, DWORD PTR [rbx].D2LB_STATE.share1_q16
    mov DWORD PTR [r9].D2LB_PLAN.share1_q16, edx
    mov DWORD PTR [r9].D2LB_PLAN.flags, D2LB_PLAN_DUAL_ACTIVE

    mov DWORD PTR [rbx].D2LB_STATE.last_rows0, eax
    mov DWORD PTR [rbx].D2LB_STATE.last_rows1, ecx
    mov DWORD PTR [rbx].D2LB_STATE.last_align_rows, esi
    mov DWORD PTR [rbx].D2LB_STATE.last_plan_flags, D2LB_PLAN_DUAL_ACTIVE

    ; predicted0 = (ewma_nsrow0_q16 * rows0) >> 16
    mov r10, QWORD PTR [rbx].D2LB_STATE.ewma_nsrow0_q16
    test r10, r10
    jz short pred1
    mov ecx, DWORD PTR [r9].D2LB_PLAN.rows0
    mov rax, r10
    mul rcx
    shrd rax, rdx, 16
    mov QWORD PTR [r9].D2LB_PLAN.predicted_ns0, rax
pred1:
    mov r10, QWORD PTR [rbx].D2LB_STATE.ewma_nsrow1_q16
    test r10, r10
    jz short plan_done
    mov ecx, DWORD PTR [r9].D2LB_PLAN.rows1
    mov rax, r10
    mul rcx
    shrd rax, rdx, 16
    mov QWORD PTR [r9].D2LB_PLAN.predicted_ns1, rax

plan_done:
    pop rdi
    pop rsi
    pop rbx
    ret
D2LbPlan ENDP

; ------------------------------------------------------------
; void D2LbObserve(state*, sample*)
; ------------------------------------------------------------
D2LbObserve PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 20h
    .allocstack 20h
    .endprolog

    mov rbx, rcx                    ; state
    mov rsi, rdx                    ; sample
    test rbx, rbx
    jz observe_done
    test rsi, rsi
    jz observe_done

    ; Fail closed unless timing, output parity, and device state are all valid.
    mov eax, DWORD PTR [rsi].D2LB_SAMPLE.flags
    and eax, D2LB_SAMPLE_REQUIRED
    cmp eax, D2LB_SAMPLE_REQUIRED
    jne reject_sample

    mov r12d, DWORD PTR [rsi].D2LB_SAMPLE.rows0
    mov r13d, DWORD PTR [rsi].D2LB_SAMPLE.rows1
    test r12d, r12d
    jz reject_sample
    test r13d, r13d
    jz reject_sample

    mov r14, QWORD PTR [rsi].D2LB_SAMPLE.duration0_ns
    mov r15, QWORD PTR [rsi].D2LB_SAMPLE.duration1_ns
    test r14, r14
    jz reject_sample
    test r15, r15
    jz reject_sample

    ; critical = supplied critical_ns, else max(duration0,duration1)
    mov rdi, QWORD PTR [rsi].D2LB_SAMPLE.critical_ns
    test rdi, rdi
    jnz short critical_ready
    mov rdi, r14
    cmp rdi, r15
    jae short critical_ready
    mov rdi, r15
critical_ready:

    mov QWORD PTR [rbx].D2LB_STATE.last_duration0_ns, r14
    mov QWORD PTR [rbx].D2LB_STATE.last_duration1_ns, r15
    mov QWORD PTR [rbx].D2LB_STATE.last_critical_ns, rdi
    mov rax, QWORD PTR [rsi].D2LB_SAMPLE.overlap_ns
    mov QWORD PTR [rbx].D2LB_STATE.last_overlap_ns, rax

    ; skew = abs(d0-d1)
    mov rax, r14
    cmp r14, r15
    jae short skew_sub_1
    mov rax, r15
    sub rax, r14
    jmp short skew_ready
skew_sub_1:
    sub rax, r15
skew_ready:
    mov QWORD PTR [rbx].D2LB_STATE.last_skew_ns, rax
    mov QWORD PTR [rsp+00h], rax    ; local skew

    ; cost0_q16 = (duration0 << 16) / rows0
    mov rax, r14
    xor rdx, rdx
    shld rdx, rax, 16
    shl rax, 16
    mov ecx, r12d
    div rcx
    mov r10, rax                    ; sample cost0

    ; cost1_q16 = (duration1 << 16) / rows1
    mov rax, r15
    xor rdx, rdx
    shld rdx, rax, 16
    shl rax, 16
    mov ecx, r13d
    div rcx
    mov r11, rax                    ; sample cost1

    ; Robust clamp: once an EWMA exists, limit a single sample to [0.5x, 2x].
    mov rax, QWORD PTR [rbx].D2LB_STATE.ewma_nsrow0_q16
    test rax, rax
    jz short ewma0_seed
    mov rcx, rax
    shr rcx, 1
    cmp r10, rcx
    jae short ewma0_hi
    mov r10, rcx
ewma0_hi:
    mov rcx, rax
    shl rcx, 1
    cmp r10, rcx
    jbe short ewma0_update
    mov r10, rcx
ewma0_update:
    ; old + (sample-old)/8, signed-safe for positive integers
    cmp r10, rax
    jae short ewma0_up
    mov rcx, rax
    sub rcx, r10
    shr rcx, D2LB_EWMA_SHIFT
    sub rax, rcx
    jmp short ewma0_store
ewma0_up:
    mov rcx, r10
    sub rcx, rax
    shr rcx, D2LB_EWMA_SHIFT
    add rax, rcx
    jmp short ewma0_store
ewma0_seed:
    mov rax, r10
ewma0_store:
    mov QWORD PTR [rbx].D2LB_STATE.ewma_nsrow0_q16, rax

    mov rax, QWORD PTR [rbx].D2LB_STATE.ewma_nsrow1_q16
    test rax, rax
    jz short ewma1_seed
    mov rcx, rax
    shr rcx, 1
    cmp r11, rcx
    jae short ewma1_hi
    mov r11, rcx
ewma1_hi:
    mov rcx, rax
    shl rcx, 1
    cmp r11, rcx
    jbe short ewma1_update
    mov r11, rcx
ewma1_update:
    cmp r11, rax
    jae short ewma1_up
    mov rcx, rax
    sub rcx, r11
    shr rcx, D2LB_EWMA_SHIFT
    sub rax, rcx
    jmp short ewma1_store
ewma1_up:
    mov rcx, r11
    sub rcx, rax
    shr rcx, D2LB_EWMA_SHIFT
    add rax, rcx
    jmp short ewma1_store
ewma1_seed:
    mov rax, r11
ewma1_store:
    mov QWORD PTR [rbx].D2LB_STATE.ewma_nsrow1_q16, rax

    ; sample accepted
    inc DWORD PTR [rbx].D2LB_STATE.samples_ok

    ; Best critical-path retention.
    mov rax, QWORD PTR [rbx].D2LB_STATE.best_critical_ns
    cmp rdi, rax
    jae short no_new_best
    mov QWORD PTR [rbx].D2LB_STATE.best_critical_ns, rdi
    mov eax, DWORD PTR [rbx].D2LB_STATE.share1_q16
    mov DWORD PTR [rbx].D2LB_STATE.best_share1_q16, eax
no_new_best:

    ; deadband = max(20us, critical/64)
    mov rax, rdi
    shr rax, 6
    cmp rax, D2LB_MIN_DEADBAND_NS
    jae short deadband_ready
    mov rax, D2LB_MIN_DEADBAND_NS
deadband_ready:
    mov QWORD PTR [rsp+08h], rax

    ; adaptive step Q16 based on skew fraction of critical path.
    ; base 0.78%, then 1.56%, 3.125%, 6.25% for larger skew.
    mov ecx, 512
    mov rax, QWORD PTR [rsp+00h]
    mov rdx, rdi
    shr rdx, 3                     ; critical/8
    cmp rax, rdx
    jbe short step_ready
    mov ecx, 1024
    mov rdx, rdi
    shr rdx, 2                     ; critical/4
    cmp rax, rdx
    jbe short step_ready
    mov ecx, 2048
    mov rdx, rdi
    shr rdx, 1                     ; critical/2
    cmp rax, rdx
    jbe short step_ready
    mov ecx, 4096
step_ready:

    mov eax, DWORD PTR [rbx].D2LB_STATE.share1_q16
    mov edx, eax                    ; candidate share1

    ; Compare lane durations with deadband.
    mov r8, QWORD PTR [rsp+08h]
    mov r9, r14
    add r9, r8
    cmp r15, r9
    ja short gpu1_is_tail

    mov r9, r15
    add r9, r8
    cmp r14, r9
    ja short gpu0_is_tail

    ; Near matched durations: settle gently toward measured linear model.
    ; target_share1 = cost0 / (cost0 + cost1)
    cmp DWORD PTR [rbx].D2LB_STATE.samples_ok, 4
    jb short clamp_candidate
    mov r10, QWORD PTR [rbx].D2LB_STATE.ewma_nsrow0_q16
    mov r11, QWORD PTR [rbx].D2LB_STATE.ewma_nsrow1_q16
    mov rcx, r10
    add rcx, r11
    jz short clamp_candidate
    mov rax, r10
    xor rdx, rdx
    shld rdx, rax, 16
    shl rax, 16
    div rcx                         ; EAX target share1 q16
    mov ecx, DWORD PTR [rbx].D2LB_STATE.share1_q16
    cmp eax, ecx
    jae short settle_up
    sub ecx, eax
    shr ecx, 3                     ; 1/8 nudge
    mov edx, DWORD PTR [rbx].D2LB_STATE.share1_q16
    sub edx, ecx
    jmp short clamp_candidate
settle_up:
    sub eax, ecx
    shr eax, 3
    mov edx, DWORD PTR [rbx].D2LB_STATE.share1_q16
    add edx, eax
    jmp short clamp_candidate

gpu1_is_tail:
    ; Slower GPU1 finishes late: give it fewer rows.
    sub edx, ecx
    jmp short clamp_candidate

gpu0_is_tail:
    ; Faster GPU0 now finishes late: move rows back to GPU1.
    add edx, ecx

clamp_candidate:
    mov eax, DWORD PTR [rbx].D2LB_STATE.min_share1_q16
    cmp edx, eax
    jae short clamp_max
    mov edx, eax
clamp_max:
    mov eax, DWORD PTR [rbx].D2LB_STATE.max_share1_q16
    cmp edx, eax
    jbe short rollback_check
    mov edx, eax

rollback_check:
    ; If current critical path regresses >5% above the best, pull halfway
    ; back toward the best split instead of continuing a bad direction.
    mov rax, QWORD PTR [rbx].D2LB_STATE.best_critical_ns
    cmp rax, -1
    je short commit_share
    mov rcx, rax
    imul rcx, D2LB_ROLLBACK_PCT
    mov rax, rdi
    imul rax, 100
    cmp rax, rcx
    jbe short commit_share

    mov eax, DWORD PTR [rbx].D2LB_STATE.best_share1_q16
    add eax, edx
    shr eax, 1
    mov edx, eax

commit_share:
    mov DWORD PTR [rbx].D2LB_STATE.share1_q16, edx
    jmp short observe_done

reject_sample:
    inc DWORD PTR [rbx].D2LB_STATE.samples_rejected
    ; Intentionally do not mutate the split on bad evidence.

observe_done:
    add rsp, 20h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
D2LbObserve ENDP

END
