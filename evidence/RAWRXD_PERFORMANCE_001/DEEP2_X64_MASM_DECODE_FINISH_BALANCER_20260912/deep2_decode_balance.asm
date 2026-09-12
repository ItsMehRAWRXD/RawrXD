option casemap:none
include deep2_decode_balance.inc

.code

; rcx = D2DB_STATE*
D2DbInit PROC
    test rcx, rcx
    jz short init_done
    xor rax, rax
    mov [rcx+D2S_MAGIC], rax
    mov [rcx+D2S_COST0_Q16], rax
    mov [rcx+D2S_COST1_Q16], rax
    mov [rcx+D2S_START_SKEW_EWMA_NS], rax
    mov [rcx+D2S_FINISH_SKEW_EWMA_NS], rax
    mov [rcx+D2S_BEST_CRITICAL_NS], rax
    mov dword ptr [rcx+D2S_BEST_SHARE1_Q16], D2DB_DEFAULT_GPU1_SHARE_Q16
    mov dword ptr [rcx+D2S_SHARE1_Q16], D2DB_DEFAULT_GPU1_SHARE_Q16
    mov dword ptr [rcx+D2S_VALID_SAMPLES], 0
    mov dword ptr [rcx+D2S_BAD_SAMPLES], 0
    mov [rcx+D2S_TOKEN_INDEX], rax
    mov [rcx+D2S_LAST_CRITICAL_NS], rax
    mov [rcx+D2S_LAST_FINISH_SKEW_NS], rax
    mov [rcx+D2S_LAST_START_SKEW_NS], rax
    mov [rcx+D2S_FLAGS], rax
    mov rax, D2DB_VALID_MAGIC
    mov [rcx+D2S_MAGIC], rax
init_done:
    ret
D2DbInit ENDP

; rcx=state, edx=totalRows, r8d=rowAlignment, r9=plan
; Returns eax=1 success, 0 invalid.
; Model solve minimizes max absolute completion time:
; S0 + c0*w0 ~= S1 + c1*w1, w0+w1=W
; w0 = (c1*W + (S1-S0)) / (c0+c1)
; costs are Q16 ns/row so start skew is promoted by <<16.
D2DbPlanToken PROC
    test rcx, rcx
    jz plan_fail
    test r9, r9
    jz plan_fail
    test edx, edx
    jz plan_fail
    cmp qword ptr [rcx+D2S_MAGIC], D2DB_VALID_MAGIC
    jne plan_fail
    test r8d, r8d
    jnz short align_ok
    mov r8d, 1
align_ok:
    mov r10d, edx                    ; total rows
    mov r11, [rcx+D2S_COST0_Q16]
    mov rax, [rcx+D2S_COST1_Q16]
    test r11, r11
    jz seed_plan
    test rax, rax
    jz seed_plan

    ; numerator = c1*W + start_skew<<16 (signed)
    imul rax, r10                    ; c1_q16 * rows
    mov rdx, [rcx+D2S_START_SKEW_EWMA_NS]
    shl rdx, 16
    add rax, rdx
    ; denom = c0+c1
    mov rdx, r11
    add rdx, [rcx+D2S_COST1_Q16]
    test rdx, rdx
    jz seed_plan
    ; signed clamp numerator >= alignment before division
    test rax, rax
    jg short numerator_ok
    mov eax, r8d
    jmp short got_rows0_raw
numerator_ok:
    ; signed division rax / denominator; numerator positive in normal path
    mov r11, rdx                     ; denom
    xor rdx, rdx
    div r11
    ; rax rows0 raw
got_rows0_raw:
    mov r11d, eax
    mov dword ptr [r9+D2P_MODE], 1
    jmp short clamp_rows

seed_plan:
    ; rows1 = W * default share; rows0 = W-rows1
    mov eax, [rcx+D2S_SHARE1_Q16]
    mov r11d, eax
    mov eax, r10d
    imul rax, r11
    shr rax, 16
    mov r11d, r10d
    sub r11d, eax
    mov dword ptr [r9+D2P_MODE], 0

clamp_rows:
    ; ensure at least one aligned tile on each lane
    mov eax, r8d
    cmp r11d, eax
    jae short low_ok
    mov r11d, eax
low_ok:
    mov eax, r10d
    sub eax, r8d
    cmp r11d, eax
    jbe short high_ok
    mov r11d, eax
high_ok:
    ; align rows0 down, then rows1 gets remainder; keep GPU1 non-zero
    mov eax, r11d
    xor edx, edx
    div r8d
    imul eax, r8d
    mov r11d, eax
    mov eax, r10d
    sub eax, r11d
    test eax, eax
    jnz short aligned_ok
    sub r11d, r8d
    mov eax, r8d
aligned_ok:
    mov [r9+D2P_ROWS0], r11d
    mov [r9+D2P_ROWS1], eax

    ; share1_q16 = rows1/total
    mov edx, eax
    mov rax, rdx
    shl rax, 16
    xor rdx, rdx
    div r10
    mov [r9+D2P_SHARE1_Q16], eax

    ; predicted relative ends when model exists
    xor rax, rax
    mov [r9+D2P_PRED_END0_NS], rax
    mov [r9+D2P_PRED_END1_NS], rax
    mov r11, [rcx+D2S_COST0_Q16]
    test r11, r11
    jz short plan_ok
    mov eax, [r9+D2P_ROWS0]
    imul rax, r11
    shr rax, 16
    mov [r9+D2P_PRED_END0_NS], rax
    mov r11, [rcx+D2S_COST1_Q16]
    mov eax, [r9+D2P_ROWS1]
    imul rax, r11
    shr rax, 16
    add rax, [rcx+D2S_START_SKEW_EWMA_NS]
    mov [r9+D2P_PRED_END1_NS], rax
plan_ok:
    mov eax, 1
    ret
plan_fail:
    xor eax, eax
    ret
D2DbPlanToken ENDP

; rcx=state, rdx=sample
; Returns eax: 1 accepted, 0 rejected/fail-closed.
D2DbObserveToken PROC
    push rsi
    push rdi
    mov rsi, rcx                     ; state
    mov rdi, rdx                     ; sample
    test rsi, rsi
    jz obs_fail
    test rdi, rdi
    jz obs_fail
    cmp qword ptr [rsi+D2S_MAGIC], D2DB_VALID_MAGIC
    jne obs_fail

    ; Fail closed unless all product/correctness invariants hold.
    cmp dword ptr [rdi+D2M_OUTPUT_PARITY], 1
    jne obs_bad
    cmp dword ptr [rdi+D2M_DEVICE_OK], 1
    jne obs_bad
    cmp dword ptr [rdi+D2M_SAME_TOKEN], 1
    jne obs_bad
    cmp dword ptr [rdi+D2M_PRODUCT_LINKED], 1
    jne obs_bad
    cmp dword ptr [rdi+D2M_PACKED_LIVE], 1
    jne obs_bad
    cmp dword ptr [rdi+D2M_SERIAL_CHAIN], 0
    jne obs_bad
    cmp dword ptr [rdi+D2M_WEIGHT_MIGRATION], 0
    jne obs_bad

    mov r8, [rdi+D2M_END0_NS]
    sub r8, [rdi+D2M_START0_NS]      ; duration0
    mov r9, [rdi+D2M_END1_NS]
    sub r9, [rdi+D2M_START1_NS]      ; duration1
    test r8, r8
    jle obs_bad
    test r9, r9
    jle obs_bad
    mov r10d, [rdi+D2M_ROWS0]
    mov r11d, [rdi+D2M_ROWS1]
    test r10d, r10d
    jz obs_bad
    test r11d, r11d
    jz obs_bad

    ; cost0 sample Q16
    mov rax, r8
    shl rax, 16
    xor rdx, rdx
    div r10
    mov r10, rax
    ; cost1 sample Q16
    mov rax, r9
    shl rax, 16
    xor rdx, rdx
    mov r11d, [rdi+D2M_ROWS1]
    div r11
    mov r11, rax

    ; EWMA cost0: old += (sample-old)/8; first sample installs directly.
    mov rax, [rsi+D2S_COST0_Q16]
    test rax, rax
    jz short cost0_first
    mov rdx, r10
    sub rdx, rax
    sar rdx, D2DB_EWMA_SHIFT
    add rax, rdx
cost0_first:
    test rax, rax
    jnz short cost0_store
    mov rax, r10
cost0_store:
    mov [rsi+D2S_COST0_Q16], rax

    mov rax, [rsi+D2S_COST1_Q16]
    test rax, rax
    jz short cost1_first
    mov rdx, r11
    sub rdx, rax
    sar rdx, D2DB_EWMA_SHIFT
    add rax, rdx
cost1_first:
    test rax, rax
    jnz short cost1_store
    mov rax, r11
cost1_store:
    mov [rsi+D2S_COST1_Q16], rax

    ; start skew = S1-S0, finish skew = E1-E0 (signed authority metrics)
    mov r10, [rdi+D2M_START1_NS]
    sub r10, [rdi+D2M_START0_NS]
    mov r11, [rdi+D2M_END1_NS]
    sub r11, [rdi+D2M_END0_NS]
    mov [rsi+D2S_LAST_START_SKEW_NS], r10
    mov [rsi+D2S_LAST_FINISH_SKEW_NS], r11

    ; signed EWMA start skew
    mov rax, [rsi+D2S_START_SKEW_EWMA_NS]
    mov rdx, r10
    sub rdx, rax
    sar rdx, D2DB_EWMA_SHIFT
    add rax, rdx
    mov [rsi+D2S_START_SKEW_EWMA_NS], rax
    ; signed EWMA finish skew
    mov rax, [rsi+D2S_FINISH_SKEW_EWMA_NS]
    mov rdx, r11
    sub rdx, rax
    sar rdx, D2DB_EWMA_SHIFT
    add rax, rdx
    mov [rsi+D2S_FINISH_SKEW_EWMA_NS], rax

    mov rax, [rdi+D2M_CRITICAL_NS]
    test rax, rax
    jz obs_bad
    mov [rsi+D2S_LAST_CRITICAL_NS], rax

    ; best critical path retention; derive current observed GPU1 share.
    mov rdx, [rsi+D2S_BEST_CRITICAL_NS]
    test rdx, rdx
    jz short install_best
    cmp rax, rdx
    jae short check_regress
install_best:
    mov [rsi+D2S_BEST_CRITICAL_NS], rax
    mov eax, [rdi+D2M_ROWS1]
    shl rax, 16
    xor rdx, rdx
    mov r10d, [rdi+D2M_ROWS0]
    add r10d, [rdi+D2M_ROWS1]
    div r10
    mov [rsi+D2S_BEST_SHARE1_Q16], eax
    mov [rsi+D2S_SHARE1_Q16], eax
    and qword ptr [rsi+D2S_FLAGS], NOT D2DB_F_ROLLBACK_LAST
    jmp short accepted

check_regress:
    ; if critical > best*1.05, rollback seed share toward best immediately.
    mov r10, [rsi+D2S_BEST_CRITICAL_NS]
    imul r10, D2DB_REGRESS_PM
    mov rax, [rdi+D2M_CRITICAL_NS]
    imul rax, 1000
    cmp rax, r10
    jbe short accepted
    mov eax, [rsi+D2S_BEST_SHARE1_Q16]
    mov [rsi+D2S_SHARE1_Q16], eax
    or qword ptr [rsi+D2S_FLAGS], D2DB_F_ROLLBACK_LAST

accepted:
    inc dword ptr [rsi+D2S_VALID_SAMPLES]
    inc qword ptr [rsi+D2S_TOKEN_INDEX]
    or qword ptr [rsi+D2S_FLAGS], D2DB_F_MODEL_READY or D2DB_F_AUTH_VALID
    mov eax, 1
    pop rdi
    pop rsi
    ret

obs_bad:
    inc dword ptr [rsi+D2S_BAD_SAMPLES]
obs_fail:
    xor eax, eax
    pop rdi
    pop rsi
    ret
D2DbObserveToken ENDP

END
