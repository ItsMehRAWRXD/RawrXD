; =============================================================================
; RawrXD_HexMag_RepeatTuner.asm — Polymorphic Repeat Tuner (pure x64 MASM)
; =============================================================================
; Port of services/hexmag/core/repeat_tuner.py — ZERO Python / CRT / weights.
;
;   WRONG != rerun same generation
;   WRONG == classify failure -> mutate genome -> new generation_id -> retry
;
; Hard invariants (HEXMAG_POLYMORPHIC_REPEAT_TUNER_001):
;   - fingerprint unique per request
;   - generation_id changes every retry
;   - Q_BLOCKING + blocking_passes=3
;   - missing_information -> evidence-guard (temp=0), never invent facts
;   - persistent_weight_delta_bytes = 0
;   - retry exhaustion -> INSUFFICIENT_INFORMATION (caller), never fake success
;
; Dependencies: kernel32 only via RawrXD_Common.inc (none required for core math)
; Build: ml64 /c /Zi /Fo RawrXD_HexMag_RepeatTuner.obj
; =============================================================================

INCLUDE RawrXD_Common.inc

; =============================================================================
;                         STRATEGY / SPECIALIST / FAILURE ENUMS
; =============================================================================

HX_STRAT_DIRECT             EQU     0
HX_STRAT_DECOMPOSE          EQU     1
HX_STRAT_REVERSE            EQU     2
HX_STRAT_COUNTEREXAMPLE     EQU     3
HX_STRAT_INVARIANT          EQU     4
HX_STRAT_REPAIR             EQU     5
HX_STRAT_EVIDENCE_GUARD     EQU     6

HX_SPEC_GENERALIST          EQU     0
HX_SPEC_PLANNER             EQU     1
HX_SPEC_FALSIFIER           EQU     2
HX_SPEC_BOUNDARY            EQU     3
HX_SPEC_CONSISTENCY         EQU     4
HX_SPEC_RESOLVER            EQU     5
HX_SPEC_ASSUMPTION_BREAKER  EQU     6
HX_SPEC_TEST_DRIVEN         EQU     7
HX_SPEC_ALT_DERIVATION      EQU     8
HX_SPEC_EPISTEMIC           EQU     9

; Failure kind bit flags (OR-able)
HX_FAIL_CONTRADICTION       EQU     0001h
HX_FAIL_COUNTEREXAMPLE      EQU     0002h
HX_FAIL_UNSUPPORTED         EQU     0004h   ; hallucination / assumption
HX_FAIL_TEST                EQU     0008h   ; test/compile/runtime
HX_FAIL_STAGNATION          EQU     0010h   ; duplicate / no improvement
HX_FAIL_MISSING_INFO        EQU     0020h
HX_FAIL_WRONG               EQU     0040h   ; generic verifier wrong

HX_QUEUE_Q_BLOCKING         EQU     1
HX_TUNER_MAX_SEEN           EQU     64
HX_TUNER_BASE_RING          EQU     6
HX_TUNER_OK                 EQU     0
HX_TUNER_ERR_EXHAUSTED      EQU     1
HX_TUNER_ERR_BAD_ARG        EQU     2

; =============================================================================
;                         STRUCTURES
; =============================================================================

; Fixed-point: temp_milli=200 means 0.20; top_p_milli=900 means 0.90
HX_GEN_PROFILE STRUCT
    strategy                DWORD   ?
    specialist              DWORD   ?
    temp_milli               DWORD   ?
    top_p_milli             DWORD   ?
    candidate_count         DWORD   ?
    reverse_depth           DWORD   ?
    counterexample_budget   DWORD   ?
    invariant_budget        DWORD   ?
    blocking_passes         DWORD   ?       ; always 3 on retries
    queue_policy            DWORD   ?       ; HX_QUEUE_Q_BLOCKING
    mutation_nonce          DWORD   ?
    _pad0                   DWORD   ?
HX_GEN_PROFILE ENDS

HX_TUNER_STATE STRUCT
    initialized             DWORD   ?
    max_attempts            DWORD   ?
    seen_count              DWORD   ?
    _pad1                   DWORD   ?
    request_id_hash         QWORD   ?       ; active request
    seen_fps                QWORD   HX_TUNER_MAX_SEEN DUP(?)
    active_profile          HX_GEN_PROFILE <>
    generation_id           QWORD   ?
    attempt                 DWORD   ?
    weight_delta_bytes      DWORD   ?       ; ALWAYS 0
HX_TUNER_STATE ENDS

; =============================================================================
;                         DATA — base ring (6 archetypes)
; =============================================================================
_DATA64 SEGMENT ALIGN(64) 'DATA'

g_Tuner     HX_TUNER_STATE <>

; Packed base ring as DWORD rows: strategy, specialist, temp, topp, cand, rev, cex, inv
; (blocking/queue/nonce filled at use time)
ALIGN 16
g_BaseRing LABEL DWORD
; direct / generalist
    DD HX_STRAT_DIRECT, HX_SPEC_GENERALIST, 200, 900, 1, 1, 1, 1
; decompose / planner
    DD HX_STRAT_DECOMPOSE, HX_SPEC_PLANNER, 300, 920, 2, 1, 1, 2
; reverse / falsifier
    DD HX_STRAT_REVERSE, HX_SPEC_FALSIFIER, 250, 900, 2, 2, 2, 1
; counterexample / boundary
    DD HX_STRAT_COUNTEREXAMPLE, HX_SPEC_BOUNDARY, 400, 940, 3, 2, 4, 1
; invariant / consistency
    DD HX_STRAT_INVARIANT, HX_SPEC_CONSISTENCY, 150, 860, 2, 2, 1, 4
; repair / resolver
    DD HX_STRAT_REPAIR, HX_SPEC_RESOLVER, 280, 900, 3, 3, 3, 3

_DATA64 ENDS

; =============================================================================
;                         EXPORTS
; =============================================================================

PUBLIC HexMag_Tuner_Init
PUBLIC HexMag_Tuner_Reset
PUBLIC HexMag_Tuner_Initial
PUBLIC HexMag_Tuner_Next
PUBLIC HexMag_Tuner_Fingerprint
PUBLIC HexMag_Tuner_GenerationId
PUBLIC HexMag_Tuner_GetProfile
PUBLIC HexMag_Tuner_WeightDelta
PUBLIC HexMag_Tuner_Attempt
PUBLIC HexMag_Tuner_Strategy

; =============================================================================
;                         CODE
; =============================================================================
_TEXT SEGMENT ALIGN(16) 'CODE'

; -----------------------------------------------------------------------------
; hx_fp_mix — mix ECX into RAX (FNV-ish). Clobber: rdx
; -----------------------------------------------------------------------------
hx_fp_mix PROC
    mov     rdx, 100000001B3h
    imul    rax, rdx
    mov     edx, ecx
    xor     rax, rdx
    ret
hx_fp_mix ENDP

; -----------------------------------------------------------------------------
; HexMag_Tuner_Fingerprint — RCX = HX_GEN_PROFILE*
; Returns RAX = 64-bit fingerprint (never all-zero for valid profiles)
; -----------------------------------------------------------------------------
HexMag_Tuner_Fingerprint PROC
    test    rcx, rcx
    jz      @fp_zero
    push    rbx
    mov     rbx, rcx
    mov     eax, 2166136261
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.strategy
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.specialist
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.temp_milli
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.top_p_milli
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.candidate_count
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.reverse_depth
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.counterexample_budget
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.invariant_budget
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.blocking_passes
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.queue_policy
    call    hx_fp_mix
    mov     ecx, DWORD PTR [rbx].HX_GEN_PROFILE.mutation_nonce
    call    hx_fp_mix
    pop     rbx
    ret
@fp_zero:
    xor     eax, eax
    ret
HexMag_Tuner_Fingerprint ENDP

; -----------------------------------------------------------------------------
; hx_load_base — EDX = index 0..5, RDI = dest HX_GEN_PROFILE*
; -----------------------------------------------------------------------------
hx_load_base PROC
    push    rsi
    and     edx, 7
    cmp     edx, HX_TUNER_BASE_RING
    jb      @lb_ok
    xor     edx, edx
@lb_ok:
    lea     rsi, g_BaseRing
    mov     eax, edx
    imul    eax, 32                     ; 8 DWORDs
    add     rsi, rax
    mov     eax, DWORD PTR [rsi]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.strategy, eax
    mov     eax, DWORD PTR [rsi+4]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.specialist, eax
    mov     eax, DWORD PTR [rsi+8]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli, eax
    mov     eax, DWORD PTR [rsi+12]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.top_p_milli, eax
    mov     eax, DWORD PTR [rsi+16]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count, eax
    mov     eax, DWORD PTR [rsi+20]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.reverse_depth, eax
    mov     eax, DWORD PTR [rsi+24]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.counterexample_budget, eax
    mov     eax, DWORD PTR [rsi+28]
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.invariant_budget, eax
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.blocking_passes, 3
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.queue_policy, HX_QUEUE_Q_BLOCKING
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.mutation_nonce, 0
    pop     rsi
    ret
hx_load_base ENDP

; -----------------------------------------------------------------------------
; hx_seen_add — RAX = fingerprint. Returns RAX=0 if newly added, 1 if already seen
; -----------------------------------------------------------------------------
hx_seen_has PROC
    lea     r8, g_Tuner
    mov     ecx, DWORD PTR [r8].HX_TUNER_STATE.seen_count
    xor     edx, edx
@sh_loop:
    cmp     edx, ecx
    jae     @sh_no
    lea     r9, [r8].HX_TUNER_STATE.seen_fps
    cmp     QWORD PTR [r9 + rdx*8], rax
    je      @sh_yes
    inc     edx
    jmp     @sh_loop
@sh_yes:
    mov     eax, 1
    ret
@sh_no:
    xor     eax, eax
    ret
hx_seen_has ENDP

hx_seen_add PROC
    lea     r8, g_Tuner
    mov     ecx, DWORD PTR [r8].HX_TUNER_STATE.seen_count
    cmp     ecx, HX_TUNER_MAX_SEEN
    jae     @sa_done
    lea     r9, [r8].HX_TUNER_STATE.seen_fps
    mov     QWORD PTR [r9 + rcx*8], rax
    inc     DWORD PTR [r8].HX_TUNER_STATE.seen_count
@sa_done:
    ret
hx_seen_add ENDP

; -----------------------------------------------------------------------------
; hx_unique — RDI = profile*; force unique fingerprint via nonce bump
; Returns RAX = HX_TUNER_OK or HX_TUNER_ERR_EXHAUSTED
; -----------------------------------------------------------------------------
hx_unique PROC
    push    rbx
    push    rsi
    mov     ebx, 64
@uq_loop:
    mov     rcx, rdi
    call    HexMag_Tuner_Fingerprint
    mov     rsi, rax
    call    hx_seen_has
    test    eax, eax
    jz      @uq_ok
    ; bump nonce + tiny temp nudge (+10 milli, cap 600)
    inc     DWORD PTR [rdi].HX_GEN_PROFILE.mutation_nonce
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli
    add     eax, 10
    cmp     eax, 600
    jbe     @uq_temp
    mov     eax, 600
@uq_temp:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli, eax
    dec     ebx
    jnz     @uq_loop
    mov     eax, HX_TUNER_ERR_EXHAUSTED
    jmp     @uq_done
@uq_ok:
    mov     rax, rsi
    call    hx_seen_add
    xor     eax, eax
@uq_done:
    pop     rsi
    pop     rbx
    ret
hx_unique ENDP

; -----------------------------------------------------------------------------
; hx_apply_failure — RDI=profile*, ECX=fail_kind_mask
; -----------------------------------------------------------------------------
hx_apply_failure PROC
    test    ecx, HX_FAIL_CONTRADICTION
    jz      @af_cex
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.strategy, HX_STRAT_INVARIANT
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.specialist, HX_SPEC_CONSISTENCY
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli
    cmp     eax, 180
    jbe     @af_inv_t
    mov     eax, 180
@af_inv_t:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.invariant_budget
    cmp     eax, 5
    jae     @af_inv_b
    mov     eax, 5
@af_inv_b:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.invariant_budget, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.reverse_depth
    cmp     eax, 2
    jae     @af_cex
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.reverse_depth, 2

@af_cex:
    test    ecx, HX_FAIL_COUNTEREXAMPLE
    jz      @af_uns
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.strategy, HX_STRAT_COUNTEREXAMPLE
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.specialist, HX_SPEC_BOUNDARY
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count
    cmp     eax, 3
    jae     @af_cex_c
    mov     eax, 3
@af_cex_c:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.counterexample_budget
    cmp     eax, 5
    jae     @af_cex_b
    mov     eax, 5
@af_cex_b:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.counterexample_budget, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.reverse_depth
    cmp     eax, 2
    jae     @af_uns
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.reverse_depth, 2

@af_uns:
    test    ecx, HX_FAIL_UNSUPPORTED
    jz      @af_test
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.strategy, HX_STRAT_REVERSE
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.specialist, HX_SPEC_ASSUMPTION_BREAKER
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli
    cmp     eax, 220
    jbe     @af_uns_t
    mov     eax, 220
@af_uns_t:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.reverse_depth
    cmp     eax, 3
    jae     @af_uns_r
    mov     eax, 3
@af_uns_r:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.reverse_depth, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.invariant_budget
    cmp     eax, 3
    jae     @af_test
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.invariant_budget, 3

@af_test:
    test    ecx, HX_FAIL_TEST
    jz      @af_stag
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.strategy, HX_STRAT_REPAIR
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.specialist, HX_SPEC_TEST_DRIVEN
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli
    cmp     eax, 200
    jbe     @af_test_t
    mov     eax, 200
@af_test_t:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count
    cmp     eax, 3
    jae     @af_test_c
    mov     eax, 3
@af_test_c:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.invariant_budget
    cmp     eax, 4
    jae     @af_stag
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.invariant_budget, 4

@af_stag:
    test    ecx, HX_FAIL_STAGNATION
    jz      @af_miss
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.strategy, HX_STRAT_DECOMPOSE
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.specialist, HX_SPEC_ALT_DERIVATION
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli
    add     eax, 120
    cmp     eax, 320
    jae     @af_stag_t
    mov     eax, 320
@af_stag_t:
    cmp     eax, 550
    jbe     @af_stag_t2
    mov     eax, 550
@af_stag_t2:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.top_p_milli
    cmp     eax, 940
    jae     @af_stag_p
    mov     eax, 940
@af_stag_p:
    cmp     eax, 970
    jbe     @af_stag_p2
    mov     eax, 970
@af_stag_p2:
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.top_p_milli, eax
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count
    cmp     eax, 3
    jae     @af_miss
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count, 3

@af_miss:
    test    ecx, HX_FAIL_MISSING_INFO
    jz      @af_done
    ; evidence-guard: do NOT increase creativity
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.strategy, HX_STRAT_EVIDENCE_GUARD
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.specialist, HX_SPEC_EPISTEMIC
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.temp_milli, 0
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.top_p_milli, 800
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.candidate_count, 1
    mov     eax, DWORD PTR [rdi].HX_GEN_PROFILE.counterexample_budget
    cmp     eax, 2
    jae     @af_done
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.counterexample_budget, 2
@af_done:
    ; Always enforce Q_BLOCKING + 3 passes on repeats
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.blocking_passes, 3
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.queue_policy, HX_QUEUE_Q_BLOCKING
    ret
hx_apply_failure ENDP

; -----------------------------------------------------------------------------
; HexMag_Tuner_Init — ECX = max_attempts (0 => 6)
; -----------------------------------------------------------------------------
HexMag_Tuner_Init PROC
    push    rdi
    mov     edx, ecx                    ; save max_attempts
    lea     rdi, g_Tuner
    mov     rcx, SIZEOF HX_TUNER_STATE
    xor     eax, eax
    rep     stosb
    lea     rax, g_Tuner
    test    edx, edx
    jnz     @ti_max
    mov     edx, 6
@ti_max:
    mov     DWORD PTR [rax].HX_TUNER_STATE.max_attempts, edx
    mov     DWORD PTR [rax].HX_TUNER_STATE.initialized, 1
    mov     DWORD PTR [rax].HX_TUNER_STATE.weight_delta_bytes, 0
    xor     eax, eax
    pop     rdi
    ret
HexMag_Tuner_Init ENDP

; -----------------------------------------------------------------------------
; HexMag_Tuner_Reset — RCX = request_id_hash
; -----------------------------------------------------------------------------
HexMag_Tuner_Reset PROC
    lea     rax, g_Tuner
    mov     QWORD PTR [rax].HX_TUNER_STATE.request_id_hash, rcx
    mov     DWORD PTR [rax].HX_TUNER_STATE.seen_count, 0
    mov     DWORD PTR [rax].HX_TUNER_STATE.attempt, 0
    mov     QWORD PTR [rax].HX_TUNER_STATE.generation_id, 0
    mov     DWORD PTR [rax].HX_TUNER_STATE.weight_delta_bytes, 0
    xor     eax, eax
    ret
HexMag_Tuner_Reset ENDP

; -----------------------------------------------------------------------------
; HexMag_Tuner_Initial — RCX = request_id_hash, RDX = out HX_GEN_PROFILE* (opt)
; Returns RAX = fingerprint; profile stored in g_Tuner.active_profile
; -----------------------------------------------------------------------------
HexMag_Tuner_Initial PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    mov     rbx, rcx                    ; rid
    mov     rsi, rdx                    ; out optional

    call    HexMag_Tuner_Reset          ; rcx still rid

    lea     rdi, g_Tuner
    lea     rdi, [rdi].HX_TUNER_STATE.active_profile
    xor     edx, edx
    call    hx_load_base
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.mutation_nonce, 0

    call    hx_unique
    test    eax, eax
    jnz     @ini_fail

    lea     rax, g_Tuner
    mov     DWORD PTR [rax].HX_TUNER_STATE.attempt, 0
    ; generation_id = mix(rid, attempt, fingerprint)
    mov     rcx, rdi
    call    HexMag_Tuner_Fingerprint
    mov     rcx, rbx
    xor     rax, rcx
    lea     r8, g_Tuner
    mov     QWORD PTR [r8].HX_TUNER_STATE.generation_id, rax

    test    rsi, rsi
    jz      @ini_fp
    ; copy profile to out
    mov     rcx, SIZEOF HX_GEN_PROFILE
    push    rsi
    mov     rdi, rsi
    lea     rsi, g_Tuner
    lea     rsi, [rsi].HX_TUNER_STATE.active_profile
    rep     movsb
    pop     rsi
@ini_fp:
    lea     rcx, g_Tuner
    lea     rcx, [rcx].HX_TUNER_STATE.active_profile
    call    HexMag_Tuner_Fingerprint
    jmp     @ini_done
@ini_fail:
    mov     eax, 0
@ini_done:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
HexMag_Tuner_Initial ENDP

; -----------------------------------------------------------------------------
; HexMag_Tuner_Next
;   RCX = request_id_hash
;   EDX = fail_kind_mask
;   R8D = attempt (1-based typical)
;   R9  = out HX_GEN_PROFILE* (optional)
; Returns RAX = new fingerprint, or 0 on exhausted/error
; -----------------------------------------------------------------------------
HexMag_Tuner_Next PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    mov     rbx, rcx                    ; rid
    mov     r12d, edx                   ; fail mask
    mov     r13d, r8d                   ; attempt
    mov     rsi, r9                     ; out

    lea     rax, g_Tuner
    cmp     DWORD PTR [rax].HX_TUNER_STATE.initialized, 1
    jne     @nx_fail
    mov     ecx, DWORD PTR [rax].HX_TUNER_STATE.max_attempts
    cmp     r13d, ecx
    jae     @nx_fail

    lea     rdi, [rax].HX_TUNER_STATE.active_profile
    ; base = ring[attempt % 6]
    mov     eax, r13d
    xor     edx, edx
    mov     ecx, HX_TUNER_BASE_RING
    div     ecx                         ; edx = remainder
    call    hx_load_base

    ; mutation_nonce = max(attempt, previous_nonce+1) — previous wiped by load; use attempt
    mov     eax, r13d
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.mutation_nonce, eax
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.blocking_passes, 3
    mov     DWORD PTR [rdi].HX_GEN_PROFILE.queue_policy, HX_QUEUE_Q_BLOCKING

    mov     ecx, r12d
    call    hx_apply_failure

    call    hx_unique
    test    eax, eax
    jnz     @nx_fail

    lea     rax, g_Tuner
    mov     DWORD PTR [rax].HX_TUNER_STATE.attempt, r13d
    mov     QWORD PTR [rax].HX_TUNER_STATE.request_id_hash, rbx

    mov     rcx, rdi
    call    HexMag_Tuner_Fingerprint
    mov     rcx, rbx
    xor     rax, rcx
    mov     ecx, r13d
    shl     rcx, 32
    xor     rax, rcx
    lea     r8, g_Tuner
    mov     QWORD PTR [r8].HX_TUNER_STATE.generation_id, rax

    test    rsi, rsi
    jz      @nx_fp
    mov     rcx, SIZEOF HX_GEN_PROFILE
    mov     rdi, rsi
    lea     rsi, g_Tuner
    lea     rsi, [rsi].HX_TUNER_STATE.active_profile
    rep     movsb
@nx_fp:
    lea     rcx, g_Tuner
    lea     rcx, [rcx].HX_TUNER_STATE.active_profile
    call    HexMag_Tuner_Fingerprint
    jmp     @nx_done
@nx_fail:
    xor     eax, eax
@nx_done:
    add     rsp, 20h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
HexMag_Tuner_Next ENDP

; -----------------------------------------------------------------------------
; HexMag_Tuner_GenerationId — RAX = current generation_id qword
; -----------------------------------------------------------------------------
HexMag_Tuner_GenerationId PROC
    lea     rax, g_Tuner
    mov     rax, QWORD PTR [rax].HX_TUNER_STATE.generation_id
    ret
HexMag_Tuner_GenerationId ENDP

; -----------------------------------------------------------------------------
; HexMag_Tuner_GetProfile — RCX = out buffer; copies active profile
; -----------------------------------------------------------------------------
HexMag_Tuner_GetProfile PROC
    push    rsi
    push    rdi
    test    rcx, rcx
    jz      @gp_bad
    mov     rdi, rcx
    lea     rsi, g_Tuner
    lea     rsi, [rsi].HX_TUNER_STATE.active_profile
    mov     rcx, SIZEOF HX_GEN_PROFILE
    rep     movsb
    xor     eax, eax
    pop     rdi
    pop     rsi
    ret
@gp_bad:
    mov     eax, HX_TUNER_ERR_BAD_ARG
    pop     rdi
    pop     rsi
    ret
HexMag_Tuner_GetProfile ENDP

HexMag_Tuner_WeightDelta PROC
    xor     eax, eax                    ; persistent_weight_delta_bytes = 0
    ret
HexMag_Tuner_WeightDelta ENDP

HexMag_Tuner_Attempt PROC
    lea     rax, g_Tuner
    mov     eax, DWORD PTR [rax].HX_TUNER_STATE.attempt
    ret
HexMag_Tuner_Attempt ENDP

HexMag_Tuner_Strategy PROC
    lea     rax, g_Tuner
    mov     eax, DWORD PTR [rax].HX_TUNER_STATE.active_profile.strategy
    ret
HexMag_Tuner_Strategy ENDP

_TEXT ENDS
END
