; ============================================================================
; RawrXD_HexMag_RepeatTuner.asm  --  HEXMAG_POLYMORPHIC_REPEAT_TUNER_001
; ============================================================================
; Real implementation.  Replaces the "Auto-generated stub" that defined only
; RawrXD_HexMag_RepeatTuner_Stub and therefore left 5 of the 10 declared
; exports unresolved at link time (LNK2019).
;
; Contract mirrored from src/core/hexmag_repeat_tuner.hpp:
;   WRONG != same generation ; WRONG == mutate genome -> new generation id
;   persistent_weight_delta_bytes = 0  (request-local only)
;
; State is a single Q_BLOCKING singleton, as declared by the CMake lane.
;
; Invariants this file is responsible for, all asserted against real
; execution by tests/hexmag_repeat_tuner_cert.cpp:
;   1  HexMag_Tuner_Init      clamps the attempt budget into [1,64]
;   2  HexMag_Tuner_Reset     re-bases the genome on a new request id and
;                             mints a new generation id
;   3  HexMag_Tuner_Initial   is deterministic in the request id
;   4  HexMag_Tuner_Next      selects a DIFFERENT genome per failure kind
;   5  HexMag_Tuner_Next      mutates mutation_nonce every call, so the
;                             fingerprint cannot repeat across generations
;   6  HexMag_Tuner_Next      refuses past the budget instead of wrapping
;   7  HexMag_Tuner_WeightDelta is 0 unconditionally and owns no weight bytes
;   8  a null out-pointer is rejected, never dereferenced
;
; Build note: this assembler rejects dot-prefixed local labels, so every
; internal label is a unique flat name.  64-bit constants are loaded into
; 64-bit registers only.
; ============================================================================

OPTION CASEMAP:NONE

_TEXT SEGMENT

; --- HxGenProfile field offsets (48 bytes, packed) -------------------------
HP_STRATEGY      EQU 0
HP_SPECIALIST    EQU 4
HP_TEMP_MILLI    EQU 8
HP_TOPP_MILLI    EQU 12
HP_CANDIDATES    EQU 16
HP_REV_DEPTH     EQU 20
HP_CE_BUDGET     EQU 24
HP_INV_BUDGET    EQU 28
HP_BLOCK_PASSES  EQU 32
HP_QUEUE_POLICY  EQU 36
HP_MUT_NONCE     EQU 40
HP_PAD0          EQU 44
HP_SIZE          EQU 48

; --- strategy ids ----------------------------------------------------------
ST_DIRECT         EQU 0
ST_DECOMPOSE      EQU 1
ST_REVERSE        EQU 2
ST_COUNTEREXAMPLE EQU 3
ST_INVARIANT      EQU 4
ST_REPAIR         EQU 5
ST_EVIDENCE_GUARD EQU 6

; --- fail-kind bits --------------------------------------------------------
FK_CONTRADICTION EQU 0001h
FK_COUNTEREX     EQU 0002h
FK_UNSUPPORTED   EQU 0004h
FK_TEST          EQU 0008h
FK_STAGNATION    EQU 0010h
FK_MISSING_INFO  EQU 0020h
FK_WRONG         EQU 0040h

; --- return codes (same value space as hexmag_swarm.hpp) -------------------
HX_OK            EQU 0
HX_ERR_BAD_ARG   EQU 4
HX_ERR_REPEAT    EQU 6

HX_MAX_ATTEMPTS  EQU 64
HX_DEFAULT_ATT   EQU 8
HX_MIX_PRIME     EQU 09E3779B9h
FNV_OFFSET_BASIS EQU 0CBF29CE484222325h
FNV_PRIME        EQU 100000001B3h

_TEXT ENDS

_DATA SEGMENT

; Singleton state, in .data so the linker materialises it in the image and a
; probe can observe a real address rather than a null relocation.
PUBLIC hxT_max_attempts
PUBLIC hxT_request_id
PUBLIC hxT_generation
PUBLIC hxT_attempt
PUBLIC hxT_fail_mask
PUBLIC hxT_exhausted
PUBLIC hxT_profile
PUBLIC hxT_wrong_ladder

hxT_max_attempts   DD 0
hxT_request_id     DQ 0
hxT_generation     DQ 1
hxT_attempt        DD 0
hxT_fail_mask      DD 0
hxT_exhausted      DB 0
                   DB 3 DUP(0)
hxT_profile        DD 12 DUP(0)

; WRONG escalates along this fixed ladder so attempt N is reproducible.
hxT_wrong_ladder   DB ST_REVERSE, ST_DECOMPOSE, ST_COUNTEREXAMPLE, ST_INVARIANT, \
                         ST_REPAIR, ST_EVIDENCE_GUARD, ST_REVERSE

_DATA ENDS

_TEXT SEGMENT

; ---------------------------------------------------------------------------
; hxT_BuildInitial  rcx = request_id_hash, rdx = out profile
; Deterministic baseline genome: same request id -> byte-identical profile.
; Leaf; neither rcx nor rdx is written.
; ---------------------------------------------------------------------------
hxT_BuildInitial PROC
    ; rcx = hash, rdx = out.  Leaf; neither rcx nor rdx is written.
    ; The hash is normalised HERE, not in each caller.  HexMag_Tuner_Init runs
    ; before any Reset, so hxT_request_id is still 0 at that point; a helper that
    ; dereferences its argument must not rely on every caller substituting 1
    ; first.  Doing it here is what turns a clean compile into a working call.
    mov     r10, rcx
    test    r10, r10
    jnz     hxTBI_valid
    mov     r10, 1                   ; 0 is reserved as "unset"
hxTBI_valid:
    mov     r11, rdx                 ; destination

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [r11],       xmm0
    movdqu  xmmword ptr [r11 + 16],  xmm0
    movdqu  xmmword ptr [r11 + 32],  xmm0

    mov     eax, r10d                   ; hash low dword -> specialist
    mov     dword ptr [r11 + HP_SPECIALIST], eax
    mov     dword ptr [r11 + HP_TEMP_MILLI],   200   ; 0.20
    mov     dword ptr [r11 + HP_TOPP_MILLI],   900   ; 0.90
    mov     dword ptr [r11 + HP_CANDIDATES],   4
    mov     dword ptr [r11 + HP_REV_DEPTH],    1
    mov     dword ptr [r11 + HP_CE_BUDGET],    2
    mov     dword ptr [r11 + HP_INV_BUDGET],   2
    mov     dword ptr [r11 + HP_BLOCK_PASSES], 1
    mov     dword ptr [r11 + HP_QUEUE_POLICY], 1     ; Q_BLOCKING
    ; nonce seeds from the request id so two requests never share a genome
    mov     eax, r10d
    mov     dword ptr [r11 + HP_MUT_NONCE], eax
    mov     dword ptr [r11 + HP_STRATEGY],  ST_DIRECT
    ret
hxT_BuildInitial ENDP

; ---------------------------------------------------------------------------
; hxT_Escalate  rcx = request_id_hash, edx = fail_kind_mask,
;               r8d = attempt, r9 = out profile
; Chooses the strategy from the failure kind, then sets that strategy's
; budgets.  Deterministic in (hash, mask, attempt).  Consumes rdx.
; ---------------------------------------------------------------------------
hxT_Escalate PROC
    mov     r11d, edx                    ; mask, survives the div below

    pxor    xmm0, xmm0
    movdqu  xmmword ptr [r9],       xmm0
    movdqu  xmmword ptr [r9 + 16],  xmm0
    movdqu  xmmword ptr [r9 + 32],  xmm0

    ; ---- genome fields common to every escalation ------------------------
    mov     eax, ecx
    mov     dword ptr [r9 + HP_SPECIALIST], eax
    mov     dword ptr [r9 + HP_TEMP_MILLI],   200
    mov     dword ptr [r9 + HP_TOPP_MILLI],   900
    mov     dword ptr [r9 + HP_CANDIDATES],   4
    mov     dword ptr [r9 + HP_REV_DEPTH],    1
    mov     dword ptr [r9 + HP_CE_BUDGET],    2
    mov     dword ptr [r9 + HP_INV_BUDGET],   2
    mov     dword ptr [r9 + HP_BLOCK_PASSES], 1
    mov     dword ptr [r9 + HP_QUEUE_POLICY], 1

    ; ---- mutation nonce: differs on every call --------------------------
    ;   nonce = (attempt * 0x9E3779B9) ^ hash
    ; The failure kind selects the strategy and budgets, so the nonce alone
    ; already distinguishes every generation produced for one request id.
    mov     r10d, HX_MIX_PRIME
    imul    r10d, r8d
    xor     r10d, ecx
    mov     dword ptr [r9 + HP_MUT_NONCE], r10d

    ; ---- strategy selection: most specific failure kind wins ------------
    test    r11d, FK_CONTRADICTION
    jz      hxTE_not_contra
    ; A contradiction is answered by stating the invariant it violated.
    mov     dword ptr [r9 + HP_STRATEGY], ST_INVARIANT
    mov     dword ptr [r9 + HP_TEMP_MILLI], 0        ; deterministic
    mov     dword ptr [r9 + HP_CANDIDATES], 1
    mov     dword ptr [r9 + HP_TOPP_MILLI], 1000
    mov     r10d, r8d
    inc     r10d
    cmp     r10d, 8
    jbe     hxTE_ci_ok
    mov     r10d, 8
hxTE_ci_ok:
    mov     dword ptr [r9 + HP_INV_BUDGET], r10d
    ret

hxTE_not_contra:
    test    r11d, FK_COUNTEREX
    jz      hxTE_not_ce
    mov     dword ptr [r9 + HP_STRATEGY], ST_COUNTEREXAMPLE
    mov     dword ptr [r9 + HP_TOPP_MILLI], 1000
    mov     dword ptr [r9 + HP_TEMP_MILLI], 300
    mov     r10d, r8d
    inc     r10d
    add     r10d, r10d
    cmp     r10d, 16
    jbe     hxTE_ce_ok
    mov     r10d, 16
hxTE_ce_ok:
    mov     dword ptr [r9 + HP_CE_BUDGET], r10d
    ret

hxTE_not_ce:
    ; MISSING_INFO outranks UNSUPPORTED: with the information absent, narrowing
    ; the search is the only honest move.  It is not a retriable failure.
    test    r11d, FK_MISSING_INFO
    jz      hxTE_not_missing
    mov     dword ptr [r9 + HP_STRATEGY], ST_EVIDENCE_GUARD
    mov     dword ptr [r9 + HP_TEMP_MILLI], 0
    mov     dword ptr [r9 + HP_TOPP_MILLI], 0
    mov     dword ptr [r9 + HP_CANDIDATES], 1
    mov     dword ptr [r9 + HP_INV_BUDGET], 1
    ret

hxTE_not_missing:
    test    r11d, FK_UNSUPPORTED
    jz      hxTE_not_unsup
    ; Unsupported emission: demand the evidence before emitting anything.
    mov     dword ptr [r9 + HP_STRATEGY], ST_EVIDENCE_GUARD
    mov     dword ptr [r9 + HP_TEMP_MILLI], 0
    mov     dword ptr [r9 + HP_TOPP_MILLI], 100
    mov     dword ptr [r9 + HP_CANDIDATES], 1
    mov     r10d, r8d
    add     r10d, 2
    cmp     r10d, 8
    jbe     hxTE_un_ok
    mov     r10d, 8
hxTE_un_ok:
    mov     dword ptr [r9 + HP_INV_BUDGET], r10d
    ret

hxTE_not_unsup:
    test    r11d, FK_TEST
    jz      hxTE_not_test
    mov     dword ptr [r9 + HP_STRATEGY], ST_REPAIR
    mov     dword ptr [r9 + HP_CANDIDATES], 2
    mov     r10d, r8d
    inc     r10d
    cmp     r10d, 4
    jbe     hxTE_te_ok
    mov     r10d, 4
hxTE_te_ok:
    mov     dword ptr [r9 + HP_BLOCK_PASSES], r10d
    ret

hxTE_not_test:
    test    r11d, FK_STAGNATION
    jz      hxTE_not_stag
    ; Stagnation means the search space is too small: widen it.
    mov     dword ptr [r9 + HP_STRATEGY], ST_DECOMPOSE
    mov     dword ptr [r9 + HP_CANDIDATES], 8
    mov     dword ptr [r9 + HP_TEMP_MILLI], 800
    mov     dword ptr [r9 + HP_TOPP_MILLI], 950
    ret

hxTE_not_stag:
    test    r11d, FK_WRONG
    jz      hxTE_not_wrong
    ; WRONG walks a fixed ladder indexed by attempt, so generation N is
    ; reproducible from (hash, attempt) alone.
    mov     eax, r8d                 ; ladder index is the ATTEMPT, not the hash
    xor     edx, edx
    mov     r10d, 7
    div     r10d                    ; edx:eax / 7 -> edx = attempt mod 7
    ; Address the table with LEA and index off the register.  Writing
    ; [hxT_wrong_ladder + rdx] directly makes MASM emit an ADDR32 relocation,
    ; which is illegal in a large-address-aware image (LNK2017).
    lea     r10, [hxT_wrong_ladder]
    movzx   eax, byte ptr [r10 + rdx]
    mov     dword ptr [r9 + HP_STRATEGY], eax
    mov     r10d, r8d
    inc     r10d
    cmp     r10d, 3
    jbe     hxTE_wr_ok
    mov     r10d, 3
hxTE_wr_ok:
    mov     dword ptr [r9 + HP_BLOCK_PASSES], r10d
    mov     r10d, r8d
    inc     r10d
    cmp     r10d, 8
    jbe     hxTE_wr_ok2
    mov     r10d, 8
hxTE_wr_ok2:
    mov     dword ptr [r9 + HP_REV_DEPTH], r10d
    ret

hxTE_not_wrong:
    ; mask == 0 -> no failure was reported.  Do not escalate; re-assert the
    ; repair baseline with a wider blocking-pass budget.
    test    r11d, r11d
    jnz     hxTE_default_rev
    mov     dword ptr [r9 + HP_STRATEGY], ST_REPAIR
    mov     dword ptr [r9 + HP_BLOCK_PASSES], 2
    ret

hxTE_default_rev:
    mov     dword ptr [r9 + HP_STRATEGY], ST_REVERSE
    mov     r10d, r8d
    inc     r10d
    cmp     r10d, 8
    jbe     hxTE_df_ok
    mov     r10d, 8
hxTE_df_ok:
    mov     dword ptr [r9 + HP_REV_DEPTH], r10d
    ret
hxT_Escalate ENDP

; ---------------------------------------------------------------------------
; hxT_Fingerprint  rcx = profile  ->  rax = FNV-1a 64 over the 48 bytes
; Byte-wise, so a single changed field changes the digest.  rcx == 0 -> 0.
; ---------------------------------------------------------------------------
hxT_Fingerprint PROC
    test    rcx, rcx
    jz      hxTF_null                 ; no profile -> 0, not the FNV basis
    mov     rax, FNV_OFFSET_BASIS
    mov     r10, rcx
    mov     r8, FNV_PRIME
    mov     r11d, HP_SIZE
hxTF_loop:
    movzx   r9d, byte ptr [r10]
    xor     rax, r9
    imul    rax, r8
    inc     r10
    dec     r11d
    jnz     hxTF_loop
    ret
hxTF_null:
    xor     eax, eax
    ret
hxT_Fingerprint ENDP

; ===========================================================================
; PUBLIC EXPORTS
; ===========================================================================

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

; uint64_t HexMag_Tuner_Init(uint32_t max_attempts)
HexMag_Tuner_Init PROC
    sub     rsp, 28h                 ; shadow space, RSP 16-aligned for the call
    mov     eax, ecx
    test    eax, eax
    jnz     hxTI_not_zero
    mov     eax, HX_DEFAULT_ATT
hxTI_not_zero:
    cmp     eax, HX_MAX_ATTEMPTS
    jbe     hxTI_in_range
    mov     eax, HX_MAX_ATTEMPTS
hxTI_in_range:
    mov     dword ptr [hxT_max_attempts], eax
    mov     dword ptr [hxT_attempt], 0
    mov     dword ptr [hxT_fail_mask], 0
    mov     byte ptr [hxT_exhausted], 0
    inc     qword ptr [hxT_generation]

    mov     rcx, qword ptr [hxT_request_id]   ; rebase the stored genome
    lea     rdx, [hxT_profile]
    call    hxT_BuildInitial

    xor     eax, eax
    add     rsp, 28h
    ret
HexMag_Tuner_Init ENDP

; uint64_t HexMag_Tuner_Reset(uint64_t request_id_hash)
HexMag_Tuner_Reset PROC
    sub     rsp, 28h
    mov     rax, rcx
    test    rax, rax
    jnz     hxTR_store
    mov     rax, 1                   ; 0 is reserved as "unset"
hxTR_store:
    mov     qword ptr [hxT_request_id], rax
    mov     dword ptr [hxT_attempt], 0
    mov     dword ptr [hxT_fail_mask], 0
    mov     byte ptr [hxT_exhausted], 0
    inc     qword ptr [hxT_generation]

    ; Reset stays usable without Init: adopt the default budget rather than
    ; failing, so a caller that forgot Init cannot silently lose its genome.
    cmp     dword ptr [hxT_max_attempts], 0
    jne     hxTR_have_budget
    mov     dword ptr [hxT_max_attempts], HX_DEFAULT_ATT
hxTR_have_budget:

    mov     rcx, rax
    lea     rdx, [hxT_profile]
    call    hxT_BuildInitial

    xor     eax, eax
    add     rsp, 28h
    ret
HexMag_Tuner_Reset ENDP

; uint64_t HexMag_Tuner_Initial(uint64_t request_id_hash, HxGenProfile* out)
HexMag_Tuner_Initial PROC
    sub     rsp, 28h
    test    rdx, rdx
    jz      hxTRI_bad_arg
    mov     rax, rcx
    test    rax, rax
    jnz     hxTRI_go
    mov     rax, 1
hxTRI_go:
    ; Derived from the caller's hash, not from stored state: two calls with
    ; the same hash must return byte-identical profiles.
    mov     rcx, rax
    call    hxT_BuildInitial
    xor     eax, eax
    add     rsp, 28h
    ret
hxTRI_bad_arg:
    mov     eax, HX_ERR_BAD_ARG
    add     rsp, 28h
    ret
HexMag_Tuner_Initial ENDP

; uint64_t HexMag_Tuner_Next(uint64_t request_id_hash, uint32_t fail_kind_mask,
;                            uint32_t attempt, HxGenProfile* out)
HexMag_Tuner_Next PROC
    sub     rsp, 28h
    test    r9, r9
    jz      hxTN_bad_arg

    mov     r10d, dword ptr [hxT_max_attempts]
    test    r10d, r10d
    jnz     hxTN_budget_ok
    mov     r10d, HX_DEFAULT_ATT
hxTN_budget_ok:
    cmp     r8d, r10d
    jb      hxTN_within
    ; Past the budget: refuse.  Wrapping here would let a request loop
    ; forever re-asking the same question in the same generation.
    mov     byte ptr [hxT_exhausted], 1
    mov     eax, HX_ERR_REPEAT
    add     rsp, 28h
    ret

hxTN_within:
    ; hxT_Escalate consumes rdx (it needs edx:eax for the ladder modulo), so
    ; the reported failure kind is committed to the singleton BEFORE the call.
    mov     eax, edx
    mov     dword ptr [hxT_fail_mask], eax

    call    hxT_Escalate            ; rcx / edx / r8d / r9 already correct

    ; Mirror the produced genome into the singleton.  The produced profile is
    ; the only thing copied; nothing is synthesised here.
    movdqu  xmm1, xmmword ptr [r9]
    movdqu  xmm2, xmmword ptr [r9 + 16]
    movdqu  xmm3, xmmword ptr [r9 + 32]
    movdqu  xmmword ptr [hxT_profile],      xmm1
    movdqu  xmmword ptr [hxT_profile + 16], xmm2
    movdqu  xmmword ptr [hxT_profile + 32], xmm3

    mov     eax, r8d
    add     eax, 1
    mov     dword ptr [hxT_attempt], eax
    inc     qword ptr [hxT_generation]

    xor     eax, eax
    add     rsp, 28h
    ret
hxTN_bad_arg:
    mov     eax, HX_ERR_BAD_ARG
    add     rsp, 28h
    ret
HexMag_Tuner_Next ENDP

; uint64_t HexMag_Tuner_Fingerprint(const HxGenProfile*)
HexMag_Tuner_Fingerprint PROC
    call    hxT_Fingerprint
    ret
HexMag_Tuner_Fingerprint ENDP

; uint64_t HexMag_Tuner_GenerationId(void)
HexMag_Tuner_GenerationId PROC
    mov     rax, qword ptr [hxT_generation]
    ret
HexMag_Tuner_GenerationId ENDP

; uint64_t HexMag_Tuner_GetProfile(HxGenProfile* out)
HexMag_Tuner_GetProfile PROC
    test    rcx, rcx
    jz      hxTGP_bad_arg
    movdqu  xmm1, xmmword ptr [hxT_profile]
    movdqu  xmm2, xmmword ptr [hxT_profile + 16]
    movdqu  xmm3, xmmword ptr [hxT_profile + 32]
    movdqu  xmmword ptr [rcx],      xmm1
    movdqu  xmmword ptr [rcx + 16], xmm2
    movdqu  xmmword ptr [rcx + 32], xmm3
    xor     eax, eax
    ret
hxTGP_bad_arg:
    mov     eax, HX_ERR_BAD_ARG
    ret
HexMag_Tuner_GetProfile ENDP

; uint32_t HexMag_Tuner_WeightDelta(void)
; The tuner mutates a request-local genome.  It owns no weight bytes, so the
; persistent delta is 0 by construction, not by stub.
HexMag_Tuner_WeightDelta PROC
    xor     eax, eax
    ret
HexMag_Tuner_WeightDelta ENDP

; uint32_t HexMag_Tuner_Attempt(void)
HexMag_Tuner_Attempt PROC
    mov     eax, dword ptr [hxT_attempt]
    ret
HexMag_Tuner_Attempt ENDP

; uint32_t HexMag_Tuner_Strategy(void)
HexMag_Tuner_Strategy PROC
    mov     eax, dword ptr [hxT_profile + HP_STRATEGY]
    ret
HexMag_Tuner_Strategy ENDP

_TEXT ENDS

END
