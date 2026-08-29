; =============================================================================
; RawrXD_HexMag_Swarm.asm — HexMag Control Plane (pure x64 MASM, no Python)
; =============================================================================
;
; Ports the HexMag orchestration semantics out of Python FastAPI into a
; dependency-light MASM64 control plane:
;
;   goal.requested
;     -> architect.plan
;     -> handoff(code_generation)
;     -> codegen.finding
;     -> handoff(verification)
;     -> verification.build/run
;     -> goal.satisfied
;
; HexMag decides WHO (role). Model/backend selection stays outside this module
; (model_policy_router / Deep2 are workers, not the boss).
;
; Dependencies (kernel32 only via RawrXD_Common.inc):
;   VirtualAlloc, VirtualFree, OutputDebugStringA
; NO: Python, FastAPI, ModelBridge, CRT heap beyond what the host already links.
;
; Architecture: x64 MASM64 | Windows x64 ABI (RCX, RDX, R8, R9)
; Build: ml64 /c /Zi /Fo RawrXD_HexMag_Swarm.obj
; =============================================================================

INCLUDE RawrXD_Common.inc

; Polymorphic repeat tuner (separate MASM module, no Python)
EXTERN HexMag_Tuner_Init:PROC
EXTERN HexMag_Tuner_Initial:PROC
EXTERN HexMag_Tuner_Next:PROC
EXTERN HexMag_Tuner_Strategy:PROC
EXTERN HexMag_Tuner_GenerationId:PROC
EXTERN HexMag_Tuner_WeightDelta:PROC

; Failure masks (must match RawrXD_HexMag_RepeatTuner.asm)
HX_FAIL_TEST_MASK           EQU     0008h
HX_FAIL_WRONG_MASK          EQU     0040h
HX_FAIL_UNSUPPORTED_MASK    EQU     0004h

; =============================================================================
;                         CONSTANTS
; =============================================================================

HX_ROLE_ARCHITECT       EQU     0
HX_ROLE_CODEGEN         EQU     1
HX_ROLE_VERIFICATION    EQU     2
HX_ROLE_COUNT           EQU     3

HX_EVT_NONE             EQU     0
HX_EVT_GOAL_REQUESTED   EQU     1
HX_EVT_PARTIAL          EQU     2
HX_EVT_HANDOFF          EQU     3
HX_EVT_ROLE_REQUESTED   EQU     4
HX_EVT_ANSWER           EQU     5
HX_EVT_GOAL_SATISFIED   EQU     6
HX_EVT_FAILED           EQU     7
HX_EVT_CONTACT          EQU     8
HX_EVT_PLAN             EQU     9
HX_EVT_RESPONDER_SPAWN  EQU     10
HX_EVT_ANSWER_CANDIDATE EQU     11
HX_EVT_REVERSE          EQU     12
HX_EVT_CRITIQUE         EQU     13
HX_EVT_NEED_INPUT       EQU     14
HX_EVT_VERIFY           EQU     15
HX_EVT_ANSWER_FINAL     EQU     16
HX_EVT_DEFLATE          EQU     17
HX_EVT_TUNER_ADJUST     EQU     18

HX_OK                   EQU     0
HX_ERR_ALLOC            EQU     1
HX_ERR_NOT_INIT         EQU     2
HX_ERR_ALREADY_INIT     EQU     3
HX_ERR_BAD_ARG          EQU     4
HX_ERR_DEPTH            EQU     5
HX_ERR_REPEAT           EQU     6
HX_ERR_QUEUE_FULL       EQU     7
HX_ERR_IDLE_FAIL        EQU     8
HX_ERR_TIMEOUT          EQU     9

HX_MAX_HANDOFF_DEPTH    EQU     16          ; allow refine loops
HX_MAX_SIGNATURES       EQU     32
HX_MAX_TUNER_ROUNDS     EQU     8
HX_POLY_VARIANTS        EQU     3
HX_EVENT_SIZE           EQU     512
HX_EVENT_CAPACITY       EQU     256
HX_EVENT_RING_BYTES     EQU     512 * 256     ; 128 KB
HX_WORK_CAPACITY        EQU     64
HX_GOAL_BYTES           EQU     1024
HX_CTX_BYTES            EQU     4096

; =============================================================================
;                         STRUCTURES
; =============================================================================

; Fixed-size event / finding record (512 bytes)
HX_EVENT STRUCT
    kind            DWORD   ?           ; HX_EVT_*
    role            DWORD   ?           ; producer or target role
    target_role     DWORD   ?           ; handoff target (if handoff)
    depth           DWORD   ?           ; handoff_depth at emit
    goal_id         QWORD   ?           ; opaque goal id
    payload_len     DWORD   ?           ; bytes used in payload
    _pad0           DWORD   ?           ; align
    payload         DB      480 DUP(?) ; UTF-8 text / stub artifact
HX_EVENT ENDS

; Work-queue item: role to run next
HX_WORK STRUCT
    role            DWORD   ?
    _pad0           DWORD   ?
    goal_id         QWORD   ?
HX_WORK ENDS

; Per-goal agent context (page-sized)
; Polymorphic gen: EVERY spawn mints a brand-new unused agent/model id.
;   agent ids are monotonic and never recycled (process lifetime).
; Repeat tuner: verify fail → bump gain/attempt → mint NEW agent → re-run codegen.
HX_AGENT_CTX STRUCT
    goal_id         QWORD   ?
    handoff_depth   DWORD   ?
    satisfied       DWORD   ?           ; 1 when goal.satisfied emitted
    failed          DWORD   ?
    visited_mask    DWORD   ?           ; bit per role visited
    sig_count       DWORD   ?
    _pad_sig        DWORD   ?           ; align signatures to 8
    signatures      QWORD   HX_MAX_SIGNATURES DUP(?)
    root_goal_len   DWORD   ?
    poly_seed       DWORD   ?           ; goal-conditioned polymorph seed
    tuner_attempt   DWORD   ?           ; generation index (raised on wrong)
    tuner_gain      DWORD   ?           ; raised on wrong answers
    verify_fails    DWORD   ?           ; count of failed verifies
    last_variant    DWORD   ?           ; 0/1=wrong candidate, 2=correct
    active_agent_id QWORD   ?           ; current ephemeral agent/model id
    agents_this_goal DWORD  ?           ; spawns for this goal
    _pad_agents     DWORD   ?
    root_goal       DB      HX_GOAL_BYTES DUP(?)
HX_AGENT_CTX ENDS

; Global swarm state
HX_STATE STRUCT
    initialized     DWORD   ?
    bot_count       DWORD   ?           ; always HX_ROLE_COUNT
    event_base      QWORD   ?           ; VirtualAlloc ring
    event_head      DWORD   ?           ; producer index
    event_tail      DWORD   ?           ; consumer index
    work_count      DWORD   ?           ; pending work items
    work_roles      DWORD   HX_WORK_CAPACITY DUP(?)
    total_handoffs  QWORD   ?
    total_steps     QWORD   ?
    total_goals     QWORD   ?
    ctx             QWORD   ?           ; pointer to HX_AGENT_CTX
    lock_flag       DWORD   ?
    _pad2           DWORD   ?
    next_agent_id   QWORD   ?           ; monotonic; never reused
    agents_spawned  QWORD   ?           ; total fresh agents minted
    last_agent_id   QWORD   ?           ; most recent mint
    parallel_agents DWORD   ?           ; 1..8 multi-candidate swarm width
    _pad_par        DWORD   ?
HX_STATE ENDS

; =============================================================================
;                         DATA
; =============================================================================
_DATA64 SEGMENT ALIGN(64) 'DATA'

g_HxState       HX_STATE <>
g_NextGoalId    QWORD   1

g_MsgHxInit     DB  'HexMag: MASM control plane initialized (polymorphic agents + tuner)', 0
g_MsgHxDown     DB  'HexMag: shutdown complete', 0
g_MsgHxAlloc    DB  'HexMag: ERROR VirtualAlloc failed', 0
g_MsgHxDepth    DB  'HexMag: ERROR max handoff depth', 0
g_MsgHxRepeat   DB  'HexMag: ERROR repeated handoff suppressed', 0

; Scratch for spawn/candidate payloads (NUL-terminated)
g_PayloadBuf    DB  480 DUP(0)

; Stub payloads (NUL-terminated, copied into events)
g_PlanStub      DB  'architect.plan: diagnose -> implement -> verify', 0
g_CodeWrong0    DB  'candidate.impl=sub #WRONG agent=', 0
g_CodeWrong1    DB  'candidate.impl=mul #WRONG agent=', 0
g_CodeOk        DB  'candidate.impl=add #OK agent=', 0
g_SpawnPrefix   DB  'hexmag.responder.spawn unused=1 agent=', 0
g_ModelPrefix   DB  ' model=hx-ephemeral-', 0
g_TunerPrefix   DB  'hexmag.tuner.adjust attempt=', 0
g_CritiqueWrong DB  'hexmag.critique: candidate falsified; minting unused agent', 0
g_ReverseFail   DB  'hexmag.reverse: computational fail', 0
g_VerifyOk      DB  'hexmag.verify: ok', 0
g_BuildStub     DB  'verification.build: ok (stub)', 0
g_RunStub       DB  'verification.run: ok (stub)', 0
g_DoneStub      DB  'goal.satisfied: verified', 0
g_DeflateStub   DB  'hexmag.deflate: responders discarded (ids burned)', 0
g_FinalStub     DB  'llm.answer.final', 0

_DATA64 ENDS

; =============================================================================
;                         EXPORTS
; =============================================================================

PUBLIC HexMag_Init
PUBLIC HexMag_Shutdown
PUBLIC HexMag_GetState
PUBLIC HexMag_SubmitGoal
PUBLIC HexMag_Step
PUBLIC HexMag_PollEvent
PUBLIC HexMag_RunToSatisfied
PUBLIC HexMag_BotCount
PUBLIC HexMag_AgentsSpawned
PUBLIC HexMag_LastAgentId
PUBLIC HexMag_TunerAttempt
PUBLIC HexMag_Feedback
PUBLIC HexMag_IsInitialized
PUBLIC HexMag_SetParallelAgents
PUBLIC HexMag_GetParallelAgents

; =============================================================================
;                         CODE
; =============================================================================
_TEXT SEGMENT ALIGN(16) 'CODE'

; -----------------------------------------------------------------------------
; HexMag_BotCount — RAX = number of built-in roles
; -----------------------------------------------------------------------------
HexMag_BotCount PROC
    mov     eax, HX_ROLE_COUNT
    ret
HexMag_BotCount ENDP

; -----------------------------------------------------------------------------
; HexMag_AgentsSpawned — RAX = total fresh unused agents minted (never reused)
; -----------------------------------------------------------------------------
HexMag_AgentsSpawned PROC
    lea     rax, g_HxState
    mov     rax, QWORD PTR [rax].HX_STATE.agents_spawned
    ret
HexMag_AgentsSpawned ENDP

; -----------------------------------------------------------------------------
; HexMag_LastAgentId — RAX = most recently minted agent/model id
; -----------------------------------------------------------------------------
HexMag_LastAgentId PROC
    lea     rax, g_HxState
    mov     rax, QWORD PTR [rax].HX_STATE.last_agent_id
    ret
HexMag_LastAgentId ENDP

; -----------------------------------------------------------------------------
; HexMag_TunerAttempt — RAX = current goal tuner_attempt
; -----------------------------------------------------------------------------
HexMag_TunerAttempt PROC
    lea     rax, g_HxState
    mov     rax, QWORD PTR [rax].HX_STATE.ctx
    test    rax, rax
    jz      @ta_zero
    mov     eax, DWORD PTR [rax].HX_AGENT_CTX.tuner_attempt
    ret
@ta_zero:
    xor     eax, eax
    ret
HexMag_TunerAttempt ENDP

; -----------------------------------------------------------------------------
; HexMag_GetState — RAX = &g_HxState
; -----------------------------------------------------------------------------
HexMag_GetState PROC
    lea     rax, g_HxState
    ret
HexMag_GetState ENDP

; -----------------------------------------------------------------------------
; HexMag_Init
; Returns: RAX = HX_OK | error
; -----------------------------------------------------------------------------
HexMag_Init PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    lea     rbx, g_HxState
    cmp     DWORD PTR [rbx].HX_STATE.initialized, 1
    je      @init_already

    ; Zero state
    mov     rdi, rbx
    mov     rcx, SIZEOF HX_STATE
    xor     eax, eax
    rep     stosb

    ; Allocate event ring
    mov     rcx, 0                      ; lpAddress
    mov     rdx, HX_EVENT_RING_BYTES
    mov     r8d, MEM_COMMIT OR MEM_RESERVE
    mov     r9d, PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      @init_alloc_fail
    mov     QWORD PTR [rbx].HX_STATE.event_base, rax

    ; Allocate agent context
    mov     rcx, 0
    mov     rdx, HX_CTX_BYTES
    mov     r8d, MEM_COMMIT OR MEM_RESERVE
    mov     r9d, PAGE_READWRITE
    call    VirtualAlloc
    test    rax, rax
    jz      @init_alloc_fail2
    mov     QWORD PTR [rbx].HX_STATE.ctx, rax

    mov     rdi, rax
    mov     rcx, HX_CTX_BYTES
    xor     eax, eax
    rep     stosb

    mov     DWORD PTR [rbx].HX_STATE.initialized, 1
    mov     DWORD PTR [rbx].HX_STATE.bot_count, HX_ROLE_COUNT
    mov     QWORD PTR [rbx].HX_STATE.next_agent_id, 1   ; first unused id
    mov     QWORD PTR [rbx].HX_STATE.agents_spawned, 0
    mov     QWORD PTR [rbx].HX_STATE.last_agent_id, 0
    mov     DWORD PTR [rbx].HX_STATE.parallel_agents, 3 ; default multi-agent

    lea     rcx, g_MsgHxInit
    call    OutputDebugStringA

    xor     eax, eax                    ; HX_OK
    jmp     @init_done

@init_already:
    mov     eax, HX_ERR_ALREADY_INIT
    jmp     @init_done

@init_alloc_fail2:
    mov     rcx, QWORD PTR [rbx].HX_STATE.event_base
    mov     rdx, 0
    mov     r8d, MEM_RELEASE
    call    VirtualFree
    mov     QWORD PTR [rbx].HX_STATE.event_base, 0
@init_alloc_fail:
    lea     rcx, g_MsgHxAlloc
    call    OutputDebugStringA
    mov     eax, HX_ERR_ALLOC

@init_done:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
HexMag_Init ENDP

; -----------------------------------------------------------------------------
; HexMag_Shutdown
; -----------------------------------------------------------------------------
HexMag_Shutdown PROC FRAME
    push    rbx
    .pushreg rbx
    push    rdi
    .pushreg rdi
    sub     rsp, 28h
    .allocstack 28h
    .endprolog

    lea     rbx, g_HxState
    cmp     DWORD PTR [rbx].HX_STATE.initialized, 1
    jne     @shut_ok

    mov     rcx, QWORD PTR [rbx].HX_STATE.event_base
    test    rcx, rcx
    jz      @shut_ctx
    mov     rdx, 0
    mov     r8d, MEM_RELEASE
    call    VirtualFree

@shut_ctx:
    mov     rcx, QWORD PTR [rbx].HX_STATE.ctx
    test    rcx, rcx
    jz      @shut_zero
    mov     rdx, 0
    mov     r8d, MEM_RELEASE
    call    VirtualFree

@shut_zero:
    mov     rdi, rbx
    mov     rcx, SIZEOF HX_STATE
    xor     eax, eax
    rep     stosb

    lea     rcx, g_MsgHxDown
    call    OutputDebugStringA

@shut_ok:
    xor     eax, eax
    add     rsp, 28h
    pop     rdi
    pop     rbx
    ret
HexMag_Shutdown ENDP

; -----------------------------------------------------------------------------
; hx_emit_event — internal
; RCX = kind, EDX = role, R8D = target_role, R9 = payload ptr (or 0)
; Uses g_HxState.ctx for goal_id/depth. Clobbers rax,r10,r11.
; Returns RAX = 0 OK, or HX_ERR_QUEUE_FULL
; -----------------------------------------------------------------------------
hx_emit_event PROC FRAME
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

    mov     r12d, ecx                   ; kind
    mov     r13d, edx                   ; role
    ; r8d = target, r9 = payload

    lea     rbx, g_HxState
    mov     eax, DWORD PTR [rbx].HX_STATE.event_head
    mov     edx, DWORD PTR [rbx].HX_STATE.event_tail
    inc     eax
    and     eax, HX_EVENT_CAPACITY - 1
    cmp     eax, edx
    je      @emit_full

    mov     esi, DWORD PTR [rbx].HX_STATE.event_head
    mov     rdi, QWORD PTR [rbx].HX_STATE.event_base
    mov     eax, esi
    imul    rax, HX_EVENT_SIZE
    add     rdi, rax                    ; rdi -> HX_EVENT slot

    ; zero slot
    push    rcx
    push    rdi
    mov     rcx, HX_EVENT_SIZE
    xor     eax, eax
    rep     stosb
    pop     rdi
    pop     rcx

    mov     DWORD PTR [rdi].HX_EVENT.kind, r12d
    mov     DWORD PTR [rdi].HX_EVENT.role, r13d
    mov     DWORD PTR [rdi].HX_EVENT.target_role, r8d

    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    mov     ecx, DWORD PTR [rax].HX_AGENT_CTX.handoff_depth
    mov     DWORD PTR [rdi].HX_EVENT.depth, ecx
    mov     rcx, QWORD PTR [rax].HX_AGENT_CTX.goal_id
    mov     QWORD PTR [rdi].HX_EVENT.goal_id, rcx

    ; copy payload if present
    test    r9, r9
    jz      @emit_advance
    lea     rsi, [rdi].HX_EVENT.payload
    mov     rcx, 479                    ; max copy
@emit_copy:
    mov     al, BYTE PTR [r9]
    mov     BYTE PTR [rsi], al
    test    al, al
    jz      @emit_len
    inc     r9
    inc     rsi
    dec     rcx
    jnz     @emit_copy
    mov     BYTE PTR [rsi], 0
@emit_len:
    lea     rax, [rdi].HX_EVENT.payload
    ; length = rsi - payload (approx via 479-rcx) — store simple strlen
    lea     rsi, [rdi].HX_EVENT.payload
    xor     ecx, ecx
@emit_strlen:
    cmp     BYTE PTR [rsi + rcx], 0
    je      @emit_store_len
    inc     ecx
    cmp     ecx, 480
    jb      @emit_strlen
@emit_store_len:
    mov     DWORD PTR [rdi].HX_EVENT.payload_len, ecx

@emit_advance:
    mov     eax, DWORD PTR [rbx].HX_STATE.event_head
    inc     eax
    and     eax, HX_EVENT_CAPACITY - 1
    mov     DWORD PTR [rbx].HX_STATE.event_head, eax
    xor     eax, eax
    jmp     @emit_done

@emit_full:
    mov     eax, HX_ERR_QUEUE_FULL

@emit_done:
    add     rsp, 20h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
hx_emit_event ENDP

; -----------------------------------------------------------------------------
; hx_enqueue_role — EDX = role
; -----------------------------------------------------------------------------
hx_enqueue_role PROC
    lea     rax, g_HxState
    mov     ecx, DWORD PTR [rax].HX_STATE.work_count
    cmp     ecx, HX_WORK_CAPACITY
    jae     @enq_full
    lea     r8, [rax].HX_STATE.work_roles
    mov     DWORD PTR [r8 + rcx*4], edx
    inc     DWORD PTR [rax].HX_STATE.work_count
    xor     eax, eax
    ret
@enq_full:
    mov     eax, HX_ERR_QUEUE_FULL
    ret
hx_enqueue_role ENDP

; -----------------------------------------------------------------------------
; hx_hash_sig — RCX = remaining goal ptr, EDX = target role
; Returns RAX = signature qword
; -----------------------------------------------------------------------------
hx_hash_sig PROC
    mov     r8, rcx
    mov     eax, edx
    xor     r9d, r9d
    test    r8, r8
    jz      @hash_done
@hash_loop:
    movzx   ecx, BYTE PTR [r8]
    test    ecx, ecx
    jz      @hash_done
    ; FNV-ish mix
    imul    eax, eax, 01000193h
    xor     eax, ecx
    rol     r9d, 5
    xor     r9d, ecx
    inc     r8
    jmp     @hash_loop
@hash_done:
    shl     r9, 32
    or      rax, r9
    ret
hx_hash_sig ENDP

; -----------------------------------------------------------------------------
; hx_try_handoff — EDX = target_role, R8 = reason payload ptr
; Returns RAX = HX_OK or error
; -----------------------------------------------------------------------------
hx_try_handoff PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    mov     esi, edx                    ; target role
    mov     rdi, r8                     ; payload

    lea     rbx, g_HxState
    mov     rax, QWORD PTR [rbx].HX_STATE.ctx

    cmp     DWORD PTR [rax].HX_AGENT_CTX.handoff_depth, HX_MAX_HANDOFF_DEPTH
    jae     @ho_depth

    ; signature = hash(root_goal, target_role) XOR (tuner_attempt<<17)
    ; so refine loops are not HX_ERR_REPEAT
    lea     rcx, [rax].HX_AGENT_CTX.root_goal
    mov     edx, esi
    call    hx_hash_sig
    mov     r10, QWORD PTR [rbx].HX_STATE.ctx
    mov     ecx, DWORD PTR [r10].HX_AGENT_CTX.tuner_attempt
    shl     rcx, 17
    xor     rax, rcx
    ; check against signatures
    mov     ecx, DWORD PTR [r10].HX_AGENT_CTX.sig_count
    xor     r11d, r11d
@ho_check:
    cmp     r11d, ecx
    jae     @ho_ok_sig
    lea     r8, [r10].HX_AGENT_CTX.signatures
    cmp     QWORD PTR [r8 + r11*8], rax
    je      @ho_repeat
    inc     r11d
    jmp     @ho_check

@ho_ok_sig:
    ; store signature
    cmp     ecx, HX_MAX_SIGNATURES
    jae     @ho_repeat
    lea     r8, [r10].HX_AGENT_CTX.signatures
    mov     QWORD PTR [r8 + rcx*8], rax
    inc     DWORD PTR [r10].HX_AGENT_CTX.sig_count
    inc     DWORD PTR [r10].HX_AGENT_CTX.handoff_depth

    ; visited mask
    mov     eax, 1
    mov     ecx, esi
    shl     eax, cl
    or      DWORD PTR [r10].HX_AGENT_CTX.visited_mask, eax

    lock inc QWORD PTR [rbx].HX_STATE.total_handoffs

    ; emit handoff event (producer role = previous implied by visited)
    mov     ecx, HX_EVT_HANDOFF
    mov     edx, DWORD PTR [r10].HX_AGENT_CTX.visited_mask ; rough
    ; Better: set role to architect/codegen based on target-1
    xor     edx, edx
    cmp     esi, HX_ROLE_CODEGEN
    jne     @ho_role_from
    mov     edx, HX_ROLE_ARCHITECT
    jmp     @ho_emit
@ho_role_from:
    cmp     esi, HX_ROLE_VERIFICATION
    jne     @ho_emit
    mov     edx, HX_ROLE_CODEGEN
@ho_emit:
    mov     r8d, esi
    mov     r9, rdi
    call    hx_emit_event

    ; enqueue target role + role.requested event
    mov     ecx, HX_EVT_ROLE_REQUESTED
    mov     edx, esi
    mov     r8d, esi
    mov     r9, rdi
    call    hx_emit_event

    mov     edx, esi
    call    hx_enqueue_role

    xor     eax, eax
    jmp     @ho_done

@ho_depth:
    lea     rcx, g_MsgHxDepth
    call    OutputDebugStringA
    mov     eax, HX_ERR_DEPTH
    jmp     @ho_done
@ho_repeat:
    lea     rcx, g_MsgHxRepeat
    call    OutputDebugStringA
    mov     eax, HX_ERR_REPEAT
@ho_done:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
hx_try_handoff ENDP

; -----------------------------------------------------------------------------
; hx_append_u64 — append decimal of RAX into buffer RSI; RSI advanced past digits
; Clobbers: rax,rcx,rdx,r8
; -----------------------------------------------------------------------------
hx_append_u64 PROC
    push    rbx
    push    rdi
    sub     rsp, 40h
    mov     rbx, rax
    lea     rdi, [rsp + 20h]
    xor     ecx, ecx
    test    rbx, rbx
    jnz     @au_loop
    mov     BYTE PTR [rsi], '0'
    inc     rsi
    jmp     @au_done
@au_loop:
    test    rbx, rbx
    jz      @au_emit
    xor     rdx, rdx
    mov     rax, rbx
    mov     r8, 10
    div     r8
    mov     rbx, rax
    add     dl, '0'
    mov     BYTE PTR [rdi + rcx], dl
    inc     ecx
    jmp     @au_loop
@au_emit:
    dec     ecx
@au_emit_loop:
    cmp     ecx, 0
    jl      @au_done
    mov     al, BYTE PTR [rdi + rcx]
    mov     BYTE PTR [rsi], al
    inc     rsi
    dec     ecx
    jmp     @au_emit_loop
@au_done:
    add     rsp, 40h
    pop     rdi
    pop     rbx
    ret
hx_append_u64 ENDP

; -----------------------------------------------------------------------------
; hx_strcpy_z — copy R9 NUL-string to RSI; RSI advanced to terminator; clobber al
; -----------------------------------------------------------------------------
hx_strcpy_z PROC
@sc_loop:
    mov     al, BYTE PTR [r9]
    mov     BYTE PTR [rsi], al
    test    al, al
    jz      @sc_done
    inc     r9
    inc     rsi
    jmp     @sc_loop
@sc_done:
    ret
hx_strcpy_z ENDP

; -----------------------------------------------------------------------------
; hx_mint_unused_agent — mint brand-new never-used agent/model id
; EDX = role for spawn event. Returns RAX = agent_id. Emits RESPONDER_SPAWN.
; -----------------------------------------------------------------------------
hx_mint_unused_agent PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    sub     rsp, 28h
    .allocstack 28h
    .endprolog

    mov     r12d, edx                   ; role
    lea     rbx, g_HxState

    ; agent_id = next_agent_id++  (never reuse)
    mov     rax, QWORD PTR [rbx].HX_STATE.next_agent_id
    mov     rdi, rax                    ; saved id
    inc     rax
    mov     QWORD PTR [rbx].HX_STATE.next_agent_id, rax
    mov     QWORD PTR [rbx].HX_STATE.last_agent_id, rdi
    lock inc QWORD PTR [rbx].HX_STATE.agents_spawned

    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    mov     QWORD PTR [rax].HX_AGENT_CTX.active_agent_id, rdi
    inc     DWORD PTR [rax].HX_AGENT_CTX.agents_this_goal

    ; Build payload: "hexmag.responder.spawn unused=1 agent=N model=hx-ephemeral-N"
    lea     rsi, g_PayloadBuf
    lea     r9, g_SpawnPrefix
    call    hx_strcpy_z
    ; rsi at NUL — overwrite NUL and append id
    mov     rax, rdi
    call    hx_append_u64
    lea     r9, g_ModelPrefix
    call    hx_strcpy_z
    mov     rax, rdi
    call    hx_append_u64
    mov     BYTE PTR [rsi], 0

    mov     ecx, HX_EVT_RESPONDER_SPAWN
    mov     edx, r12d
    xor     r8d, r8d
    lea     r9, g_PayloadBuf
    call    hx_emit_event

    mov     rax, rdi
    add     rsp, 28h
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
hx_mint_unused_agent ENDP

; -----------------------------------------------------------------------------
; hx_build_candidate — fill g_PayloadBuf from last_variant + active agent
; Variants 0,1 = WRONG (forces tuner); 2+ = OK hello-world MASM candidate
; -----------------------------------------------------------------------------
hx_build_candidate PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    lea     rbx, g_HxState
    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    mov     ecx, DWORD PTR [rax].HX_AGENT_CTX.last_variant
    mov     rdi, QWORD PTR [rax].HX_AGENT_CTX.active_agent_id

    lea     rsi, g_PayloadBuf
    cmp     ecx, 0
    je      @bc_w0
    cmp     ecx, 1
    je      @bc_w1
    lea     r9, g_CodeOk
    jmp     @bc_copy
@bc_w0:
    lea     r9, g_CodeWrong0
    jmp     @bc_copy
@bc_w1:
    lea     r9, g_CodeWrong1
@bc_copy:
    push    rcx
    call    hx_strcpy_z
    mov     rax, rdi
    call    hx_append_u64
    pop     rcx
    cmp     ecx, 2
    jb      @bc_term
    mov     BYTE PTR [rsi], ' '
    mov     BYTE PTR [rsi+1], ';'
    mov     BYTE PTR [rsi+2], ' '
    mov     BYTE PTR [rsi+3], 'H'
    mov     BYTE PTR [rsi+4], 'e'
    mov     BYTE PTR [rsi+5], 'l'
    mov     BYTE PTR [rsi+6], 'l'
    mov     BYTE PTR [rsi+7], 'o'
    mov     BYTE PTR [rsi+8], 'W'
    mov     BYTE PTR [rsi+9], 'o'
    mov     BYTE PTR [rsi+10], 'r'
    mov     BYTE PTR [rsi+11], 'l'
    mov     BYTE PTR [rsi+12], 'd'
    mov     BYTE PTR [rsi+13], ' '
    mov     BYTE PTR [rsi+14], 'x'
    mov     BYTE PTR [rsi+15], '6'
    mov     BYTE PTR [rsi+16], '4'
    add     rsi, 17
@bc_term:
    mov     BYTE PTR [rsi], 0

    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
hx_build_candidate ENDP

; -----------------------------------------------------------------------------
; hx_tuner_bump — on wrong answer: raise attempt/gain, mint NEW unused agent
; Returns RAX = 1 if should re-run codegen, 0 if exhausted
; -----------------------------------------------------------------------------
hx_tuner_bump PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    r12
    .pushreg r12
    sub     rsp, 28h
    .allocstack 28h
    .endprolog

    lea     rbx, g_HxState
    mov     rsi, QWORD PTR [rbx].HX_STATE.ctx

    inc     DWORD PTR [rsi].HX_AGENT_CTX.verify_fails
    inc     DWORD PTR [rsi].HX_AGENT_CTX.tuner_attempt
    mov     eax, DWORD PTR [rsi].HX_AGENT_CTX.tuner_gain
    inc     eax
    add     eax, DWORD PTR [rsi].HX_AGENT_CTX.verify_fails
    mov     DWORD PTR [rsi].HX_AGENT_CTX.tuner_gain, eax

    cmp     DWORD PTR [rsi].HX_AGENT_CTX.tuner_attempt, HX_MAX_TUNER_ROUNDS
    jae     @tb_exhausted

    ; Failure-directed genome mutation (MASM RepeatTuner — never same profile)
    mov     ecx, DWORD PTR [rsi].HX_AGENT_CTX.poly_seed
    mov     r12, rcx                    ; request_id_hash
    mov     edx, HX_FAIL_TEST_MASK OR HX_FAIL_WRONG_MASK
    mov     r8d, DWORD PTR [rsi].HX_AGENT_CTX.tuner_attempt
    xor     r9, r9                      ; no out buffer
    call    HexMag_Tuner_Next
    test    rax, rax
    jz      @tb_exhausted

    ; payload: hexmag.tuner.adjust attempt=N
    lea     rsi, g_PayloadBuf
    lea     r9, g_TunerPrefix
    call    hx_strcpy_z
    lea     rax, g_HxState
    mov     rax, QWORD PTR [rax].HX_STATE.ctx
    mov     eax, DWORD PTR [rax].HX_AGENT_CTX.tuner_attempt
    call    hx_append_u64
    mov     BYTE PTR [rsi], 0

    mov     ecx, HX_EVT_TUNER_ADJUST
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_PayloadBuf
    call    hx_emit_event

    ; Mint happens in hx_run_codegen — do not double-mint here
    mov     edx, HX_ROLE_CODEGEN
    call    hx_enqueue_role

    mov     eax, 1
    jmp     @tb_done
@tb_exhausted:
    xor     eax, eax
@tb_done:
    add     rsp, 28h
    pop     r12
    pop     rsi
    pop     rbx
    ret
hx_tuner_bump ENDP

; -----------------------------------------------------------------------------
; Role handlers
; -----------------------------------------------------------------------------
hx_run_architect PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    ; Contact + plan + fresh architect agent
    mov     ecx, HX_EVT_CONTACT
    mov     edx, HX_ROLE_ARCHITECT
    xor     r8d, r8d
    lea     r9, g_PlanStub
    call    hx_emit_event

    mov     edx, HX_ROLE_ARCHITECT
    call    hx_mint_unused_agent

    mov     ecx, HX_EVT_PLAN
    mov     edx, HX_ROLE_ARCHITECT
    xor     r8d, r8d
    lea     r9, g_PlanStub
    call    hx_emit_event

    mov     ecx, HX_EVT_PARTIAL
    mov     edx, HX_ROLE_ARCHITECT
    xor     r8d, r8d
    lea     r9, g_PlanStub
    call    hx_emit_event

    mov     edx, HX_ROLE_CODEGEN
    lea     r8, g_PlanStub
    call    hx_try_handoff

    add     rsp, 20h
    pop     rbx
    ret
hx_run_architect ENDP

hx_run_codegen PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    sub     rsp, 28h
    .allocstack 28h
    .endprolog

    lea     rbx, g_HxState
    mov     rsi, QWORD PTR [rbx].HX_STATE.ctx

    ; parallel_agents = swarm width (Cursor-style multi-response)
    mov     r13d, DWORD PTR [rbx].HX_STATE.parallel_agents
    cmp     r13d, 1
    jae     @cg_have_n
    mov     r13d, 1
@cg_have_n:
    cmp     r13d, 8
    jbe     @cg_n_ok
    mov     r13d, 8
@cg_n_ok:

    xor     r12d, r12d                  ; any_ok flag
    xor     r14d, r14d                  ; candidate index

@cg_multi:
    mov     edx, HX_ROLE_CODEGEN
    call    hx_mint_unused_agent

    ; Variant: tuner_attempt>=2 => OK for all; else wrong cycling 0/1 by index
    mov     eax, DWORD PTR [rsi].HX_AGENT_CTX.tuner_attempt
    cmp     eax, 2
    jae     @cg_var_ok
    mov     eax, r14d
    and     eax, 1
    mov     DWORD PTR [rsi].HX_AGENT_CTX.last_variant, eax
    jmp     @cg_emit
@cg_var_ok:
    mov     DWORD PTR [rsi].HX_AGENT_CTX.last_variant, 2
    mov     r12d, 1
@cg_emit:
    call    hx_build_candidate

    mov     ecx, HX_EVT_PARTIAL
    mov     edx, HX_ROLE_CODEGEN
    xor     r8d, r8d
    lea     r9, g_PayloadBuf
    call    hx_emit_event

    mov     ecx, HX_EVT_ANSWER_CANDIDATE
    mov     edx, HX_ROLE_CODEGEN
    xor     r8d, r8d
    lea     r9, g_PayloadBuf
    call    hx_emit_event

    mov     ecx, HX_EVT_ANSWER
    mov     edx, HX_ROLE_CODEGEN
    xor     r8d, r8d
    lea     r9, g_PayloadBuf
    call    hx_emit_event

    inc     r14d
    cmp     r14d, r13d
    jb      @cg_multi

    ; Verify uses last_variant: mark OK if any candidate in batch was OK
    test    r12d, r12d
    jz      @cg_handoff
    mov     DWORD PTR [rsi].HX_AGENT_CTX.last_variant, 2

@cg_handoff:
    mov     edx, HX_ROLE_VERIFICATION
    lea     r8, g_PayloadBuf
    call    hx_try_handoff
    test    eax, eax
    jz      @cg_done
    cmp     eax, HX_ERR_REPEAT
    jne     @cg_done
    mov     edx, HX_ROLE_VERIFICATION
    call    hx_enqueue_role

@cg_done:
    add     rsp, 28h
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rbx
    ret
hx_run_codegen ENDP

hx_run_verification PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 28h
    .allocstack 28h
    .endprolog

    lea     rbx, g_HxState
    mov     rsi, QWORD PTR [rbx].HX_STATE.ctx

    mov     ecx, HX_EVT_REVERSE
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_ReverseFail
    ; If variant OK, reverse will be overwritten path below
    mov     eax, DWORD PTR [rsi].HX_AGENT_CTX.last_variant
    cmp     eax, 2
    jb      @vr_fail_path

    ; --- PASS path ---
    lea     r9, g_VerifyOk
    mov     ecx, HX_EVT_VERIFY
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    call    hx_emit_event

    mov     ecx, HX_EVT_PARTIAL
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_BuildStub
    call    hx_emit_event

    mov     ecx, HX_EVT_PARTIAL
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_RunStub
    call    hx_emit_event

    mov     ecx, HX_EVT_ANSWER_FINAL
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_FinalStub
    call    hx_emit_event

    mov     ecx, HX_EVT_GOAL_SATISFIED
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_DoneStub
    call    hx_emit_event

    mov     ecx, HX_EVT_DEFLATE
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_DeflateStub
    call    hx_emit_event

    mov     DWORD PTR [rsi].HX_AGENT_CTX.satisfied, 1
    jmp     @vr_done

@vr_fail_path:
    ; reverse + critique
    mov     ecx, HX_EVT_REVERSE
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_ReverseFail
    call    hx_emit_event

    mov     ecx, HX_EVT_CRITIQUE
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_CritiqueWrong
    call    hx_emit_event

    call    hx_tuner_bump
    test    eax, eax
    jnz     @vr_done

    ; Exhausted tuner rounds
    mov     ecx, HX_EVT_FAILED
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_CritiqueWrong
    call    hx_emit_event
    mov     DWORD PTR [rsi].HX_AGENT_CTX.failed, 1

@vr_done:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
hx_run_verification ENDP

; -----------------------------------------------------------------------------
; HexMag_SubmitGoal
; RCX = goal ptr (UTF-8), EDX = length (or 0 => strlen)
; Returns RAX = goal_id (nonzero) or 0 on error; RDX = error code if fail
; -----------------------------------------------------------------------------
HexMag_SubmitGoal PROC FRAME
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

    lea     rbx, g_HxState
    cmp     DWORD PTR [rbx].HX_STATE.initialized, 1
    jne     @sg_not_init
    test    rcx, rcx
    jz      @sg_bad

    mov     r12, rcx                    ; goal ptr
    mov     r13d, edx                   ; len
    test    r13d, r13d
    jnz     @sg_have_len
    xor     r13d, r13d
@sg_strlen:
    cmp     BYTE PTR [r12 + r13], 0
    je      @sg_have_len
    inc     r13d
    cmp     r13d, HX_GOAL_BYTES - 1
    jb      @sg_strlen

@sg_have_len:
    cmp     r13d, HX_GOAL_BYTES
    jb      @sg_len_ok
    mov     r13d, HX_GOAL_BYTES - 1
@sg_len_ok:

    mov     rdi, QWORD PTR [rbx].HX_STATE.ctx
    mov     rcx, HX_CTX_BYTES
    xor     eax, eax
    rep     stosb

    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    lock inc QWORD PTR g_NextGoalId
    mov     rcx, QWORD PTR g_NextGoalId
    mov     QWORD PTR [rax].HX_AGENT_CTX.goal_id, rcx
    mov     DWORD PTR [rax].HX_AGENT_CTX.root_goal_len, r13d

    lea     rdi, [rax].HX_AGENT_CTX.root_goal
    mov     rsi, r12
    mov     ecx, r13d
    rep     movsb
    mov     BYTE PTR [rdi], 0

    ; poly_seed from goal bytes (FNV-ish)
    lea     rsi, [rax].HX_AGENT_CTX.root_goal
    mov     ecx, 2166136261
@sg_poly:
    movzx   edx, BYTE PTR [rsi]
    test    edx, edx
    jz      @sg_poly_done
    imul    ecx, ecx, 16777619
    xor     ecx, edx
    inc     rsi
    jmp     @sg_poly
@sg_poly_done:
    mov     DWORD PTR [rax].HX_AGENT_CTX.poly_seed, ecx
    ; tuner starts at 0 → first candidates intentionally wrong until adjust
    mov     DWORD PTR [rax].HX_AGENT_CTX.tuner_attempt, 0
    mov     DWORD PTR [rax].HX_AGENT_CTX.tuner_gain, 0

    ; Request-local polymorphic genome (MASM RepeatTuner)
    push    rax
    mov     r12d, ecx                   ; poly_seed as request hash
    mov     ecx, HX_MAX_TUNER_ROUNDS
    call    HexMag_Tuner_Init
    mov     ecx, r12d
    xor     edx, edx
    call    HexMag_Tuner_Initial
    pop     rax

    lock inc QWORD PTR [rbx].HX_STATE.total_goals
    mov     DWORD PTR [rbx].HX_STATE.work_count, 0
    mov     DWORD PTR [rbx].HX_STATE.event_head, 0
    mov     DWORD PTR [rbx].HX_STATE.event_tail, 0

    mov     ecx, HX_EVT_GOAL_REQUESTED
    xor     edx, edx
    xor     r8d, r8d
    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    lea     r9, [rax].HX_AGENT_CTX.root_goal
    call    hx_emit_event

    mov     edx, HX_ROLE_ARCHITECT
    call    hx_enqueue_role

    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    mov     rax, QWORD PTR [rax].HX_AGENT_CTX.goal_id
    xor     edx, edx
    jmp     @sg_done

@sg_not_init:
    xor     eax, eax
    mov     edx, HX_ERR_NOT_INIT
    jmp     @sg_done
@sg_bad:
    xor     eax, eax
    mov     edx, HX_ERR_BAD_ARG
@sg_done:
    add     rsp, 20h
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
HexMag_SubmitGoal ENDP

; -----------------------------------------------------------------------------
; HexMag_Step — process one work item
; Returns RAX = event kind last emitted-ish, or HX_EVT_NONE if idle,
;         or HX_EVT_GOAL_SATISFIED / FAILED codes as status
; -----------------------------------------------------------------------------
HexMag_Step PROC FRAME
    push    rbx
    .pushreg rbx
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    lea     rbx, g_HxState
    cmp     DWORD PTR [rbx].HX_STATE.initialized, 1
    jne     @st_not_init

    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    cmp     DWORD PTR [rax].HX_AGENT_CTX.satisfied, 1
    je      @st_satisfied

    mov     ecx, DWORD PTR [rbx].HX_STATE.work_count
    test    ecx, ecx
    jz      @st_idle

    ; pop front
    lea     r9, [rbx].HX_STATE.work_roles
    mov     edx, DWORD PTR [r9]         ; role 0
    dec     ecx
    mov     DWORD PTR [rbx].HX_STATE.work_count, ecx
    xor     r8d, r8d
@st_shift:
    cmp     r8d, ecx
    jae     @st_run
    mov     eax, DWORD PTR [r9 + r8*4 + 4]
    mov     DWORD PTR [r9 + r8*4], eax
    inc     r8d
    jmp     @st_shift

@st_run:
    lock inc QWORD PTR [rbx].HX_STATE.total_steps
    cmp     edx, HX_ROLE_ARCHITECT
    je      @st_arch
    cmp     edx, HX_ROLE_CODEGEN
    je      @st_code
    cmp     edx, HX_ROLE_VERIFICATION
    je      @st_ver
    mov     eax, HX_EVT_FAILED
    jmp     @st_done

@st_arch:
    call    hx_run_architect
    mov     eax, HX_EVT_HANDOFF
    jmp     @st_done
@st_code:
    call    hx_run_codegen
    mov     eax, HX_EVT_HANDOFF
    jmp     @st_done
@st_ver:
    call    hx_run_verification
    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    cmp     DWORD PTR [rax].HX_AGENT_CTX.satisfied, 1
    je      @st_ver_ok
    cmp     DWORD PTR [rax].HX_AGENT_CTX.failed, 1
    je      @st_ver_fail
    mov     eax, HX_EVT_CRITIQUE       ; refine in progress
    jmp     @st_done
@st_ver_ok:
    mov     eax, HX_EVT_GOAL_SATISFIED
    jmp     @st_done
@st_ver_fail:
    mov     eax, HX_EVT_FAILED
    jmp     @st_done

@st_satisfied:
    mov     eax, HX_EVT_GOAL_SATISFIED
    jmp     @st_done
@st_idle:
    xor     eax, eax
    jmp     @st_done
@st_not_init:
    mov     eax, HX_EVT_FAILED
@st_done:
    add     rsp, 20h
    pop     rbx
    ret
HexMag_Step ENDP

; -----------------------------------------------------------------------------
; HexMag_PollEvent — RCX = pointer to HX_EVENT out buffer (512 bytes)
; Returns RAX = 1 if event copied, 0 if empty
; -----------------------------------------------------------------------------
HexMag_PollEvent PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    lea     rbx, g_HxState
    cmp     DWORD PTR [rbx].HX_STATE.initialized, 1
    jne     @pe_empty
    test    rcx, rcx
    jz      @pe_empty

    mov     eax, DWORD PTR [rbx].HX_STATE.event_tail
    cmp     eax, DWORD PTR [rbx].HX_STATE.event_head
    je      @pe_empty

    mov     rdi, rcx                    ; dest
    mov     rsi, QWORD PTR [rbx].HX_STATE.event_base
    mov     eax, DWORD PTR [rbx].HX_STATE.event_tail
    imul    rax, HX_EVENT_SIZE
    add     rsi, rax
    mov     rcx, HX_EVENT_SIZE
    rep     movsb

    mov     eax, DWORD PTR [rbx].HX_STATE.event_tail
    inc     eax
    and     eax, HX_EVENT_CAPACITY - 1
    mov     DWORD PTR [rbx].HX_STATE.event_tail, eax
    mov     eax, 1
    jmp     @pe_done

@pe_empty:
    xor     eax, eax
@pe_done:
    add     rsp, 20h
    pop     rdi
    pop     rsi
    pop     rbx
    ret
HexMag_PollEvent ENDP

; -----------------------------------------------------------------------------
; HexMag_RunToSatisfied — ECX = max steps
; Returns RAX = HX_OK if satisfied, else error
; -----------------------------------------------------------------------------
HexMag_RunToSatisfied PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 28h
    .allocstack 28h
    .endprolog

    mov     esi, ecx                    ; max steps
    lea     rbx, g_HxState
    cmp     DWORD PTR [rbx].HX_STATE.initialized, 1
    jne     @rts_not_init

@rts_loop:
    test    esi, esi
    jz      @rts_timeout
    dec     esi
    call    HexMag_Step
    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    cmp     DWORD PTR [rax].HX_AGENT_CTX.satisfied, 1
    je      @rts_ok
    cmp     eax, HX_EVT_NONE            ; HexMag_Step return in eax already overwritten
    ; re-check work
    cmp     DWORD PTR [rbx].HX_STATE.work_count, 0
    jne     @rts_loop
    mov     rax, QWORD PTR [rbx].HX_STATE.ctx
    cmp     DWORD PTR [rax].HX_AGENT_CTX.satisfied, 1
    je      @rts_ok
    mov     eax, HX_ERR_IDLE_FAIL
    jmp     @rts_done

@rts_ok:
    xor     eax, eax
    jmp     @rts_done
@rts_timeout:
    mov     eax, HX_ERR_TIMEOUT
    jmp     @rts_done
@rts_not_init:
    mov     eax, HX_ERR_NOT_INIT
@rts_done:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
HexMag_RunToSatisfied ENDP

; -----------------------------------------------------------------------------
; HexMag_IsInitialized — RAX = 1 if control plane up
; -----------------------------------------------------------------------------
HexMag_IsInitialized PROC
    lea     rax, g_HxState
    mov     eax, DWORD PTR [rax].HX_STATE.initialized
    ret
HexMag_IsInitialized ENDP

; -----------------------------------------------------------------------------
; HexMag_Feedback — external verifier / user / IDE signal
;   ECX = 0 => correct (finalize if candidate pending)
;   ECX = fail_kind_mask (nonzero) => mutate genome + re-spawn codegen
; Returns RAX = 1 if refine scheduled, 2 if finalized, 0 exhausted/error
; -----------------------------------------------------------------------------
HexMag_Feedback PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    sub     rsp, 28h
    .allocstack 28h
    .endprolog

    lea     rbx, g_HxState
    cmp     DWORD PTR [rbx].HX_STATE.initialized, 1
    jne     @fb_err
    mov     rsi, QWORD PTR [rbx].HX_STATE.ctx
    test    rsi, rsi
    jz      @fb_err

    test    ecx, ecx
    jnz     @fb_wrong

    ; correct — promote to final if not already
    cmp     DWORD PTR [rsi].HX_AGENT_CTX.satisfied, 1
    je      @fb_done_ok
    mov     ecx, HX_EVT_ANSWER_FINAL
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_FinalStub
    call    hx_emit_event
    mov     ecx, HX_EVT_GOAL_SATISFIED
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_DoneStub
    call    hx_emit_event
    mov     ecx, HX_EVT_DEFLATE
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_DeflateStub
    call    hx_emit_event
    mov     DWORD PTR [rsi].HX_AGENT_CTX.satisfied, 1
@fb_done_ok:
    mov     eax, 2
    jmp     @fb_done

@fb_wrong:
    ; Force candidate as wrong for tuner path
    mov     DWORD PTR [rsi].HX_AGENT_CTX.last_variant, 0
    call    hx_tuner_bump
    test    eax, eax
    jz      @fb_exhausted
    mov     eax, 1
    jmp     @fb_done
@fb_exhausted:
    mov     ecx, HX_EVT_FAILED
    mov     edx, HX_ROLE_VERIFICATION
    xor     r8d, r8d
    lea     r9, g_CritiqueWrong
    call    hx_emit_event
    mov     DWORD PTR [rsi].HX_AGENT_CTX.failed, 1
    xor     eax, eax
    jmp     @fb_done
@fb_err:
    xor     eax, eax
@fb_done:
    add     rsp, 28h
    pop     rsi
    pop     rbx
    ret
HexMag_Feedback ENDP

; -----------------------------------------------------------------------------
; HexMag_SetParallelAgents — ECX = count (clamped 1..8). Cursor-style swarm width.
; Returns RAX = applied count
; -----------------------------------------------------------------------------
HexMag_SetParallelAgents PROC
    lea     rax, g_HxState
    mov     edx, ecx
    cmp     edx, 1
    jae     @spa_lo
    mov     edx, 1
@spa_lo:
    cmp     edx, 8
    jbe     @spa_hi
    mov     edx, 8
@spa_hi:
    mov     DWORD PTR [rax].HX_STATE.parallel_agents, edx
    mov     eax, edx
    ret
HexMag_SetParallelAgents ENDP

; -----------------------------------------------------------------------------
; HexMag_GetParallelAgents — RAX = current swarm width
; -----------------------------------------------------------------------------
HexMag_GetParallelAgents PROC
    lea     rax, g_HxState
    mov     eax, DWORD PTR [rax].HX_STATE.parallel_agents
    test    eax, eax
    jnz     @gpa_ok
    mov     eax, 1
@gpa_ok:
    ret
HexMag_GetParallelAgents ENDP

_TEXT ENDS
END
