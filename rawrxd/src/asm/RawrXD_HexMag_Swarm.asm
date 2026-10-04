; ============================================================================
; RawrXD_HexMag_Swarm.asm  --  HEXMAG_CONTROL_PLANE_001
; ============================================================================
; Real implementation.  Replaces the "Auto-generated stub" that defined only
; RawrXD_HexMag_Swarm_Stub, which is why every HexMag_* call in
; src/core/hexmag_control_plane.cpp and src/core/hexmag_runtime_controller.cpp
; was an unresolved external at link time.
;
; Layouts mirrored from src/core/hexmag_swarm.hpp:
;   HxEvent  512 bytes : kind@0 role@4 target_role@8 depth@12
;                        goal_id@16 payload_len@24 _pad0@28 payload@32[480]
;   15 exports, Win64 ABI.
;
; ---------------------------------------------------------------------------
; FAIL-CLOSED CONTRACT -- why this file does not simply emit ANSWER_FINAL /
; GOAL_SATISFIED when the search completes:
;   core/hexmag_control_plane.cpp::claimFromSwarmAnswer() treats an answer
;   containing "goal.satisfied" (or "#OK", or "llm.answer.final") as verifier
;   evidence and marks the claim Verified.  A swarm that emitted that payload
;   on its own would certify itself with no evidence at all -- the exact
;   self-certifying-gate defect this repository has retracted three times.
;   Therefore the machine reaches SATISFIED only after an external
;   verification grant arrives through HexMag_Feedback(0).  With no grant it
;   halts at VERIFY and HexMag_RunToSatisfied returns a failure code.
;   This MASM backend is a sequencing/transport layer.  Truth is owned by
;   core/hexmag_finalize_policy.hpp on the C++ side.
;
; Invariants asserted against real execution by
; tests/hexmag_ide_e2e_cert.cpp:
;   1  Init -> SubmitGoal -> RunToSatisfied WITHOUT a grant fails closed
;   2  the same run WITH HexMag_Feedback(0) reaches GOAL_SATISFIED
;   3  PollEvent returns 0 once the queue is drained and never fabricates one
;   4  every emitted event's payload_len agrees with its NUL-terminated payload
;   5  agent ids minted for one goal are pairwise distinct
;   6  SetParallelAgents clamps to [1,8] and reports the EFFECTIVE value
;   7  double Init returns HX_ERR_ALREADY_INIT instead of resetting
;   8  a second goal while one is in flight is refused, not silently replaced
;
; Build note: this assembler rejects dot-prefixed local labels, so every
; internal label is a unique flat name.
; ============================================================================

OPTION CASEMAP:NONE

; The swarm reports the tuner's live attempt counter, so the two cannot drift.
; Every target that links this file also links RawrXD_HexMag_RepeatTuner.asm.
EXTERNDEF HexMag_Tuner_Attempt:PROC

_TEXT SEGMENT

; --- HxEvent field offsets (512 bytes total) -------------------------------
EV_KIND        EQU 0
EV_ROLE        EQU 4
EV_TARGET_ROLE EQU 8
EV_DEPTH       EQU 12
EV_GOAL_ID     EQU 16
EV_PAYLOAD_LEN EQU 24
EV_PAYLOAD     EQU 32
EV_SIZE        EQU 512

; --- control block field offsets (hxS_block, 80 bytes) ---------------------
BL_INITIALIZED    EQU 0
BL_PARALLEL       EQU 4
BL_BOT_COUNT      EQU 8
BL_GRANT          EQU 12
BL_STAGE          EQU 16
BL_STEP_COUNT     EQU 20
BL_SATISFIED      EQU 24
BL_EVENT_COUNT    EQU 28
BL_QUEUE_FULL     EQU 32
BL_RESERVED0      EQU 36
BL_AGENTS_SPAWNED EQU 40
BL_GOAL_ID        EQU 48
BL_LAST_AGENT_ID  EQU 56
BL_GOAL_LEN       EQU 64
BL_FINALIZED      EQU 68
BL_RESERVED1      EQU 72
BL_SIZE           EQU 80

; --- pipeline stages -------------------------------------------------------
STG_IDLE       EQU 0
STG_REQUESTED  EQU 1
STG_PLANNED    EQU 2
STG_SPAWNED    EQU 3
STG_CANDIDATES EQU 4
STG_VERIFY     EQU 5
STG_SATISFIED  EQU 6

; --- event kinds (must match hexmag_swarm.hpp) -----------------------------
EVT_GOAL_REQUESTED   EQU 1
EVT_GOAL_SATISFIED   EQU 6
EVT_ROLE_REQUESTED   EQU 4
EVT_PLAN             EQU 9
EVT_RESPONDER_SPAWN  EQU 10
EVT_ANSWER_CANDIDATE EQU 11
EVT_VERIFY           EQU 15
EVT_ANSWER_FINAL     EQU 16

ROLE_ARCHITECT EQU 0

; --- return codes (hexmag_swarm.hpp) --------------------------------------
HX_OK               EQU 0
HX_ERR_NOT_INIT     EQU 2
HX_ERR_ALREADY_INIT EQU 3
HX_ERR_BAD_ARG      EQU 4
HX_ERR_REPEAT       EQU 6
HX_ERR_QUEUE_FULL   EQU 7
HX_ERR_IDLE_FAIL    EQU 8
HX_ERR_TIMEOUT      EQU 9

HX_EVENT_CAPACITY EQU 256
HX_EVENT_MASK     EQU 255
HX_GOAL_BYTES     EQU 1024
HX_PAYLOAD_BYTES  EQU 480
HX_CANDIDATES     EQU 4
HX_MIN_PARALLEL   EQU 1
HX_MAX_PARALLEL   EQU 8
HX_FNV_PRIME      EQU 100000001B3h
HX_SPLITMIX_ADD   EQU 0E1F0A5EDh
FNV_OFFSET_BASIS  EQU 0CBF29CE484222325h

_TEXT ENDS

_DATA SEGMENT

; ---------------------------------------------------------------------------
; Control block: the single source of truth.  Every exported accessor reads
; these fields, so no value exists in two places and can disagree with itself.
; ---------------------------------------------------------------------------
PUBLIC hxS_block
PUBLIC hxS_goal_text
PUBLIC hxS_event_queue
PUBLIC hxS_event_head
PUBLIC hxS_event_tail
PUBLIC hxS_scratch

hxS_block:
    DB BL_SIZE DUP(0)

hxS_goal_text     DB HX_GOAL_BYTES DUP(0)

; 256 * 512 = 131072 bytes, written out literally so the extent is auditable
; from the source text rather than inferred from a repeat count.
hxS_event_queue   DB 131072 DUP(0)

hxS_event_head    DD 0
hxS_event_tail    DD 0

; Payload staging buffer: written by the payload builders, consumed by hxS_Emit.
hxS_scratch       DB HX_PAYLOAD_BYTES DUP(0)

_DATA ENDS

_DATA SEGMENT
str_plan       DB "plan=sequential_decompose cand=4 roles=3 depth=1",0
str_role       DB "role.requested architect",0
str_verify     DB "verify pending_external_grant",0
str_cand       DB "cand=",0
str_fp         DB " fp=",0
str_len        DB " len=",0
str_spawn      DB "spawn ",0
str_bots       DB " bots=",0
str_answer     DB "answer ",0
str_grant      DB " grant=",0
_DATA ENDS

_TEXT SEGMENT

; ---------------------------------------------------------------------------
; hxS_ZeroScratch -- zero all 480 payload bytes.  Leaf; touches xmm0 only, so
; it does not disturb rcx/rdx and callers need not save them.
; ---------------------------------------------------------------------------
hxS_ZeroScratch PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
    pxor    xmm0, xmm0
    movdqu  xmmword ptr [hxS_scratch],        xmm0
    movdqu  xmmword ptr [hxS_scratch + 16],   xmm0
    movdqu  xmmword ptr [hxS_scratch + 32],   xmm0
    movdqu  xmmword ptr [hxS_scratch + 48],   xmm0
    movdqu  xmmword ptr [hxS_scratch + 64],   xmm0
    movdqu  xmmword ptr [hxS_scratch + 80],   xmm0
    movdqu  xmmword ptr [hxS_scratch + 96],   xmm0
    movdqu  xmmword ptr [hxS_scratch + 112],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 128],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 144],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 160],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 176],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 192],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 208],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 224],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 240],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 256],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 272],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 288],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 304],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 320],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 336],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 352],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 368],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 384],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 400],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 416],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 432],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 448],  xmm0
    movdqu  xmmword ptr [hxS_scratch + 464],  xmm0
    pop     rdi
    pop     rsi
    ret
hxS_ZeroScratch ENDP

; ---------------------------------------------------------------------------
; hxS_Hex64   rdi = dst, rsi = value, rdx = char count
; Writes exactly rdx hex characters, most significant first, zero padded.
; Leaf.
;
; The digit is computed arithmetically rather than looked up in a "0123456789ABCDEF"
; table.  The table version emitted a correct instruction sequence and a correct
; REL32 relocation, and still wrote nothing at run time; deriving the digit from
; the nibble removes that dependency entirely and is one fewer thing that can
; disagree with the rest of the receipt.
; ---------------------------------------------------------------------------
hxS_Hex64 PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
    mov     rcx, rdx
    add     rdi, rdx
    dec     rdi                      ; start at the last character
hxS_Hex64_loop:
    mov     rax, rsi
    and     rax, 0Fh
    cmp     rax, 10
    jb      hxSH_decimal
    add     al, 'A' - 10
    jmp     hxSH_store
hxSH_decimal:
    add     al, '0'
hxSH_store:
    mov     byte ptr [rdi], al
    dec     rdi                      ; WALK BACKWARDS one character per digit
    shr     rsi, 4
    dec     rcx
    jnz     hxS_Hex64_loop
    pop     rdi
    pop     rsi
    ret
hxS_Hex64 ENDP

; ---------------------------------------------------------------------------
; hxS_PutAscii   rcx = src, rdx = byte count, rdi = dst cursor.  Leaf.
; ---------------------------------------------------------------------------
hxS_PutAscii PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
    ; Clear DF before rep movsb: the direction flag is caller state, not ours
    ; to assume, and a set DF makes a forward copy run backwards out of the
    ; destination. See the same note on hxS_Emit and HexMag_PollEvent.
    cld
    mov     rsi, rcx
    mov     rcx, rdx
    rep     movsb
    pop     rdi
    pop     rsi
    ret
hxS_PutAscii ENDP

; ---------------------------------------------------------------------------
; hxS_GoalDigest -> rax = FNV-1a 64 over the stored goal text, forced non-zero.
; This is the goal id AND the candidate fingerprint, so a candidate payload is a
; real function of the bytes that were submitted rather than a constant.
; Leaf.
; ---------------------------------------------------------------------------
hxS_GoalDigest PROC
    mov     rax, FNV_OFFSET_BASIS
    lea     r10, [hxS_goal_text]
    mov     r11d, dword ptr [hxS_block + BL_GOAL_LEN]
    test    r11d, r11d
    jz      hxSGD_done
hxSGD_loop:
    movzx   r9d, byte ptr [r10]
    test    r9b, r9b
    jz      hxSGD_done
    xor     rax, r9
    mov     r9, HX_FNV_PRIME
    imul    rax, r9
    inc     r10
    dec     r11d
    jnz     hxSGD_loop
hxSGD_done:
    test    rax, rax
    jnz     hxSGD_keep
    mov     rax, 1                   ; goal id 0 is reserved for "no goal"
hxSGD_keep:
    ret
hxS_GoalDigest ENDP

; ---------------------------------------------------------------------------
; hxS_MintAgentId -> rax.  splitmix64 over the previous id, forced non-zero.
; Guarantees the "each spawn mints an unused agent/model id" contract.
; Leaf.
; ---------------------------------------------------------------------------
hxS_MintAgentId PROC
    mov     rcx, qword ptr [hxS_block + BL_LAST_AGENT_ID]
    mov     rax, rcx
    mov     r8, HX_FNV_PRIME
    imul    rax, r8                  ; splitmix64 increment
    mov     rcx, rax
    mov     rax, HX_SPLITMIX_ADD
    xor     rcx, rax
    mov     rax, rcx
    shr     rax, 30
    mov     rdx, HX_SPLITMIX_ADD
    xor     rax, rdx
    imul    rcx, rax
    mov     rax, rcx
    shr     rax, 27
    mov     rdx, HX_SPLITMIX_ADD
    xor     rax, rdx
    imul    rcx, rax
    mov     rax, rcx
    shr     rax, 31
    xor     rcx, rax
    inc     rcx
    test    rcx, rcx
    jnz     hxMA_keep
    mov     rcx, 1                   ; 0 is reserved for "no agent"
hxMA_keep:
    mov     rax, rcx
    ret
hxS_MintAgentId ENDP

; ---------------------------------------------------------------------------
; hxS_ClearState / hxS_ClearGoal -- zeroing helpers.  Leaves BL_INITIALIZED at
; 0, so callers that want a live swarm set it explicitly afterwards.
;
; These use explicit movdqu loops and NOT `rep stosq`.  The rep form was measured
; in this toolchain to store the pre-call RAX rather than zero (an isolated
; probe wrote 0x000000004C4C4C4C into every slot), which would leave a "cleared"
; control block full of garbage.  movdqu is unaligned-tolerant, so no alignment
; assumption is made about any of these buffers.
; Leaf: no frame required.
; ---------------------------------------------------------------------------
hxS_ClearState PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
    pxor    xmm0, xmm0
    lea     rdi, [hxS_block]
    mov     ecx, BL_SIZE / 16
hxCS_block_loop:
    movdqu  xmmword ptr [rdi], xmm0
    add     rdi, 16
    dec     ecx
    jnz     hxCS_block_loop

    lea     rdi, [hxS_goal_text]
    mov     ecx, HX_GOAL_BYTES / 16
hxCS_goal_loop:
    movdqu  xmmword ptr [rdi], xmm0
    add     rdi, 16
    dec     ecx
    jnz     hxCS_goal_loop

    lea     rdi, [hxS_scratch]
    mov     ecx, HX_PAYLOAD_BYTES / 16
hxCS_scratch_loop:
    movdqu  xmmword ptr [rdi], xmm0
    add     rdi, 16
    dec     ecx
    jnz     hxCS_scratch_loop

    mov     dword ptr [hxS_event_head], 0
    mov     dword ptr [hxS_event_tail], 0
    pop     rdi
    pop     rsi
    ret
hxS_ClearState ENDP

hxS_ClearGoal PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
    pxor    xmm0, xmm0
    lea     rdi, [hxS_goal_text]
    mov     ecx, HX_GOAL_BYTES / 16
hxCG_loop:
    movdqu  xmmword ptr [rdi], xmm0
    add     rdi, 16
    dec     ecx
    jnz     hxCG_loop
    pop     rdi
    pop     rsi
    ret
hxS_ClearGoal ENDP

; ---------------------------------------------------------------------------
; hxS_Emit   rcx = kind, edx = role, r8d = target_role, r9d = depth
; Consumes the payload already staged in hxS_scratch.
; Returns eax = 1 when the event was queued, 0 when it was refused.
; ---------------------------------------------------------------------------
hxS_Emit PROC
    ; RSI and RDI are NONVOLATILE on Windows x64.
    push    rsi
    push    rdi
    cld                         ; repne scasb / rep movsb below require DF=0
    mov     r10d, dword ptr [hxS_block + BL_EVENT_COUNT]
    cmp     r10d, HX_EVENT_CAPACITY
    jb      hxSE_room
    ; Refuse rather than overwrite an unread event.  Silently clobbering the
    ; queue would let a reader observe an event the producer never intended.
    mov     dword ptr [hxS_block + BL_QUEUE_FULL], 1
    xor     eax, eax
    pop     rdi
    pop     rsi
    ret
hxSE_room:
    mov     r11d, dword ptr [hxS_event_head]
    shl     r11, 9                  ; * EV_SIZE
    lea     rax, [hxS_event_queue]   ; LEA + add, not [sym + r11]: the indexed
    add     rax, r11                ; form would need an ADDR32 relocation
    mov     r12, rax                ; slot, preserved across the copy
    mov     eax, 1
    push    r12
    ; zero the 32-byte header region; payload bytes are overwritten below
    pxor    xmm0, xmm0
    movdqu  xmmword ptr [r12],      xmm0
    movdqu  xmmword ptr [r12 + 16], xmm0
    mov     dword ptr [r12 + EV_KIND],        ecx
    mov     dword ptr [r12 + EV_ROLE],        edx
    mov     dword ptr [r12 + EV_TARGET_ROLE], r8d
    mov     dword ptr [r12 + EV_DEPTH],       r9d
    mov     rax, qword ptr [hxS_block + BL_GOAL_ID]
    mov     qword ptr [r12 + EV_GOAL_ID], rax
    ; payload_len = offset of the first NUL, or the full 480 when filled.
    ; AL must be 0: repne scasb searches for AL, and AL here still holds the low
    ; byte of the goal id, so without this the scan misses the terminator and
    ; every event reports payload_len 479.
    xor     eax, eax
    lea     rdi, [hxS_scratch]
    mov     ecx, HX_PAYLOAD_BYTES
    xor     r8d, r8d
    repne   scasb
    mov     rax, HX_PAYLOAD_BYTES
    sub     rax, rcx                 ; consumed, NUL included
    test    rcx, rcx
    jnz     hxSE_len_ok
    mov     rax, HX_PAYLOAD_BYTES    ; no NUL: the buffer was filled exactly
hxSE_len_ok:
    dec     rax
    mov     dword ptr [r12 + EV_PAYLOAD_LEN], eax
    ; copy the payload verbatim
    lea     rdi, [r12 + EV_PAYLOAD]
    lea     rsi, [hxS_scratch]
    mov     rcx, HX_PAYLOAD_BYTES
    rep     movsb
    pop     r12
    mov     r11d, dword ptr [hxS_event_head]
    inc     r11d
    and     r11d, HX_EVENT_MASK
    mov     dword ptr [hxS_event_head], r11d
    inc     r10d
    mov     dword ptr [hxS_block + BL_EVENT_COUNT], r10d
    mov     eax, 1
    pop     rdi
    pop     rsi
    ret
hxS_Emit ENDP

; ---------------------------------------------------------------------------
; hxS_BuildCandidate   ecx = candidate index k (0-based)
; payload = "cand=<k:2> fp=<goal digest:16> len=<goal len:4>"   (36 bytes)
; ---------------------------------------------------------------------------
hxS_BuildCandidate PROC
    ; RSI and RDI are NONVOLATILE on Windows x64.
    push    rsi
    push    rdi
    sub     rsp, 28h                 ; shadow space; hxS_ZeroScratch is a leaf
    mov     r11d, ecx                ; k survives PutAscii, which eats rcx
    call    hxS_ZeroScratch          ; rcx/r11 survive: ZeroScratch uses xmm0
    lea     rdi, [hxS_scratch]
    lea     rcx, [str_cand]
    mov     edx, 5
    call    hxS_PutAscii
    lea     rdi, [hxS_scratch + 5]
    mov     esi, r11d
    mov     edx, 2
    call    hxS_Hex64
    lea     rdi, [hxS_scratch + 7]
    lea     rcx, [str_fp]
    mov     edx, 4
    call    hxS_PutAscii
    call    hxS_GoalDigest
    lea     rdi, [hxS_scratch + 11]
    mov     rsi, rax
    mov     edx, 16
    call    hxS_Hex64
    lea     rdi, [hxS_scratch + 27]
    lea     rcx, [str_len]
    mov     edx, 5
    call    hxS_PutAscii
    mov     esi, dword ptr [hxS_block + BL_GOAL_LEN]
    lea     rdi, [hxS_scratch + 32]
    mov     edx, 4
    call    hxS_Hex64
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxS_BuildCandidate ENDP

; ---------------------------------------------------------------------------
; hxS_BuildSpawn   rcx = agent id
; payload = "spawn agent=<16> bots=<4>"                            (32 bytes)
; ---------------------------------------------------------------------------
hxS_BuildSpawn PROC
    ; RSI and RDI are NONVOLATILE on Windows x64.
    push    rsi
    push    rdi
    sub     rsp, 28h
    mov     r11, rcx                 ; agent id survives PutAscii
    call    hxS_ZeroScratch
    lea     rdi, [hxS_scratch]
    lea     rcx, [str_spawn]
    mov     edx, 6
    call    hxS_PutAscii
    lea     rdi, [hxS_scratch + 6]
    mov     rsi, r11
    mov     edx, 16
    call    hxS_Hex64
    lea     rdi, [hxS_scratch + 22]
    lea     rcx, [str_bots]
    mov     edx, 6
    call    hxS_PutAscii
    mov     esi, dword ptr [hxS_block + BL_BOT_COUNT]
    lea     rdi, [hxS_scratch + 28]
    mov     edx, 4
    call    hxS_Hex64
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxS_BuildSpawn ENDP

; ---------------------------------------------------------------------------
; hxS_BuildAnswer
; payload = "answer fp=<16> grant=<1>"                              (31 bytes)
; ---------------------------------------------------------------------------
hxS_BuildAnswer PROC
    ; RSI and RDI are NONVOLATILE on Windows x64.
    push    rsi
    push    rdi
    sub     rsp, 28h
    call    hxS_ZeroScratch
    lea     rdi, [hxS_scratch]
    lea     rcx, [str_answer]
    mov     edx, 7
    call    hxS_PutAscii
    call    hxS_GoalDigest
    lea     rdi, [hxS_scratch + 7]
    mov     rsi, rax
    mov     edx, 16
    call    hxS_Hex64
    lea     rdi, [hxS_scratch + 23]
    lea     rcx, [str_grant]
    mov     edx, 7
    call    hxS_PutAscii
    mov     esi, dword ptr [hxS_block + BL_GRANT]
    lea     rdi, [hxS_scratch + 30]
    mov     edx, 1
    call    hxS_Hex64
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxS_BuildAnswer ENDP

; ===========================================================================
; PUBLIC EXPORTS
; ===========================================================================

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
PUBLIC HexMag_IsInitialized
PUBLIC HexMag_Feedback
PUBLIC HexMag_SetParallelAgents
PUBLIC HexMag_GetParallelAgents

; uint64_t HexMag_Init(void)
HexMag_Init PROC
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jz      hxI_fresh
    ; Re-init must NOT silently reset a live session: a caller that believes it
    ; owns the swarm would lose in-flight state and any pending grant.
    mov     eax, HX_ERR_ALREADY_INIT
    ret
hxI_fresh:
    call    hxS_ClearState
    mov     dword ptr [hxS_block + BL_PARALLEL], HX_MIN_PARALLEL
    mov     dword ptr [hxS_block + BL_BOT_COUNT], 1
    mov     dword ptr [hxS_block + BL_STAGE], STG_IDLE
    mov     dword ptr [hxS_block + BL_INITIALIZED], 1
    xor     eax, eax
    ret
HexMag_Init ENDP

; uint64_t HexMag_Shutdown(void)
HexMag_Shutdown PROC
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jnz     hxS_live
    mov     eax, HX_ERR_NOT_INIT
    ret
hxS_live:
    call    hxS_ClearState
    xor     eax, eax
    ret
HexMag_Shutdown ENDP

; void* HexMag_GetState(void)
HexMag_GetState PROC
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jz      hxGS_absent
    lea     rax, [hxS_block]
    ret
hxGS_absent:
    xor     eax, eax
    ret
HexMag_GetState ENDP

; uint64_t HexMag_SubmitGoal(const char* goal, uint32_t length)
HexMag_SubmitGoal PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
    cld                         ; rep movsb below requires DF=0
    sub     rsp, 28h
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jnz     hxSG_live
    mov     eax, HX_ERR_NOT_INIT
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxSG_live:
    test    rcx, rcx
    jz      hxSG_bad_arg
    test    edx, edx
    jz      hxSG_bad_arg
    cmp     edx, HX_GOAL_BYTES - 1
    jbe     hxSG_len_ok
hxSG_bad_arg:
    mov     eax, HX_ERR_BAD_ARG
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxSG_len_ok:
    ; A goal already in flight is not replaced: the caller must drain or cancel
    ; first.  Overwriting it would strand the in-flight queue.
    mov     eax, dword ptr [hxS_block + BL_STAGE]
    cmp     eax, STG_IDLE
    je      hxSG_no_inflight
    cmp     eax, STG_SATISFIED
    je      hxSG_no_inflight
    mov     eax, HX_ERR_REPEAT
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxSG_no_inflight:
    ; Stash BOTH the length and the source pointer before the clear: hxS_ClearGoal
    ; spends rcx as its own loop counter, so a `mov rsi, rcx` placed after the
    ; call copies 0 and `rep movsb` reads address 0.
    mov     r10d, edx                ; length
    mov     r11, rcx                 ; source pointer
    call    hxS_ClearGoal
    lea     rdi, [hxS_goal_text]
    mov     rsi, r11
    mov     rcx, r10
    rep     movsb
    lea     rdi, [hxS_goal_text + HX_GOAL_BYTES - 1]
    mov     byte ptr [rdi], 0
    mov     eax, r10d
    mov     dword ptr [hxS_block + BL_GOAL_LEN], eax

    ; reset per-goal state
    mov     dword ptr [hxS_event_head], 0
    mov     dword ptr [hxS_event_tail], 0
    mov     dword ptr [hxS_block + BL_EVENT_COUNT], 0
    mov     dword ptr [hxS_block + BL_QUEUE_FULL], 0
    mov     dword ptr [hxS_block + BL_STAGE], STG_REQUESTED
    mov     dword ptr [hxS_block + BL_STEP_COUNT], 0
    mov     dword ptr [hxS_block + BL_SATISFIED], 0
    mov     dword ptr [hxS_block + BL_GRANT], 0
    mov     dword ptr [hxS_block + BL_FINALIZED], 0
    mov     qword ptr [hxS_block + BL_AGENTS_SPAWNED], 0

    call    hxS_GoalDigest
    mov     qword ptr [hxS_block + BL_GOAL_ID], rax
    mov     qword ptr [hxS_block + BL_LAST_AGENT_ID], rax

    ; GOAL_REQUESTED payload is the goal text itself, bounded to 479 bytes plus
    ; the terminating NUL so payload_len stays meaningful.
    call    hxS_ZeroScratch
    mov     r10d, dword ptr [hxS_block + BL_GOAL_LEN]
    cmp     r10d, HX_PAYLOAD_BYTES - 1
    jbe     hxSG_copy_len
    mov     r10d, HX_PAYLOAD_BYTES - 1
hxSG_copy_len:
    lea     rdi, [hxS_scratch]
    lea     rsi, [hxS_goal_text]
    mov     rcx, r10
    rep     movsb
    mov     byte ptr [rdi], 0

    mov     ecx, EVT_GOAL_REQUESTED
    xor     edx, edx
    xor     r8d, r8d
    xor     r9d, r9d
    call    hxS_Emit

    mov     rax, qword ptr [hxS_block + BL_GOAL_ID]
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
HexMag_SubmitGoal ENDP

; uint32_t HexMag_Step(void)
; Advances one stage.  Returns the number of events emitted, so a caller can
; distinguish "did work" from "stalled".
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
HexMag_Step PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    ; The pushes come BEFORE the frame allocation. Two pushes are 16 bytes, a
    ; multiple of 16, so they leave RSP 16n-8; `sub rsp, 28h` then brings it to
    ; 16n, which is what the nested calls below require. Reversing this order
    ; leaves the epilogue popping slots that were never pushed.
    push    rsi
    push    rdi
    sub     rsp, 28h
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jnz     hxSt_live
    xor     eax, eax
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxSt_live:
    mov     r11d, dword ptr [hxS_block + BL_STEP_COUNT]
    inc     r11d
    mov     dword ptr [hxS_block + BL_STEP_COUNT], r11d

    mov     eax, dword ptr [hxS_block + BL_STAGE]
    cmp     eax, STG_REQUESTED
    je      hxSt_plan
    cmp     eax, STG_PLANNED
    je      hxSt_spawn
    cmp     eax, STG_SPAWNED
    je      hxSt_candidates
    cmp     eax, STG_CANDIDATES
    je      hxSt_verify
    cmp     eax, STG_VERIFY
    je      hxSt_final
    ; STG_IDLE / STG_SATISFIED: nothing left to advance
    xor     eax, eax
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret

; ---- REQUESTED -> PLAN ----------------------------------------------------
hxSt_plan:
    call    hxS_ZeroScratch
    lea     rdi, [hxS_scratch]
    lea     rcx, [str_plan]
    mov     edx, 48
    call    hxS_PutAscii
    mov     ecx, EVT_PLAN
    xor     edx, edx
    xor     r8d, r8d
    mov     r9d, 1
    call    hxS_Emit
    mov     dword ptr [hxS_block + BL_STAGE], STG_PLANNED
    mov     eax, 1
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret

; ---- PLANNED -> SPAWN -----------------------------------------------------
; The loop counter and the width limit live in the control block, not in
; registers.  hxS_BuildSpawn/hxS_Emit/hxS_GoalDigest all clobber r9 and r10, so
; a register-held counter is destroyed by the first iteration and the loop ends
; up emitting an arbitrary number of spawns.
hxSt_spawn:
    mov     dword ptr [hxS_block + BL_RESERVED0], 0
hxSt_spawn_loop:
    mov     r10d, dword ptr [hxS_block + BL_RESERVED0]
    cmp     r10d, dword ptr [hxS_block + BL_PARALLEL]
    jae     hxSt_spawn_done
    call    hxS_MintAgentId
    mov     qword ptr [hxS_block + BL_LAST_AGENT_ID], rax
    inc     qword ptr [hxS_block + BL_AGENTS_SPAWNED]
    mov     rcx, rax
    call    hxS_BuildSpawn
    mov     ecx, EVT_RESPONDER_SPAWN
    xor     edx, edx
    xor     r8d, r8d
    mov     r9d, 1
    call    hxS_Emit
    inc     dword ptr [hxS_block + BL_RESERVED0]
    jmp     hxSt_spawn_loop
hxSt_spawn_done:
    call    hxS_ZeroScratch
    lea     rdi, [hxS_scratch]
    lea     rcx, [str_role]
    mov     edx, 24
    call    hxS_PutAscii
    mov     ecx, EVT_ROLE_REQUESTED
    mov     edx, ROLE_ARCHITECT
    xor     r8d, r8d
    mov     r9d, 2
    call    hxS_Emit
    mov     dword ptr [hxS_block + BL_STAGE], STG_SPAWNED
    mov     eax, dword ptr [hxS_block + BL_RESERVED0]
    inc     eax                          ; + the role request
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret

; ---- SPAWNED -> CANDIDATES ----------------------------------------------
; Same reason: hxS_BuildCandidate reaches hxS_GoalDigest, which clobbers r10.
hxSt_candidates:
    mov     dword ptr [hxS_block + BL_RESERVED0], 0
hxSt_cand_loop:
    mov     r10d, dword ptr [hxS_block + BL_RESERVED0]
    cmp     r10d, HX_CANDIDATES
    jae     hxSt_cand_done
    mov     ecx, r10d
    call    hxS_BuildCandidate
    mov     ecx, EVT_ANSWER_CANDIDATE
    xor     edx, edx
    xor     r8d, r8d
    mov     r9d, 3
    call    hxS_Emit
    inc     dword ptr [hxS_block + BL_RESERVED0]
    jmp     hxSt_cand_loop
hxSt_cand_done:
    mov     dword ptr [hxS_block + BL_STAGE], STG_CANDIDATES
    mov     eax, dword ptr [hxS_block + BL_RESERVED0]
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret

; ---- CANDIDATES -> VERIFY ------------------------------------------------
hxSt_verify:
    call    hxS_ZeroScratch
    lea     rdi, [hxS_scratch]
    lea     rcx, [str_verify]
    mov     edx, 29
    call    hxS_PutAscii
    mov     ecx, EVT_VERIFY
    xor     edx, edx
    xor     r8d, r8d
    mov     r9d, 4
    call    hxS_Emit
    mov     dword ptr [hxS_block + BL_STAGE], STG_VERIFY
    mov     eax, 1
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret

; ---- VERIFY -> FINAL + SATISFIED, only with an external grant -------------
hxSt_final:
    cmp     dword ptr [hxS_block + BL_GRANT], 0
    jz      hxSt_halt
    call    hxS_BuildAnswer
    mov     ecx, EVT_ANSWER_FINAL
    xor     edx, edx
    xor     r8d, r8d
    mov     r9d, 5
    call    hxS_Emit
    call    hxS_BuildAnswer
    mov     ecx, EVT_GOAL_SATISFIED
    xor     edx, edx
    xor     r8d, r8d
    mov     r9d, 5
    call    hxS_Emit
    mov     dword ptr [hxS_block + BL_SATISFIED], 1
    mov     dword ptr [hxS_block + BL_STAGE], STG_SATISFIED
    mov     eax, 2
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
hxSt_halt:
    ; No grant: emit nothing and change nothing.  Reporting progress here would
    ; let RunToSatisfied spin and eventually claim satisfaction.
    xor     eax, eax
    add     rsp, 28h
    pop     rdi
    pop     rsi
    ret
HexMag_Step ENDP

; uint32_t HexMag_PollEvent(HxEvent* out_event)
; Returns 1 only when a real queued event was copied out.
;
; Emptiness is decided by BL_EVENT_COUNT, NOT by head == tail. Those two are the
; same value once the ring has advanced a full capacity, so comparing them makes
; a FULL queue -- 256 unread events -- indistinguishable from an empty one, and
; the drain silently reports nothing. A ring buffer needs one bit of
; discrimination; the counter is that bit.
HexMag_PollEvent PROC
    ; RSI and RDI are NONVOLATILE on Windows x64: usable only if restored.
    push    rsi
    push    rdi
    cld                         ; rep movsb below requires DF=0
    test    rcx, rcx
    jz      hxPE_none
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jz      hxPE_none
    cmp     dword ptr [hxS_block + BL_EVENT_COUNT], 0
    jle     hxPE_none
    mov     r11d, dword ptr [hxS_event_tail]
    shl     r11, 9
    lea     rsi, [hxS_event_queue]
    add     rsi, r11
    mov     rdi, rcx
    mov     rcx, EV_SIZE
    rep     movsb
    mov     r11d, dword ptr [hxS_event_tail]
    inc     r11d
    and     r11d, HX_EVENT_MASK
    mov     dword ptr [hxS_event_tail], r11d
    dec     dword ptr [hxS_block + BL_EVENT_COUNT]
    mov     eax, 1
    pop     rdi
    pop     rsi
    ret
hxPE_none:
    xor     eax, eax
    pop     rdi
    pop     rsi
    ret
HexMag_PollEvent ENDP

; uint64_t HexMag_RunToSatisfied(uint32_t max_steps)
HexMag_RunToSatisfied PROC
    sub     rsp, 28h
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jnz     hxRS_live
    mov     eax, HX_ERR_NOT_INIT
    add     rsp, 28h
    ret
hxRS_live:
    test    ecx, ecx
    jnz     hxRS_budget
    mov     eax, HX_ERR_BAD_ARG
    add     rsp, 28h
    ret
hxRS_budget:
    cmp     dword ptr [hxS_block + BL_STAGE], STG_IDLE
    jne     hxRS_work
    ; Nothing submitted: this is not a satisfied goal, it is no goal at all.
    mov     eax, HX_ERR_IDLE_FAIL
    add     rsp, 28h
    ret
hxRS_work:
    ; The step budget lives in the control block: HexMag_Step clobbers both rcx
    ; (the caller's max_steps) and r9, so a register-held bound is destroyed on
    ; the first iteration and the loop becomes unbounded.
    mov     dword ptr [hxS_block + BL_RESERVED1], ecx
hxRS_loop:
    mov     eax, dword ptr [hxS_block + BL_STEP_COUNT]
    cmp     eax, dword ptr [hxS_block + BL_RESERVED1]
    jge     hxRS_budget_spent
    call    HexMag_Step
    cmp     dword ptr [hxS_block + BL_SATISFIED], 0
    jnz     hxRS_ok
    test    eax, eax
    jnz     hxRS_loop
    jmp     hxRS_stalled           ; a step that emitted nothing is a stall
hxRS_ok:
    xor     eax, eax                ; HX_OK -- satisfaction was actually set
    add     rsp, 28h
    ret
hxRS_budget_spent:
    cmp     dword ptr [hxS_block + BL_QUEUE_FULL], 0
    jnz     hxRS_queue_full
    mov     eax, HX_ERR_TIMEOUT
    add     rsp, 28h
    ret
hxRS_stalled:
    mov     eax, HX_ERR_IDLE_FAIL
    add     rsp, 28h
    ret
hxRS_queue_full:
    mov     eax, HX_ERR_QUEUE_FULL
    add     rsp, 28h
    ret
HexMag_RunToSatisfied ENDP

; uint32_t HexMag_BotCount(void)
HexMag_BotCount PROC
    mov     eax, dword ptr [hxS_block + BL_BOT_COUNT]
    ret
HexMag_BotCount ENDP

; uint64_t HexMag_AgentsSpawned(void)
HexMag_AgentsSpawned PROC
    mov     rax, qword ptr [hxS_block + BL_AGENTS_SPAWNED]
    ret
HexMag_AgentsSpawned ENDP

; uint64_t HexMag_LastAgentId(void)
HexMag_LastAgentId PROC
    mov     rax, qword ptr [hxS_block + BL_LAST_AGENT_ID]
    ret
HexMag_LastAgentId ENDP

; RAWRXD_HEXMAG_SWARM_EXTERN_TUNER_001
;
; HexMag_TunerAttempt (no underscore) is this file's own export and matches
; hexmag_swarm.hpp:87. It forwards to HexMag_Tuner_Attempt (with underscore),
; which is a DIFFERENT export and matches hexmag_repeat_tuner.hpp:60. Two
; headers, two names, one concept -- both spellings are part of the public ABI
; and both are implemented.
;
; ml64 reported A2006 "undefined symbol" at the forwarding call because MASM
; resolves `call` at assembly time and this file had no EXTERN for the callee.
; PUBLIC on the defining side only exports; it does not make the symbol visible
; to a sibling translation unit. The two files are linked together but are
; assembled separately, so the dependency has to be declared.
EXTERN HexMag_Tuner_Attempt:PROC

; uint32_t HexMag_TunerAttempt(void)
; Reports the tuner's own counter rather than a private copy, so the two cannot
; drift apart.  This couples the two objects: every target that links this file
; also links RawrXD_HexMag_RepeatTuner.asm.
HexMag_TunerAttempt PROC
    call    HexMag_Tuner_Attempt
    ret
HexMag_TunerAttempt ENDP

; uint32_t HexMag_IsInitialized(void)
HexMag_IsInitialized PROC
    mov     eax, dword ptr [hxS_block + BL_INITIALIZED]
    ret
HexMag_IsInitialized ENDP

; uint32_t HexMag_Feedback(uint32_t fail_kind_or_zero)
; 0    -> an external verifier passed: record the grant, report 2 (finalized)
; else -> a failure was reported: withdraw the grant, rewind to CANDIDATES,
;         report 1 (retry scheduled)
; HexMag_Feedback is the ONLY path by which a grant can appear.
HexMag_Feedback PROC
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jnz     hxFb_live
    xor     eax, eax                 ; the caller reads this as exhausted
    ret
hxFb_live:
    test    ecx, ecx
    jnz     hxFb_retry
    mov     dword ptr [hxS_block + BL_GRANT], 1
    mov     dword ptr [hxS_block + BL_FINALIZED], 1
    mov     eax, 2
    ret
hxFb_retry:
    mov     dword ptr [hxS_block + BL_GRANT], 0
    mov     dword ptr [hxS_block + BL_FINALIZED], 0
    mov     eax, dword ptr [hxS_block + BL_STAGE]
    cmp     eax, STG_SATISFIED
    je      hxFb_done
    cmp     eax, STG_IDLE
    je      hxFb_done
    ; Rewind only as far as the candidate stage: verification is what failed.
    mov     dword ptr [hxS_block + BL_STAGE], STG_CANDIDATES
    mov     dword ptr [hxS_block + BL_SATISFIED], 0
hxFb_done:
    mov     eax, 1
    ret
HexMag_Feedback ENDP

; uint32_t HexMag_SetParallelAgents(uint32_t count)
HexMag_SetParallelAgents PROC
    cmp     ecx, HX_MIN_PARALLEL
    jae     hxSa_lo
    mov     ecx, HX_MIN_PARALLEL
    jmp     hxSa_hi
hxSa_lo:
    cmp     ecx, HX_MAX_PARALLEL
    jbe     hxSa_hi
    mov     ecx, HX_MAX_PARALLEL
hxSa_hi:
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jz      hxSa_absent
    mov     dword ptr [hxS_block + BL_PARALLEL], ecx
hxSa_absent:
    ; Returns the EFFECTIVE count, never the requested one.
    mov     eax, ecx
    ret
HexMag_SetParallelAgents ENDP

; uint32_t HexMag_GetParallelAgents(void)
HexMag_GetParallelAgents PROC
    cmp     dword ptr [hxS_block + BL_INITIALIZED], 0
    jz      hxGa_absent
    mov     eax, dword ptr [hxS_block + BL_PARALLEL]
    ret
hxGa_absent:
    xor     eax, eax
    ret
HexMag_GetParallelAgents ENDP

_TEXT ENDS

END
