; ============================================================================
; P1_ProductRuntimeAuthority_x64.asm
;
; P1_PRODUCT_RUNTIME_AUTHORITY_002
; Pure x64 MASM — no CRT, imports, heap, stubs, or synthetic completion.
; ============================================================================

option casemap:none

include P1_ProductRuntimeAuthority_x64.inc

.code

PUBLIC P1PRA_Initialize
PUBLIC P1PRA_BeginUserPrompt
PUBLIC P1PRA_AdvanceStage
PUBLIC P1PRA_AddPhysicalCounter
PUBLIC P1PRA_Finalize

; ----------------------------------------------------------------------------
; void P1PRA_Initialize(void* state)
; RCX = state
; ----------------------------------------------------------------------------

P1PRA_Initialize PROC
    test    rcx, rcx
    jz      short init_done

    mov     r8, rcx
    xor     eax, eax
    mov     edx, P1PRA_STATE_SIZE / 8

init_zero:
    mov     qword ptr [r8], rax
    add     r8, 8
    dec     edx
    jnz     short init_zero

    mov     qword ptr [rcx + P1PRA_OFF_MAGIC], P1PRA_MAGIC
    mov     qword ptr [rcx + P1PRA_OFF_VERSION], P1PRA_VERSION
    mov     qword ptr [rcx + P1PRA_OFF_CURRENT_STAGE], P1PRA_STAGE_NONE

init_done:
    ret
P1PRA_Initialize ENDP


; ----------------------------------------------------------------------------
; uint64_t P1PRA_BeginUserPrompt(state, prompt, promptBytes)
; RCX = state, RDX = prompt, R8 = byte count
; RAX = REQUEST_ID (0 rejected)
; ----------------------------------------------------------------------------

P1PRA_BeginUserPrompt PROC
    test    rcx, rcx
    jz      short begin_fail

    cmp     qword ptr [rcx + P1PRA_OFF_MAGIC], P1PRA_MAGIC
    jne     short begin_bad_state

    test    rdx, rdx
    jz      short begin_bad_prompt

    test    r8, r8
    jz      short begin_bad_prompt

    mov     rax, qword ptr [rcx + P1PRA_OFF_REQUEST_SEQUENCE]
    inc     rax

    mov     qword ptr [rcx + P1PRA_OFF_REQUEST_SEQUENCE], rax
    mov     qword ptr [rcx + P1PRA_OFF_CURRENT_REQUEST_ID], rax

    mov     qword ptr [rcx + P1PRA_OFF_CURRENT_STAGE], P1PRA_STAGE_USER_PROMPT

    inc     qword ptr [rcx + P1PRA_OFF_PROMPT_COUNT]

    mov     r9, qword ptr [rcx + P1PRA_OFF_PROMPT_BYTES]
    add     r9, r8
    mov     qword ptr [rcx + P1PRA_OFF_PROMPT_BYTES], r9

    mov     qword ptr [rcx + P1PRA_OFF_PROMPT_PTR], rdx

    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     qword ptr [rcx + P1PRA_OFF_PROMPT_TSC], rax

    mov     rax, qword ptr [rcx + P1PRA_OFF_CURRENT_REQUEST_ID]
    ret

begin_bad_state:
    or      qword ptr [rcx + P1PRA_OFF_FAILURE_FLAGS], P1PRA_FAIL_BAD_STATE
    xor     eax, eax
    ret

begin_bad_prompt:
    or      qword ptr [rcx + P1PRA_OFF_FAILURE_FLAGS], P1PRA_FAIL_BAD_PROMPT

begin_fail:
    xor     eax, eax
    ret
P1PRA_BeginUserPrompt ENDP


; ----------------------------------------------------------------------------
; uint64_t P1PRA_AdvanceStage(state, requestId, stage)
; RCX = state, RDX = requestId, R8 = stage
; RAX = 0 success, nonzero fail
; ----------------------------------------------------------------------------

P1PRA_AdvanceStage PROC
    test    rcx, rcx
    jz      short advance_fail

    cmp     qword ptr [rcx + P1PRA_OFF_MAGIC], P1PRA_MAGIC
    jne     short advance_bad_state

    cmp     rdx, qword ptr [rcx + P1PRA_OFF_CURRENT_REQUEST_ID]
    jne     short advance_bad_stage

    mov     rax, qword ptr [rcx + P1PRA_OFF_CURRENT_STAGE]
    inc     rax
    cmp     rax, r8
    jne     short advance_bad_stage

    mov     qword ptr [rcx + P1PRA_OFF_CURRENT_STAGE], r8
    xor     eax, eax
    ret

advance_bad_state:
    or      qword ptr [rcx + P1PRA_OFF_FAILURE_FLAGS], P1PRA_FAIL_BAD_STATE
    mov     eax, 1
    ret

advance_bad_stage:
    or      qword ptr [rcx + P1PRA_OFF_FAILURE_FLAGS], P1PRA_FAIL_BAD_STAGE
    mov     eax, 2
    ret

advance_fail:
    mov     eax, 3
    ret
P1PRA_AdvanceStage ENDP


; ----------------------------------------------------------------------------
; uint64_t P1PRA_AddPhysicalCounter(state, offset, amount)
; RCX = state, RDX = offset, R8 = amount
; ----------------------------------------------------------------------------

P1PRA_AddPhysicalCounter PROC
    test    rcx, rcx
    jz      short counter_fail

    cmp     qword ptr [rcx + P1PRA_OFF_MAGIC], P1PRA_MAGIC
    jne     short counter_fail

    cmp     rdx, P1PRA_OFF_ROUTER_COUNT
    jb      short counter_fail

    cmp     rdx, P1PRA_OFF_UI_BYTES
    ja      short counter_fail

    test    rdx, 7
    jnz     short counter_fail

    mov     rax, qword ptr [rcx + rdx]
    add     rax, r8
    mov     qword ptr [rcx + rdx], rax

    xor     eax, eax
    ret

counter_fail:
    mov     eax, 1
    ret
P1PRA_AddPhysicalCounter ENDP


; ----------------------------------------------------------------------------
; uint64_t P1PRA_Finalize(void* state)
; RAX = 0 only when complete physical chain exists.
; USER_PROMPT alone MUST FAIL (returns 1).
; ----------------------------------------------------------------------------

P1PRA_Finalize PROC
    test    rcx, rcx
    jz      short finalize_fail

    inc     qword ptr [rcx + P1PRA_OFF_FINALIZE_COUNT]

    cmp     qword ptr [rcx + P1PRA_OFF_MAGIC], P1PRA_MAGIC
    jne     short finalize_fail

    cmp     qword ptr [rcx + P1PRA_OFF_FAILURE_FLAGS], 0
    jne     short finalize_fail

    cmp     qword ptr [rcx + P1PRA_OFF_CURRENT_REQUEST_ID], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_CURRENT_STAGE], P1PRA_STAGE_UI_EMIT
    jne     short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_PROMPT_COUNT], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_PROMPT_BYTES], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_ROUTER_COUNT], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_GGUF_OPEN_COUNT], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_WEIGHT_BYTES], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_FORWARD_COUNT], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_SAMPLE_COUNT], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_DECODE_BYTES], 0
    je      short finalize_incomplete

    cmp     qword ptr [rcx + P1PRA_OFF_UI_BYTES], 0
    je      short finalize_incomplete

    xor     eax, eax
    ret

finalize_incomplete:
    mov     eax, 1
    ret

finalize_fail:
    mov     eax, 1
    ret
P1PRA_Finalize ENDP

END
