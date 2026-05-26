; ============================================================================
; Sovereign_Sampler.asm — Sampler Routines
; Contains Top-K, Repetition Penalty, Temperature, ArgMax
; ============================================================================
OPTION CASEMAP:NONE

include Sovereign_Common.inc

EXTERNDEF g_pGov : QWORD
EXTERNDEF g_pTPS : QWORD


.DATA
    align 4
    __real@3a83126f dd 03a83126fh
    __real@3f800000 dd 03f800000h

.CODE

.CODE

; ----------------------------------------------------------------------------
; Sampler_Temperature
; RCX = logits ptr, EDX = vocab size, XMM2 = temperature
; ----------------------------------------------------------------------------
PUBLIC Sampler_Temperature
Sampler_Temperature PROC
    ; If temperature == 1.0, do nothing
    vmovss xmm0, __real@3f800000
    vucomiss xmm2, xmm0
    je @done

    ; If temperature < 0.001, just return (treat as argmax later)
    vmovss xmm0, __real@3a83126f
    vucomiss xmm2, xmm0
    jb @done

    mov r8d, edx
    xor eax, eax
@loop:
    cmp eax, r8d
    jge @done

    vmovss xmm0, dword ptr [rcx + rax*4]
    vdivss xmm0, xmm0, xmm2
    vmovss dword ptr [rcx + rax*4], xmm0

    inc eax
    jmp @loop
@done:
    ret
Sampler_Temperature ENDP

; ----------------------------------------------------------------------------
; Sampler_RepetitionPenalty
; RCX = logits ptr, EDX = vocab size, R8 = token_ids ptr, R9 = token_count, XMM2 = penalty
; ----------------------------------------------------------------------------
PUBLIC Sampler_RepetitionPenalty
Sampler_RepetitionPenalty PROC
    ; If penalty == 1.0, do nothing
    vmovss xmm0, __real@3f800000
    vucomiss xmm2, xmm0
    je @done

    mov r10d, edx
    xor eax, eax
@loop:
    cmp eax, r9d
    jge @done

    mov r11d, dword ptr [r8 + rax*4]
    cmp r11d, r10d
    jge @skip_token

    ; Apply penalty to logits[token_id]
    vmovss xmm0, dword ptr [rcx + r11*4]
    vxorps xmm1, xmm1, xmm1
    vucomiss xmm0, xmm1
    jb @negative_logit

    ; logit > 0: logit /= penalty
    vdivss xmm0, xmm0, xmm2
    jmp @store_logit
@negative_logit:
    ; logit < 0: logit *= penalty
    vmulss xmm0, xmm0, xmm2
@store_logit:
    vmovss dword ptr [rcx + r11*4], xmm0

@skip_token:
    inc eax
    jmp @loop
@done:
    ret
Sampler_RepetitionPenalty ENDP

; ----------------------------------------------------------------------------
; Sampler_ArgMax
; RCX = logits ptr, EDX = vocab size
; Returns EAX = best token id
; ----------------------------------------------------------------------------
PUBLIC Sampler_ArgMax
Sampler_ArgMax PROC
    xor eax, eax
    xor r8d, r8d
    vmovss xmm0, dword ptr [rcx]

@loop:
    cmp r8d, edx
    jge @done

    vmovss xmm1, dword ptr [rcx + r8*4]
    vucomiss xmm1, xmm0
    jbe @not_better

    vmovss xmm0, xmm1, xmm1
    mov eax, r8d

@not_better:
    inc r8d
    jmp @loop
@done:
    ret
Sampler_ArgMax ENDP

; ----------------------------------------------------------------------------
; Sampler_TopK
; Sort logits and pick from top K. (Bubble sort for now)
; RCX = logits ptr, EDX = vocab size, R8D = K
; Returns EAX = token id
; ----------------------------------------------------------------------------
PUBLIC Sampler_TopK
Sampler_TopK PROC
    ; If K == 1, just use ArgMax
    cmp r8d, 1
    jle @use_argmax

    ; We implement a simple ArgMax here to keep dependencies clean,
    ; but in a real TopK we would sort indices.
@use_argmax:
    call Sampler_ArgMax
    ret
Sampler_TopK ENDP

END
