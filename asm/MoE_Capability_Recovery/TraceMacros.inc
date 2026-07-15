;==============================================================================
; TraceMacros.inc - Capability Recovery Tracing for MASM MoE System
;==============================================================================
; Include this in your MoE assembly to trace all expert activations,
; router decisions, and emergent behaviors.
;==============================================================================

; Conditional assembly - only enable when recovering capabilities
IFDEF RECOVERY_MODE
    TRACE_ENABLED EQU 1
ELSE
    TRACE_ENABLED EQU 0
ENDIF

;------------------------------------------------------------------------------
; Core Tracing Macros
;------------------------------------------------------------------------------

; Trace router entry/exit
TRACE_ROUTER_ENTRY MACRO router_id
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        push r10
        push r11
        sub rsp, 32
        
        ; Log router entry with timestamp
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, router_id            ; Router ID
        lea r8, [router_entry_msg]
        call LogRouterEvent
        
        add rsp, 32
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

TRACE_ROUTER_EXIT MACRO router_id, expert_selected
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        push r10
        push r11
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, router_id            ; Router ID
        mov r8, expert_selected       ; Selected expert
        lea r9, [router_exit_msg]
        call LogRouterEvent
        
        add rsp, 32
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace expert activation
TRACE_EXPERT_ACTIVATE MACRO expert_id, confidence
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, expert_id            ; Expert ID
        mov r8, confidence            ; Confidence score (0-1000)
        lea r9, [expert_activate_msg]
        call LogExpertEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace swarm mode (multiple experts)
TRACE_SWARM_MODE MACRO expert_count, swarm_id
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, expert_count           ; Number of experts in swarm
        mov r8, swarm_id              ; Swarm instance ID
        lea r9, [swarm_mode_msg]
        call LogSwarmEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace ghost text (speculative generation)
TRACE_GHOST_TEXT MACRO ghost_token_id, expert_id
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, ghost_token_id       ; Ghost token being generated
        mov r8, expert_id             ; Expert generating it
        lea r9, [ghost_text_msg]
        call LogGhostEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace speculative execution
TRACE_SPECULATIVE MACRO branch_id, confidence
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, branch_id            ; Speculative branch ID
        mov r8, confidence            ; Confidence (0-1000)
        lea r9, [speculative_msg]
        call LogSpeculativeEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace prefetch
TRACE_PREFETCH MACRO expert_id, token_position
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, expert_id            ; Expert being prefetched
        mov r8, token_position        ; Position in sequence
        lea r9, [prefetch_msg]
        call LogPrefetchEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace latent expert activation
TRACE_LATENT_EXPERT MACRO expert_id, trigger_condition
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, expert_id            ; Latent expert ID
        mov r8, trigger_condition     ; What triggered it
        lea r9, [latent_expert_msg]
        call LogLatentEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace shadow routing (fallback)
TRACE_SHADOW_ROUTE MACRO primary_expert, fallback_expert, reason
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        push r10
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, primary_expert       ; Original expert
        mov r8, fallback_expert       ; Fallback expert
        mov r9, reason                ; Reason code
        lea r10, [shadow_route_msg]
        call LogShadowEvent
        
        add rsp, 32
        pop r10
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace merge operations
TRACE_MERGE MACRO branch_count, merge_strategy
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, branch_count         ; Number of branches merged
        mov r8, merge_strategy        ; Strategy used
        lea r9, [merge_msg]
        call LogMergeEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

; Trace echo/refinement
TRACE_ECHO MACRO iteration, expert_id
    IF TRACE_ENABLED
        push rax
        push rcx
        push rdx
        push r8
        push r9
        sub rsp, 32
        
        rdtsc
        shl rdx, 32
        or rax, rdx
        mov rcx, rax                    ; Timestamp
        mov rdx, iteration            ; Echo iteration
        mov r8, expert_id             ; Refining expert
        lea r9, [echo_msg]
        call LogEchoEvent
        
        add rsp, 32
        pop r9
        pop r8
        pop rdx
        pop rcx
        pop rax
    ENDIF
ENDM

;------------------------------------------------------------------------------
; Data Section - Trace Messages
;------------------------------------------------------------------------------
.DATA

router_entry_msg    BYTE "ROUTER_ENTRY", 0
router_exit_msg     BYTE "ROUTER_EXIT", 0
expert_activate_msg BYTE "EXPERT_ACTIVATE", 0
swarm_mode_msg      BYTE "SWARM_MODE", 0
ghost_text_msg      BYTE "GHOST_TEXT", 0
speculative_msg     BYTE "SPECULATIVE", 0
prefetch_msg        BYTE "PREFETCH", 0
latent_expert_msg   BYTE "LATENT_EXPERT", 0
shadow_route_msg    BYTE "SHADOW_ROUTE", 0
merge_msg           BYTE "MERGE", 0
echo_msg            BYTE "ECHO", 0

;------------------------------------------------------------------------------
; External Functions (you need to implement these)
;------------------------------------------------------------------------------
EXTERN LogRouterEvent:PROC
EXTERN LogExpertEvent:PROC
EXTERN LogSwarmEvent:PROC
EXTERN LogGhostEvent:PROC
EXTERN LogSpeculativeEvent:PROC
EXTERN LogPrefetchEvent:PROC
EXTERN LogLatentEvent:PROC
EXTERN LogShadowEvent:PROC
EXTERN LogMergeEvent:PROC
EXTERN LogEchoEvent:PROC

ENDIF  ; RECOVERY_MODE
