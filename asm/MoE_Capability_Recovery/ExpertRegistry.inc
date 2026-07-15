;==============================================================================
; ExpertRegistry.inc - Semantic Expert ID Mapping for MoE Capability Recovery
;==============================================================================
; Maps numeric expert IDs to human-readable semantic names and capabilities.
; Include this AFTER TraceMacros.inc to get enhanced trace output.
;==============================================================================

;------------------------------------------------------------------------------
; Expert ID Constants (adjust to match your actual expert count)
;------------------------------------------------------------------------------
EXPERT_CORE_0         EQU 0     ; Core reasoning - always active
EXPERT_CORE_1         EQU 1     ; Core reasoning - secondary
EXPERT_CORE_2         EQU 2     ; Core reasoning - tertiary
EXPERT_CORE_3         EQU 3     ; Core reasoning - quaternary

EXPERT_CODE_GEN       EQU 4     ; Code generation specialist
EXPERT_CODE_FIX       EQU 5     ; Code fixing specialist
EXPERT_CODE_OPT       EQU 6     ; Code optimization specialist
EXPERT_CODE_REVIEW    EQU 7     ; Code review specialist

EXPERT_GHOST_0        EQU 8     ; Ghost text - speculative token 0
EXPERT_GHOST_1        EQU 9     ; Ghost text - speculative token 1
EXPERT_GHOST_2        EQU 10    ; Ghost text - speculative token 2
EXPERT_GHOST_3        EQU 11    ; Ghost text - speculative token 3

EXPERT_SWARM_COORD    EQU 12    ; Swarm mode coordinator
EXPERT_SWARM_0        EQU 13    ; Swarm member 0
EXPERT_SWARM_1        EQU 14    ; Swarm member 1
EXPERT_SWARM_2        EQU 15    ; Swarm member 2

EXPERT_PREFETCH_0     EQU 16    ; Prefetch - lookahead 1 token
EXPERT_PREFETCH_1     EQU 17    ; Prefetch - lookahead 2 tokens
EXPERT_PREFETCH_2     EQU 18    ; Prefetch - lookahead 3 tokens
EXPERT_PREFETCH_3     EQU 19    ; Prefetch - lookahead 4 tokens

EXPERT_LATENT_MATH    EQU 20    ; Latent - activates on math expressions
EXPERT_LATENT_CODE    EQU 21    ; Latent - activates on code blocks
EXPERT_LATENT_LANG    EQU 22    ; Latent - activates on foreign language
EXPERT_LATENT_DEBUG   EQU 23    ; Latent - activates on error patterns

EXPERT_SHADOW_0       EQU 24    ; Shadow fallback - low confidence handler
EXPERT_SHADOW_1       EQU 25    ; Shadow fallback - timeout handler
EXPERT_SHADOW_2       EQU 26    ; Shadow fallback - error recovery
EXPERT_SHADOW_3       EQU 27    ; Shadow fallback - safety net

EXPERT_MERGE_AVG      EQU 28    ; Merge - averaging strategy
EXPERT_MERGE_WEIGHT   EQU 29    ; Merge - weighted combination
EXPERT_MERGE_VOTE     EQU 30    ; Merge - voting strategy
EXPERT_MERGE_CONF     EQU 31    ; Merge - confidence-based selection

EXPERT_ECHO_0         EQU 32    ; Echo - refinement iteration 0
EXPERT_ECHO_1         EQU 33    ; Echo - refinement iteration 1
EXPERT_ECHO_2         EQU 34    ; Echo - refinement iteration 2
EXPERT_ECHO_3         EQU 35    ; Echo - refinement iteration 3

EXPERT_SPEC_BRANCH_0  EQU 36    ; Speculative - branch 0
EXPERT_SPEC_BRANCH_1  EQU 37    ; Speculative - branch 1
EXPERT_SPEC_BRANCH_2  EQU 38    ; Speculative - branch 2
EXPERT_SPEC_BRANCH_3  EQU 39    ; Speculative - branch 3

EXPERIMENTAL_0        EQU 40    ; Experimental - undefined behavior
EXPERIMENTAL_1        EQU 41    ; Experimental - undefined behavior
EXPERIMENTAL_2        EQU 42    ; Experimental - undefined behavior
EXPERIMENTAL_3        EQU 43    ; Experimental - undefined behavior

;------------------------------------------------------------------------------
; Expert Name Table (for trace output)
;------------------------------------------------------------------------------
.DATA

ExpertNameTable LABEL QWORD
    QWORD OFFSET ExpertName_Core0
    QWORD OFFSET ExpertName_Core1
    QWORD OFFSET ExpertName_Core2
    QWORD OFFSET ExpertName_Core3
    QWORD OFFSET ExpertName_CodeGen
    QWORD OFFSET ExpertName_CodeFix
    QWORD OFFSET ExpertName_CodeOpt
    QWORD OFFSET ExpertName_CodeReview
    QWORD OFFSET ExpertName_Ghost0
    QWORD OFFSET ExpertName_Ghost1
    QWORD OFFSET ExpertName_Ghost2
    QWORD OFFSET ExpertName_Ghost3
    QWORD OFFSET ExpertName_SwarmCoord
    QWORD OFFSET ExpertName_Swarm0
    QWORD OFFSET ExpertName_Swarm1
    QWORD OFFSET ExpertName_Swarm2
    QWORD OFFSET ExpertName_Prefetch0
    QWORD OFFSET ExpertName_Prefetch1
    QWORD OFFSET ExpertName_Prefetch2
    QWORD OFFSET ExpertName_Prefetch3
    QWORD OFFSET ExpertName_LatentMath
    QWORD OFFSET ExpertName_LatentCode
    QWORD OFFSET ExpertName_LatentLang
    QWORD OFFSET ExpertName_LatentDebug
    QWORD OFFSET ExpertName_Shadow0
    QWORD OFFSET ExpertName_Shadow1
    QWORD OFFSET ExpertName_Shadow2
    QWORD OFFSET ExpertName_Shadow3
    QWORD OFFSET ExpertName_MergeAvg
    QWORD OFFSET ExpertName_MergeWeight
    QWORD OFFSET ExpertName_MergeVote
    QWORD OFFSET ExpertName_MergeConf
    QWORD OFFSET ExpertName_Echo0
    QWORD OFFSET ExpertName_Echo1
    QWORD OFFSET ExpertName_Echo2
    QWORD OFFSET ExpertName_Echo3
    QWORD OFFSET ExpertName_SpecBranch0
    QWORD OFFSET ExpertName_SpecBranch1
    QWORD OFFSET ExpertName_SpecBranch2
    QWORD OFFSET ExpertName_SpecBranch3
    QWORD OFFSET ExpertName_Experimental0
    QWORD OFFSET ExpertName_Experimental1
    QWORD OFFSET ExpertName_Experimental2
    QWORD OFFSET ExpertName_Experimental3

ExpertName_Core0        BYTE "core_reasoning_0", 0
ExpertName_Core1        BYTE "core_reasoning_1", 0
ExpertName_Core2        BYTE "core_reasoning_2", 0
ExpertName_Core3        BYTE "core_reasoning_3", 0
ExpertName_CodeGen      BYTE "code_generation", 0
ExpertName_CodeFix      BYTE "code_fixing", 0
ExpertName_CodeOpt      BYTE "code_optimization", 0
ExpertName_CodeReview   BYTE "code_review", 0
ExpertName_Ghost0       BYTE "ghost_text_0", 0
ExpertName_Ghost1       BYTE "ghost_text_1", 0
ExpertName_Ghost2       BYTE "ghost_text_2", 0
ExpertName_Ghost3       BYTE "ghost_text_3", 0
ExpertName_SwarmCoord   BYTE "swarm_coordinator", 0
ExpertName_Swarm0       BYTE "swarm_member_0", 0
ExpertName_Swarm1       BYTE "swarm_member_1", 0
ExpertName_Swarm2       BYTE "swarm_member_2", 0
ExpertName_Prefetch0    BYTE "prefetch_1token", 0
ExpertName_Prefetch1    BYTE "prefetch_2token", 0
ExpertName_Prefetch2    BYTE "prefetch_3token", 0
ExpertName_Prefetch3    BYTE "prefetch_4token", 0
ExpertName_LatentMath   BYTE "latent_math", 0
ExpertName_LatentCode   BYTE "latent_code", 0
ExpertName_LatentLang   BYTE "latent_language", 0
ExpertName_LatentDebug  BYTE "latent_debug", 0
ExpertName_Shadow0      BYTE "shadow_fallback_lowconf", 0
ExpertName_Shadow1      BYTE "shadow_fallback_timeout", 0
ExpertName_Shadow2      BYTE "shadow_fallback_error", 0
ExpertName_Shadow3      BYTE "shadow_fallback_safety", 0
ExpertName_MergeAvg     BYTE "merge_average", 0
ExpertName_MergeWeight  BYTE "merge_weighted", 0
ExpertName_MergeVote    BYTE "merge_voting", 0
ExpertName_MergeConf    BYTE "merge_confidence", 0
ExpertName_Echo0        BYTE "echo_refinement_0", 0
ExpertName_Echo1        BYTE "echo_refinement_1", 0
ExpertName_Echo2        BYTE "echo_refinement_2", 0
ExpertName_Echo3        BYTE "echo_refinement_3", 0
ExpertName_SpecBranch0  BYTE "speculative_branch_0", 0
ExpertName_SpecBranch1  BYTE "speculative_branch_1", 0
ExpertName_SpecBranch2  BYTE "speculative_branch_2", 0
ExpertName_SpecBranch3  BYTE "speculative_branch_3", 0
ExpertName_Experimental0 BYTE "experimental_0", 0
ExpertName_Experimental1 BYTE "experimental_1", 0
ExpertName_Experimental2 BYTE "experimental_2", 0
ExpertName_Experimental3 BYTE "experimental_3", 0

;------------------------------------------------------------------------------
; Capability Tags (bitmask)
;------------------------------------------------------------------------------
CAP_CORE              EQU 00000001h    ; Core reasoning
CAP_CODE              EQU 00000002h    ; Code-related
CAP_GHOST             EQU 00000004h    ; Ghost text/speculative
CAP_SWARM             EQU 00000008h    ; Swarm mode
CAP_PREFETCH          EQU 00000010h    ; Prefetch/lookahead
CAP_LATENT            EQU 00000020h    ; Latent/conditional
CAP_SHADOW            EQU 00000040h    ; Shadow/fallback
CAP_MERGE             EQU 00000080h    ; Merge/aggregation
CAP_ECHO              EQU 00000100h    ; Echo/refinement
CAP_SPECULATIVE       EQU 00000200h    ; Speculative branching
CAP_EXPERIMENTAL      EQU 00000400h    ; Experimental/unstable

; Capability table (indexed by expert ID)
ExpertCapabilities LABEL DWORD
    DD CAP_CORE                      ; 0: Core0
    DD CAP_CORE                      ; 1: Core1
    DD CAP_CORE                      ; 2: Core2
    DD CAP_CORE                      ; 3: Core3
    DD CAP_CODE                      ; 4: CodeGen
    DD CAP_CODE                      ; 5: CodeFix
    DD CAP_CODE                      ; 6: CodeOpt
    DD CAP_CODE                      ; 7: CodeReview
    DD CAP_GHOST                     ; 8: Ghost0
    DD CAP_GHOST                     ; 9: Ghost1
    DD CAP_GHOST                     ; 10: Ghost2
    DD CAP_GHOST                     ; 11: Ghost3
    DD CAP_SWARM                     ; 12: SwarmCoord
    DD CAP_SWARM                     ; 13: Swarm0
    DD CAP_SWARM                     ; 14: Swarm1
    DD CAP_SWARM                     ; 15: Swarm2
    DD CAP_PREFETCH                  ; 16: Prefetch0
    DD CAP_PREFETCH                  ; 17: Prefetch1
    DD CAP_PREFETCH                  ; 18: Prefetch2
    DD CAP_PREFETCH                  ; 19: Prefetch3
    DD CAP_LATENT                    ; 20: LatentMath
    DD CAP_LATENT                    ; 21: LatentCode
    DD CAP_LATENT                    ; 22: LatentLang
    DD CAP_LATENT                    ; 23: LatentDebug
    DD CAP_SHADOW                    ; 24: Shadow0
    DD CAP_SHADOW                    ; 25: Shadow1
    DD CAP_SHADOW                    ; 26: Shadow2
    DD CAP_SHADOW                    ; 27: Shadow3
    DD CAP_MERGE                     ; 28: MergeAvg
    DD CAP_MERGE                     ; 29: MergeWeight
    DD CAP_MERGE                     ; 30: MergeVote
    DD CAP_MERGE                     ; 31: MergeConf
    DD CAP_ECHO                      ; 32: Echo0
    DD CAP_ECHO                      ; 33: Echo1
    DD CAP_ECHO                      ; 34: Echo2
    DD CAP_ECHO                      ; 35: Echo3
    DD CAP_SPECULATIVE               ; 36: SpecBranch0
    DD CAP_SPECULATIVE               ; 37: SpecBranch1
    DD CAP_SPECULATIVE               ; 38: SpecBranch2
    DD CAP_SPECULATIVE               ; 39: SpecBranch3
    DD CAP_EXPERIMENTAL              ; 40: Experimental0
    DD CAP_EXPERIMENTAL              ; 41: Experimental1
    DD CAP_EXPERIMENTAL              ; 42: Experimental2
    DD CAP_EXPERIMENTAL              ; 43: Experimental3

;------------------------------------------------------------------------------
; Helper Macros
;------------------------------------------------------------------------------

; Get expert name from ID
GET_EXPERT_NAME MACRO expert_id, dest_reg
    IF expert_id LT 44
        lea dest_reg, [ExpertNameTable + expert_id * 8]
        mov dest_reg, QWORD PTR [dest_reg]
    ELSE
        lea dest_reg, [unknown_expert]
    ENDIF
ENDM

; Get capability mask from expert ID
GET_EXPERT_CAPS MACRO expert_id, dest_reg
    IF expert_id LT 44
        mov dest_reg, DWORD PTR [ExpertCapabilities + expert_id * 4]
    ELSE
        xor dest_reg, dest_reg
    ENDIF
ENDM

; Check if expert has specific capability
EXPERT_HAS_CAP MACRO expert_id, cap_mask, dest_reg
    push rax
    GET_EXPERT_CAPS expert_id, eax
    test eax, cap_mask
    IFIDNI <dest_reg>, <rax>
        setnz al
    ELSEIFIDNI <dest_reg>, <eax>
        setnz al
    ELSE
        setnz dest_reg
    ENDIF
    pop rax
ENDM

;------------------------------------------------------------------------------
; Enhanced Trace Macros with Semantic Names
;------------------------------------------------------------------------------

IFDEF RECOVERY_MODE

; Enhanced expert activation trace with semantic name
TRACE_EXPERT_ACTIVATE_NAMED MACRO expert_id, confidence
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
        mov rdx, expert_id            ; Expert ID
        mov r8, confidence            ; Confidence score
        GET_EXPERT_NAME expert_id, r9   ; Semantic name
        call LogExpertEventNamed
        
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

; Trace with capability context
TRACE_EXPERT_WITH_CONTEXT MACRO expert_id, confidence, context
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
        mov rdx, expert_id            ; Expert ID
        mov r8, confidence            ; Confidence
        GET_EXPERT_NAME expert_id, r9   ; Name
        mov r10, context              ; Additional context
        call LogExpertEventContext
        
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

ENDIF  ; RECOVERY_MODE

;------------------------------------------------------------------------------
; Data
;------------------------------------------------------------------------------
.DATA

unknown_expert      BYTE "unknown_expert", 0

;------------------------------------------------------------------------------
; External Functions (add to TraceLogger.asm)
;------------------------------------------------------------------------------
EXTERN LogExpertEventNamed:PROC
EXTERN LogExpertEventContext:PROC

;------------------------------------------------------------------------------
; Capability Name Table (for human-readable output)
;------------------------------------------------------------------------------
CapabilityNames LABEL QWORD
    QWORD OFFSET CapName_Core
    QWORD OFFSET CapName_Code
    QWORD OFFSET CapName_Ghost
    QWORD OFFSET CapName_Swarm
    QWORD OFFSET CapName_Prefetch
    QWORD OFFSET CapName_Latent
    QWORD OFFSET CapName_Shadow
    QWORD OFFSET CapName_Merge
    QWORD OFFSET CapName_Echo
    QWORD OFFSET CapName_Speculative
    QWORD OFFSET CapName_Experimental

CapName_Core        BYTE "core", 0
CapName_Code        BYTE "code", 0
CapName_Ghost       BYTE "ghost", 0
CapName_Swarm       BYTE "swarm", 0
CapName_Prefetch    BYTE "prefetch", 0
CapName_Latent      BYTE "latent", 0
CapName_Shadow      BYTE "shadow", 0
CapName_Merge       BYTE "merge", 0
CapName_Echo        BYTE "echo", 0
CapName_Speculative BYTE "speculative", 0
CapName_Experimental BYTE "experimental", 0

.CODE

;------------------------------------------------------------------------------
; GetCapabilityString - Convert capability mask to string
; RCX = capability mask, RDX = output buffer
;------------------------------------------------------------------------------
GetCapabilityString PROC
    push rbx
    push rdi
    push rsi
    
    mov rdi, rdx        ; Output buffer
    xor rbx, rbx        ; Capability index
    xor rsi, rsi        ; First flag
    
.next_cap:
    mov eax, ecx
    shr eax, ebx
    test eax, 1
    jz .skip
    
    ; Add separator if not first
    test rsi, rsi
    jz .first
    mov BYTE PTR [rdi], '|'
    inc rdi
.first:
    mov rsi, 1
    
    ; Copy capability name
    push rcx
    push rbx
    mov rcx, rbx
    lea rax, [CapabilityNames + rcx * 8]
    mov rsi, QWORD PTR [rax]
    
@@: lodsb
    test al, al
    jz @F
    stosb
    jmp @B
@@: 
    pop rbx
    pop rcx
    
.skip:
    inc ebx
    cmp ebx, 11
    jb .next_cap
    
    mov BYTE PTR [rdi], 0
    
    pop rsi
    pop rdi
    pop rbx
    ret
GetCapabilityString ENDP

END
