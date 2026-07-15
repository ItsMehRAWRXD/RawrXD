;==============================================================================
; SOVEREIGN_MOE.asm - Pure x64 MASM MoE Kernel
; No CRT, no dependencies, no unresolved externals
; Exports C ABI for Sovereign Runtime integration
;==============================================================================

;==============================================================================
; Capability Flags (must match C++ header)
;==============================================================================
MOE_CAP_GHOST       EQU 01h
MOE_CAP_LATENT      EQU 02h
MOE_CAP_SHADOW      EQU 04h
MOE_CAP_SWARM       EQU 08h
MOE_CAP_PREFETCH    EQU 10h
MOE_CAP_ECHO        EQU 20h
MOE_CAP_MERGE       EQU 40h
MOE_CAP_SPECULATIVE EQU 80h

;==============================================================================
; Struct Definitions (C ABI compatible)
;==============================================================================

; MoEExpertInfo - 8 bytes
MoEExpertInfo STRUCT
    id      DWORD ?
    caps    DWORD ?
MoEExpertInfo ENDS

; MoETraceEntry - 12 bytes
MoETraceEntry STRUCT
    expertId    DWORD ?
    confidence  DWORD ?
    caps        DWORD ?
MoETraceEntry ENDS

; MoETraceBuffer - 4 + 256*12 = 3076 bytes
MoETraceBuffer STRUCT
    count       DWORD ?
    entries     MoETraceEntry 256 DUP(<>)
MoETraceBuffer ENDS

; MoEGenerateInput - 24 bytes (8-byte aligned)
MoEGenerateInput STRUCT
    logits  QWORD ?
    kv      QWORD ?
    token   DWORD ?
    _pad    DWORD ?
MoEGenerateInput ENDS

; MoEGenerateOutput - 12 bytes
MoEGenerateOutput STRUCT
    expertId    DWORD ?
    confidence  DWORD ?
    caps        DWORD ?
MoEGenerateOutput ENDS

; MoEBackendCaps - 12 bytes
MoEBackendCaps STRUCT
    version         DWORD ?
    maxExperts      DWORD ?
    maxTraceEntries DWORD ?
MoEBackendCaps ENDS

;==============================================================================
; Data Section
;==============================================================================

.DATA

; Expert scores (64 experts)
ExpertScores    DWORD 64 DUP(500)    ; Default confidence 500
ExpertCaps      DWORD 64 DUP(0)     ; Capability bitmask per expert

; Recent confidence history (for shadow detection)
RecentConf      DWORD 8 DUP(500)    ; Last 8 confidence scores
RecentConfIndex DWORD 0             ; Circular buffer index

; KV density tracking
KVDensity       DWORD 500           ; Current KV cache density

; Trace buffer
TraceBuf        MoETraceBuffer <>

; Expert jump table (64 entries)
ExpertJumpTable QWORD 64 DUP(0)

; Backend caps
BackendCaps     MoEBackendCaps <1, 64, 256>

;==============================================================================
; Code Section
;==============================================================================

.CODE

;==============================================================================
; Helper: RecordTrace - Add entry to trace buffer
; RCX = expertId, RDX = confidence, R8 = caps
;==============================================================================
RecordTrace PROC
    push rbx
    push rsi
    push rdi
    
    ; Get current count using RIP-relative addressing
    lea rax, TraceBuf
    mov r9d, [rax]
    cmp r9d, 256
    jae @F                      ; Buffer full, skip
    
    ; Calculate entry offset: count * 12
    mov ebx, r9d
    imul ebx, 12
    lea rdi, [rax + rbx + 4]    ; rax = TraceBuf base, +4 to skip count field
    
    ; Store entry
    mov [rdi].MoETraceEntry.expertId, ecx
    mov [rdi].MoETraceEntry.confidence, edx
    mov [rdi].MoETraceEntry.caps, r8d
    
    ; Increment count
    inc r9d
    mov [rax], r9d
    
@@:
    pop rdi
    pop rsi
    pop rbx
    ret
RecordTrace ENDP

;==============================================================================
; Expert Stubs
;==============================================================================

Expert0 PROC
    ; Core reasoning expert
    mov eax, 500        ; Return confidence 500
    ret
Expert0 ENDP

ExpertGhost PROC
    ; Ghost text / speculative expert
    mov eax, 600        ; Higher confidence for ghost
    ret
ExpertGhost ENDP

ExpertSwarm PROC
    ; Swarm / parallel activation expert
    mov eax, 550
    ret
ExpertSwarm ENDP

ExpertLatent PROC
    ; Latent / conditional activation expert
    mov eax, 450
    ret
ExpertLatent ENDP

ExpertShadow PROC
    ; Shadow / fallback routing expert
    mov eax, 400        ; Lower confidence for fallback
    ret
ExpertShadow ENDP

;==============================================================================
; Router - Main routing logic with 6 features
;==============================================================================

Router PROC
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    ; Initialize best expert to 0
    xor r12d, r12d          ; bestExpert = 0
    mov r13d, 500           ; bestScore = 500
    
    ; Feature 1: Confidence-adaptive routing
    ; Scan all 64 experts, find highest score
    xor ecx, ecx            ; i = 0
    lea rbx, ExpertScores   ; RIP-relative
    
@scan_loop:
    cmp ecx, 64
    jae @scan_done
    
    mov eax, [rbx + rcx*4]  ; score = ExpertScores[i]
    cmp eax, r13d           ; if score > bestScore
    jle @next_expert
    
    mov r13d, eax           ; bestScore = score
    mov r12d, ecx           ; bestExpert = i
    
@next_expert:
    inc ecx
    jmp @scan_loop
    
@scan_done:
    
    ; Feature 2: KV-aware ghost trigger
    ; If KVDensity < 200, trigger ghost expert
    lea rax, KVDensity
    mov eax, [rax]
    cmp eax, 200
    jge @check_latent
    
    ; Trigger ghost expert (ID=1)
    mov r12d, 1
    mov r13d, 800           ; High confidence for ghost trigger
    jmp @router_done
    
@check_latent:
    ; Feature 3: Latent unlock on digit token
    ; Check if token is '0'-'9'
    movzx eax, byte ptr [rsp+48]  ; token from stack (simplified)
    cmp al, '0'
    jb @check_shadow
    cmp al, '9'
    ja @check_shadow
    
    ; Trigger latent expert (ID=3)
    mov r12d, 3
    mov r13d, 750
    jmp @router_done
    
@check_shadow:
    ; Feature 4: Shadow fallback detection
    ; Check if 4+ recent confidences < 300
    xor ecx, ecx
    xor edx, edx            ; lowCount = 0
    lea rbx, RecentConf     ; RIP-relative
    
@shadow_check:
    cmp ecx, 8
    jae @shadow_eval
    
    mov eax, [rbx + rcx*4]
    cmp eax, 300
    jge @next_conf
    inc edx
    
@next_conf:
    inc ecx
    jmp @shadow_check
    
@shadow_eval:
    cmp edx, 4
    jb @check_swarm
    
    ; Trigger shadow expert (ID=4)
    mov r12d, 4
    mov r13d, 350
    jmp @router_done
    
@check_swarm:
    ; Feature 5: Entropy swarm trigger
    ; If confidence < 400 AND KV > 600
    cmp r13d, 400
    jge @router_done
    
    lea rax, KVDensity
    mov eax, [rax]
    cmp eax, 600
    jle @router_done
    
    ; Trigger swarm expert (ID=2)
    mov r12d, 2
    mov r13d, 650
    
@router_done:
    ; Update recent confidence buffer
    lea rax, RecentConfIndex
    mov eax, [rax]
    and eax, 7              ; Wrap to 0-7
    lea rbx, RecentConf
    mov [rbx + rax*4], r13d
    inc eax
    mov [rax], eax          ; Update RecentConfIndex
    
    ; Return: R12D = expertId, R13D = confidence
    mov eax, r12d
    mov edx, r13d
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
Router ENDP

;==============================================================================
; Exported Functions (C ABI)
;==============================================================================

;------------------------------------------------------------------------------
; MoE_Initialize - Initialize the MoE system
;------------------------------------------------------------------------------
MoE_Initialize PROC PUBLIC
    push rbx
    push rdi
    
    ; Clear trace buffer using RIP-relative addressing
    lea rdi, TraceBuf
    xor eax, eax
    mov [rdi], eax          ; TraceBuf.count = 0
    add rdi, 4              ; Point to entries
    mov ecx, 256 * 3        ; 256 entries * 3 DWORDs
    rep stosd
    
    ; Initialize expert capabilities using RIP-relative
    lea rbx, ExpertCaps
    
    ; Expert 0: Core
    mov dword ptr [rbx + 0*4], 0
    
    ; Expert 1: Ghost
    mov dword ptr [rbx + 1*4], MOE_CAP_GHOST
    
    ; Expert 2: Swarm
    mov dword ptr [rbx + 2*4], MOE_CAP_SWARM
    
    ; Expert 3: Latent
    mov dword ptr [rbx + 3*4], MOE_CAP_LATENT
    
    ; Expert 4: Shadow
    mov dword ptr [rbx + 4*4], MOE_CAP_SHADOW
    
    ; Initialize jump table using RIP-relative
    lea rbx, ExpertJumpTable
    
    lea rax, Expert0
    mov [rbx + 0*8], rax
    
    lea rax, ExpertGhost
    mov [rbx + 1*8], rax
    
    lea rax, ExpertSwarm
    mov [rbx + 2*8], rax
    
    lea rax, ExpertLatent
    mov [rbx + 3*8], rax
    
    lea rax, ExpertShadow
    mov [rbx + 4*8], rax
    
    pop rdi
    pop rbx
    ret
MoE_Initialize ENDP

;------------------------------------------------------------------------------
; MoE_Generate - Generate output using MoE routing
; RCX = const MoEGenerateInput* in
; RDX = MoEGenerateOutput* out
;------------------------------------------------------------------------------
MoE_Generate PROC PUBLIC
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    ; Save input/output pointers
    mov r14, rcx            ; r14 = in
    mov r15, rdx            ; r15 = out
    
    ; Update KV density from input (simplified)
    mov rax, [r14].MoEGenerateInput.kv
    test rax, rax
    jz @skip_kv
    mov eax, [rax]
    mov [KVDensity], eax
    
@skip_kv:
    ; Call router to select expert
    call Router
    ; Returns: EAX = expertId, EDX = confidence
    
    mov r12d, eax           ; r12d = expertId
    mov r13d, edx           ; r13d = confidence
    
    ; Get expert capabilities
    mov r8d, [ExpertCaps + r12*4]
    
    ; Record trace
    mov ecx, r12d
    mov edx, r13d
    call RecordTrace
    
    ; Fill output struct
    mov [r15].MoEGenerateOutput.expertId, r12d
    mov [r15].MoEGenerateOutput.confidence, r13d
    mov [r15].MoEGenerateOutput.caps, r8d
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
MoE_Generate ENDP

;------------------------------------------------------------------------------
; MoE_GetExpertInfo - Get information about an expert
; RCX = uint32_t id
; RDX = MoEExpertInfo* info
;------------------------------------------------------------------------------
MoE_GetExpertInfo PROC PUBLIC
    push rbx
    
    mov r8, rdx             ; r8 = info
    mov r9d, ecx            ; r9d = id
    
    ; Validate ID
    cmp r9d, 64
    jae @invalid_id
    
    ; Fill info struct
    mov [r8].MoEExpertInfo.id, r9d
    lea rbx, ExpertCaps
    mov eax, [rbx + r9*4]
    mov [r8].MoEExpertInfo.caps, eax
    
    jmp @info_done
    
@invalid_id:
    mov [r8].MoEExpertInfo.id, 0FFFFFFFFh
    mov [r8].MoEExpertInfo.caps, 0
    
@info_done:
    pop rbx
    ret
MoE_GetExpertInfo ENDP

;------------------------------------------------------------------------------
; MoE_GetTrace - Get trace buffer
; RCX = MoETraceBuffer* buf
;------------------------------------------------------------------------------
MoE_GetTrace PROC PUBLIC
    push rsi
    push rdi
    push rcx
    
    ; Copy trace buffer using RIP-relative
    lea rsi, TraceBuf
    mov rdi, rcx
    mov ecx, SIZEOF MoETraceBuffer / 4  ; Copy as DWORDs
    rep movsd
    
    pop rcx
    pop rdi
    pop rsi
    ret
MoE_GetTrace ENDP

;------------------------------------------------------------------------------
; MoE_GetBackendCaps - Get backend capabilities
; RCX = MoEBackendCaps* caps
;------------------------------------------------------------------------------
MoE_GetBackendCaps PROC PUBLIC
    push rsi
    push rdi
    
    lea rsi, BackendCaps    ; RIP-relative
    mov rdi, rcx
    movsd                   ; Copy 3 DWORDs (version, maxExperts, maxTraceEntries)
    movsd
    movsd
    
    pop rdi
    pop rsi
    ret
MoE_GetBackendCaps ENDP

;==============================================================================
; End of file
;==============================================================================

END
