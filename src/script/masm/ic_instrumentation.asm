; RawrXD-Script IC Instrumentation
; Tracks IC performance metrics for optimization validation
; This answers: "Is the IC actually helping or just overhead?"
;
; Build Configuration:
;   Define RAWRXD_PROFILE_IC to enable instrumentation
;   Undefine for production builds (zero overhead)

.CODE

; ============================================================================
; Conditional Compilation
; ============================================================================

; RAWRXD_PROFILE_IC equ 1    ; Uncomment to enable profiling

IFDEF RAWRXD_PROFILE_IC
IC_PROFILING_ENABLED EQU 1
ELSE
IC_PROFILING_ENABLED EQU 0
ENDIF

; ============================================================================
; IC Statistics Structure
; ============================================================================
.data
align 8

; Per-slot counters (1024 slots * 4 counters * 8 bytes = 32KB)
IC_STATS_TOTAL_HITS      QWORD 0    ; Total IC hits across all slots
IC_STATS_TOTAL_MISSES    QWORD 0    ; Total IC misses across all slots
IC_STATS_MONOMORPHIC     QWORD 0    ; Monomorphic sites (1 shape)
IC_STATS_POLYMORPHIC     QWORD 0    ; Polymorphic sites (2-4 shapes)
IC_STATS_MEGAMORPHIC     QWORD 0    ; Megamorphic sites (5+ shapes)

; Per-slot detailed stats
IC_SLOT_HITS             QWORD 1024 DUP(0)  ; Hits per slot
IC_SLOT_MISSES           QWORD 1024 DUP(0)  ; Misses per slot
IC_SLOT_SHAPES_SEEN     QWORD 1024 DUP(0)  ; Unique shapes per slot

; Shape transition tracking (simplified)
IC_SHAPE_TRANSITIONS    QWORD 0    ; Number of shape transitions observed

; ============================================================================
; IC Instrumentation Functions
; ============================================================================

; IC_RecordHit - Called on IC hit
; Entry:  rcx = slot index
; Preserves: all registers
IC_RecordHit PROC FRAME
    push rax
    push rbx
    .pushreg rax
    .pushreg rbx
    .endprolog
    
IF IC_PROFILING_ENABLED
    ; Validate slot index
    cmp ecx, 1024
    jae .done
    
    ; Increment total hits
    inc qword ptr [IC_STATS_TOTAL_HITS]
    
    ; Increment per-slot hits
    mov rbx, rcx
    shl rbx, 3                            ; * 8 bytes per counter
    inc qword ptr [IC_SLOT_HITS + rbx]
ENDIF
    
.done:
    pop rbx
    pop rax
    ret
IC_RecordHit ENDP

; IC_RecordMiss - Called on IC miss
; Entry:  rcx = slot index
;         rdx = new shape pointer
IC_RecordMiss PROC FRAME
    push rax
    push rbx
    push rsi
    .pushreg rax
    .pushreg rbx
    .pushreg rsi
    .endprolog
    
IF IC_PROFILING_ENABLED
    ; Validate slot index
    cmp ecx, 1024
    jae .done
    
    ; Increment total misses
    inc qword ptr [IC_STATS_TOTAL_MISSES]
    
    ; Increment per-slot misses
    mov rbx, rcx
    shl rbx, 3
    inc qword ptr [IC_SLOT_MISSES + rbx]
    
    ; Increment shapes seen for this slot
    inc qword ptr [IC_SLOT_SHAPES_SEEN + rbx]
    
    ; Check if this slot is becoming polymorphic
    mov rax, [IC_SLOT_SHAPES_SEEN + rbx]
    cmp rax, 1
    je .monomorphic
    cmp rax, 5
    jb .polymorphic
    jmp .megamorphic
    
.monomorphic:
    ; First shape - monomorphic
    inc qword ptr [IC_STATS_MONOMORPHIC]
    jmp .done
    
.polymorphic:
    ; 2-4 shapes - polymorphic
    inc qword ptr [IC_STATS_POLYMORPHIC]
    jmp .done
    
.megamorphic:
    ; 5+ shapes - megamorphic (IC becomes useless)
    inc qword ptr [IC_STATS_MEGAMORPHIC]
ENDIF
    
.done:
    pop rsi
    pop rbx
    pop rax
    ret
IC_RecordMiss ENDP

; IC_GetHitRate - Calculate IC hit rate
; Exit:   rax = hit rate as percentage (0-100)
IC_GetHitRate PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    
    mov rax, [IC_STATS_TOTAL_HITS]
    mov rbx, [IC_STATS_TOTAL_MISSES]
    add rbx, rax                            ; rbx = total accesses
    
    test rbx, rbx
    jz .no_data
    
    ; Calculate percentage: (hits * 100) / total
    mov rax, [IC_STATS_TOTAL_HITS]
    mov rcx, 100
    mul rcx                                 ; rax = hits * 100
    div rbx                                 ; rax = percentage
    
    jmp .done
    
.no_data:
    xor rax, rax
    
.done:
    pop rbx
    ret
IC_GetHitRate ENDP

; IC_GetStats - Get all statistics
; Entry:  rcx = pointer to ICStats structure
IC_GetStats PROC FRAME
    push rbx
    push rsi
    push rdi
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .endprolog
    
    mov rdi, rcx                            ; rdi = destination
    
    ; Copy statistics
    mov rax, [IC_STATS_TOTAL_HITS]
    mov [rdi], rax
    
    mov rax, [IC_STATS_TOTAL_MISSES]
    mov [rdi + 8], rax
    
    mov rax, [IC_STATS_MONOMORPHIC]
    mov [rdi + 16], rax
    
    mov rax, [IC_STATS_POLYMORPHIC]
    mov [rdi + 24], rax
    
    mov rax, [IC_STATS_MEGAMORPHIC]
    mov [rdi + 32], rax
    
    ; Calculate hit rate
    call IC_GetHitRate
    mov [rdi + 40], rax
    
    pop rdi
    pop rsi
    pop rbx
    ret
IC_GetStats ENDP

; IC_ResetStats - Reset all counters
IC_ResetStats PROC FRAME
    push rdi
    push rcx
    push rax
    .pushreg rdi
    .pushreg rcx
    .pushreg rax
    .endprolog
    
    ; Clear global counters
    mov qword ptr [IC_STATS_TOTAL_HITS], 0
    mov qword ptr [IC_STATS_TOTAL_MISSES], 0
    mov qword ptr [IC_STATS_MONOMORPHIC], 0
    mov qword ptr [IC_STATS_POLYMORPHIC], 0
    mov qword ptr [IC_STATS_MEGAMORPHIC], 0
    
    ; Clear per-slot counters
    lea rdi, [IC_SLOT_HITS]
    mov rcx, 1024 * 3                       ; 3 arrays * 1024 entries
    xor rax, rax
    rep stosq
    
    pop rax
    pop rcx
    pop rdi
    ret
IC_ResetStats ENDP

; IC_PrintReport - Print IC statistics to console
IC_PrintReport PROC FRAME
    push rbx
    push rsi
    push rdi
    sub rsp, 64
    .allocstack 64
    .endprolog
    
    ; Print header
    lea rcx, ic_report_header
    call RawrXD_OutputLog
    
    ; Print total hits
    mov rdx, [IC_STATS_TOTAL_HITS]
    lea rcx, ic_report_hits
    call RawrXD_OutputLog
    
    ; Print total misses
    mov rdx, [IC_STATS_TOTAL_MISSES]
    lea rcx, ic_report_misses
    call RawrXD_OutputLog
    
    ; Calculate and print hit rate
    call IC_GetHitRate
    mov rdx, rax
    lea rcx, ic_report_rate
    call RawrXD_OutputLog
    
    ; Print site types
    mov rdx, [IC_STATS_MONOMORPHIC]
    lea rcx, ic_report_mono
    call RawrXD_OutputLog
    
    mov rdx, [IC_STATS_POLYMORPHIC]
    lea rcx, ic_report_poly
    call RawrXD_OutputLog
    
    mov rdx, [IC_STATS_MEGAMORPHIC]
    lea rcx, ic_report_mega
    call RawrXD_OutputLog
    
    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    ret
IC_PrintReport ENDP

; ============================================================================
; Data Section - Report Strings
; ============================================================================
.data

ic_report_header    BYTE "=== IC Performance Report ===", 0Dh, 0Ah, 0
ic_report_hits      BYTE "Total Hits:    %llu", 0Dh, 0Ah, 0
ic_report_misses    BYTE "Total Misses:  %llu", 0Dh, 0Ah, 0
ic_report_rate      BYTE "Hit Rate:      %llu%%", 0Dh, 0Ah, 0
ic_report_mono      BYTE "Monomorphic:   %llu sites", 0Dh, 0Ah, 0
ic_report_poly      BYTE "Polymorphic:   %llu sites", 0Dh, 0Ah, 0
ic_report_mega      BYTE "Megamorphic:   %llu sites", 0Dh, 0Ah, 0

; External function
EXTERN RawrXD_OutputLog:PROC

END
