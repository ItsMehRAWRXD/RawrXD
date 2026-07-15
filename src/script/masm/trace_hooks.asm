; RawrXD-Script Execution Trace Hooks (MASM Side)
; Called from interpreter to record execution traces
; These functions bridge MASM execution back to C++ validator

; ============================================================================
; EXTERN DECLARATIONS (C++ callbacks)
; ============================================================================

EXTERN Trace_Begin:PROC
EXTERN Trace_BeforeInstruction:PROC
EXTERN Trace_AfterInstruction:PROC
EXTERN Trace_End:PROC
EXTERN Trace_Exception:PROC

; ============================================================================
; TRACE CONFIGURATION
; ============================================================================

; Enable/disable tracing at assemble time
RAWRXD_TRACE_ENABLED EQU 1

; ============================================================================
; TRACE STATE (per-thread)
; ============================================================================

.data
ALIGN 8

; Current trace entry being built
g_trace_pc              DWORD 0
g_trace_opcode          BYTE 0
g_trace_raw_instr       QWORD 0
g_trace_reg_before      QWORD 16 DUP(0)  ; 16 registers
g_trace_arena_before    QWORD 0
g_trace_ic_slot           DWORD 0

; Trace statistics
g_trace_instruction_count QWORD 0
g_trace_ic_hit_count      QWORD 0
g_trace_ic_miss_count     QWORD 0

; ============================================================================
; TRACE MACROS
; ============================================================================

; Macro: Begin trace for a test
; Usage: TRACE_BEGIN "test_name"
TRACE_BEGIN MACRO testNameStr
    IF RAWRXD_TRACE_ENABLED
        LOCAL str_label
        .data
        str_label BYTE testNameStr, 0
        .code
        lea     rcx, str_label
        call    Trace_Begin
    ENDIF
ENDM

; Macro: Record instruction execution
; Must be called at instruction boundary with:
;   rbx = PC (instruction index)
;   al = opcode
;   instruction loaded in memory at [rsi + rbx*4]
TRACE_RECORD_INSTRUCTION MACRO
    IF RAWRXD_TRACE_ENABLED
        push    rax
        push    rcx
        push    rdx
        push    r8
        push    r9
        push    r10
        push    r11
        
        ; Save current state
        mov     g_trace_pc, ebx
        mov     g_trace_opcode, al
        
        ; Load raw instruction
        mov     eax, DWORD PTR [rsi + rbx*4]
        mov     g_trace_raw_instr, rax
        
        ; Call C++ callback
        ; rcx = pc
        ; rdx = opcode
        ; r8 = raw instruction
        ; r9 = pointer to registers
        mov     ecx, ebx                    ; pc
        movzx   edx, g_trace_opcode         ; opcode
        mov     r8, g_trace_raw_instr       ; raw instruction
        lea     r9, g_trace_reg_before      ; registers (simplified)
        mov     QWORD PTR [r9], r8          ; Store v0
        mov     QWORD PTR [r9+8], r9        ; Store v1
        mov     QWORD PTR [r9+16], r10      ; Store v2
        mov     QWORD PTR [r9+24], r11      ; Store v3
        
        mov     r10, REG_ARENA_BASE
        mov     g_trace_arena_before, r10
        lea     r10, g_trace_arena_before
        mov     QWORD PTR [rsp+32], r10     ; 5th arg on stack
        
        sub     rsp, 40                     ; Shadow space + alignment
        call    Trace_BeforeInstruction
        add     rsp, 40
        
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdx
        pop     rcx
        pop     rax
    ENDIF
ENDM

; Macro: Complete instruction trace after execution
; Records register changes and IC state
TRACE_COMPLETE_INSTRUCTION MACRO
    IF RAWRXD_TRACE_ENABLED
        push    rax
        push    rcx
        push    rdx
        push    r8
        push    r9
        
        ; Build register array
        lea     rcx, g_trace_reg_before
        mov     QWORD PTR [rcx], r8         ; v0
        mov     QWORD PTR [rcx+8], r9       ; v1
        mov     QWORD PTR [rcx+16], r10     ; v2
        mov     QWORD PTR [rcx+24], r11     ; v3
        
        ; rcx = registers pointer
        ; rdx = arena bump
        ; r8 = ic slot
        ; r9 = ic state
        mov     rdx, REG_BUMP
        mov     r8d, g_trace_ic_slot
        xor     r9d, r9d                    ; IC state (simplified)
        
        sub     rsp, 40
        call    Trace_AfterInstruction
        add     rsp, 40
        
        ; Update statistics
        inc     g_trace_instruction_count
        
        pop     r9
        pop     r8
        pop     rdx
        pop     rcx
        pop     rax
    ENDIF
ENDM

; Macro: Record IC hit
TRACE_IC_HIT MACRO
    IF RAWRXD_TRACE_ENABLED
        inc     g_trace_ic_hit_count
    ENDIF
ENDM

; Macro: Record IC miss
TRACE_IC_MISS MACRO
    IF RAWRXD_TRACE_ENABLED
        inc     g_trace_ic_miss_count
    ENDIF
ENDM

; Macro: End trace
TRACE_END MACRO
    IF RAWRXD_TRACE_ENABLED
        push    rcx
        
        ; rcx = final result (in r8/v0)
        mov     rcx, r8
        sub     rsp, 40
        call    Trace_End
        add     rsp, 40
        
        pop     rcx
    ENDIF
ENDM

; Macro: Record exception
; Usage: TRACE_EXCEPTION "message"
TRACE_EXCEPTION MACRO msgStr
    IF RAWRXD_TRACE_ENABLED
        LOCAL msg_label
        .data
        msg_label BYTE msgStr, 0
        .code
        
        push    rcx
        push    rdx
        
        mov     ecx, g_trace_pc             ; pc where exception occurred
        lea     rdx, msg_label              ; message
        
        sub     rsp, 40
        call    Trace_Exception
        add     rsp, 40
        
        pop     rdx
        pop     rcx
    ENDIF
ENDM

; ============================================================================
; DISPATCH WITH TRACING
; ============================================================================
; Modified dispatch loop that records each instruction

; Standard dispatch (no tracing)
DISPATCH MACRO
    movzx   eax, BYTE PTR [rsi + rbx*4]   ; Load opcode
    jmp     QWORD PTR [dispatch_table + rax*8]
ENDM

; Traced dispatch
DISPATCH_TRACED MACRO
    IF RAWRXD_TRACE_ENABLED
        movzx   eax, BYTE PTR [rsi + rbx*4]   ; Load opcode
        TRACE_RECORD_INSTRUCTION
        jmp     QWORD PTR [dispatch_table + rax*8]
    ELSE
        DISPATCH
    ENDIF
ENDM

; ============================================================================
; OPCODE HANDLER WRAPPER WITH TRACING
; ============================================================================
; Wraps each opcode handler to complete trace after execution

OPCODE_HANDLER MACRO name, code
    ALIGN 16
    handler_&&name:
        ; Execute opcode logic
        ; ... (actual implementation)
        
        IF RAWRXD_TRACE_ENABLED
            TRACE_COMPLETE_INSTRUCTION
        ENDIF
        
        ; Advance PC and dispatch
        inc     ebx                         ; PC++
        DISPATCH_TRACED
ENDM

; ============================================================================
; EXAMPLE: Traced execution entry point
; ============================================================================

.code
ALIGN 16

; ExecuteBytecode_MASM with tracing support
; See bytecode_contract.inc for calling convention
ExecuteBytecode_MASM_Traced PROC FRAME
    ; Standard prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    .endprolog
    
    ; Save arguments
    mov     REG_GLOBAL, rcx             ; runtime
    mov     REG_CODE_BASE, rdx          ; bytecode
    mov     r15, r8                     ; bytecodeLen (temp)
    mov     r14, r9                     ; result pointer (temp)
    
    ; Initialize VM state
    xor     ebx, ebx                    ; PC = 0
    mov     REG_ARENA_BASE, REG_GLOBAL ; Arena from runtime
    mov     REG_BUMP, 0                 ; Bump = 0
    mov     REG_IC_TABLE, 0             ; IC table (from runtime)
    
    ; Begin trace
    TRACE_BEGIN "ExecuteBytecode"
    
    ; Main dispatch loop
    DISPATCH_TRACED
    
    ; Exit point
    exit_traced:
    TRACE_END
    
    ; Restore and return
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
    
ExecuteBytecode_MASM_Traced ENDP

; ============================================================================
; DISPATCH TABLE (256 entries)
; ============================================================================

.data
ALIGN 64

dispatch_table LABEL QWORD
    REPEAT 256
        QWORD handler_nop               ; Default to nop
    ENDM

.code

; ============================================================================
; OPCODE HANDLERS (minimal set)
; ============================================================================

handler_nop:
    inc     ebx
    DISPATCH_TRACED

handler_halt:
    jmp     exit_traced

handler_load_const:
    ; Load constant from pool
    ; ... implementation
    inc     ebx
    DISPATCH_TRACED

handler_add:
    ; Add two values
    ; ... implementation
    inc     ebx
    DISPATCH_TRACED

; ============================================================================
; END OF TRACE HOOKS
; ============================================================================

END
