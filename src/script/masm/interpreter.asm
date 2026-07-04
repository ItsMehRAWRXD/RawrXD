; RawrXD-Script MASM Interpreter Core
; Phase 2: MASM Interpreter Implementation
; Pure x64 MASM - Zero Dependencies

; ============================================================================
; Register Mapping (as per specification)
; ============================================================================
; rbx  = PC (Program Counter) - bytecode instruction pointer
; rsi  = CODE_BASE - base of current bytecode section
; rdi  = CONST_POOL - constant pool base pointer
; r12  = GLOBAL - global object pointer
; r13  = ARENA_BASE - Sovereign Arena base
; r14  = BUMP - Arena bump allocator offset
; r15  = IC_TABLE - Inline Cache table base
; r8   = v0 - Virtual register 0 (accumulator)
; r9   = v1 - Virtual register 1
; r10  = v2 - Virtual register 2
; r11  = v3 - Virtual register 3
; rax  = SCRATCH - General scratch / return value
; rcx  = ARG0 - First argument / scratch
; rdx  = ARG1 - Second argument / scratch
; rbp  = FRAME - Call frame base pointer
; rsp  = STACK - Hardware stack pointer

; ============================================================================
; NaN-Boxing Constants
; ============================================================================
QNAN_MASK       EQU 0x7FF8000000000000      ; Quiet NaN mask
TAG_INT32       EQU 0x0001000000000000      ; Tag for int32
TAG_BOOL        EQU 0x0002000000000000      ; Tag for boolean
TAG_NULL        EQU 0x0003000000000000      ; Tag for null/undefined
TAG_STRING      EQU 0x0004000000000000      ; Tag for string pointer
TAG_OBJECT      EQU 0x0005000000000000      ; Tag for object pointer
TAG_NATIVE      EQU 0x0006000000000000      ; Tag for native function

JS_NULL         EQU 0x7FF3000000000000      ; Encoded null
JS_UNDEFINED    EQU 0x7FF3000000000001      ; Encoded undefined
JS_TRUE         EQU 0x7FF2000000000001      ; Encoded true
JS_FALSE        EQU 0x7FF2000000000000      ; Encoded false

; ============================================================================
; Bytecode Header Offsets
; ============================================================================
BC_MAGIC        EQU 0                       ; uint32_t magic
BC_VERSION      EQU 4                       ; uint16_t version
BC_FLAGS        EQU 6                       ; uint16_t flags
BC_CODE_OFF     EQU 8                       ; uint32_t code_offset
BC_CODE_SIZE    EQU 12                      ; uint32_t code_size
BC_CONST_OFF    EQU 16                      ; uint32_t const_pool_offset
BC_CONST_COUNT  EQU 20                      ; uint32_t const_pool_count
BC_STR_OFF      EQU 24                      ; uint32_t string_table_offset
BC_STR_SIZE     EQU 28                      ; uint32_t string_table_size
BC_IC_COUNT     EQU 32                      ; uint32_t ic_slot_count
BC_LINE_OFF     EQU 36                      ; uint32_t line_info_offset

; ============================================================================
; Coverage Data Section (for test instrumentation)
; ============================================================================
.data
ALIGN 16

; Opcode coverage bitmap (256 opcodes)
g_opcode_coverage BYTE 256 DUP(0)

; Trace Collector Integration
; Define RAWRXD_TRACE_COLLECTOR=1 to enable execution tracing
IFNDEF RAWRXD_TRACE_COLLECTOR
RAWRXD_TRACE_COLLECTOR EQU 1
ENDIF

IF RAWRXD_TRACE_COLLECTOR
; Trace collector state (mirrors TraceCollector in trace_collector.hpp)
g_trace_collector STRUCT
    fingerprint_low   QWORD 0           ; Lower 64 bits of 128-bit fingerprint
    fingerprint_high  QWORD 0           ; Upper 64 bits of 128-bit fingerprint
    event_count       DWORD 0           ; Number of events recorded
    is_recording      BYTE 0              ; Boolean: is recording active
    reserved          BYTE 3 DUP(0)       ; Padding to 24 bytes
    ; Event buffer (circular, 1024 events max)
    event_buffer      BYTE 1024 * 8 DUP(0)  ; 8 bytes per event
    buffer_head       DWORD 0             ; Write position
    buffer_tail       DWORD 0             ; Read position
    buffer_count      DWORD 0             ; Current event count
    reserved2         DWORD 0               ; Padding
    ; Pattern matching state
    pattern_match_id  DWORD 0             ; Matched pattern ID (0 = none)
    match_confidence  DWORD 0             ; Confidence score (0-100)
g_trace_collector ENDS

ALIGN 16
g_trace_collector_instance g_trace_collector <>

; Export trace collector for C++ integration
PUBLIC g_trace_collector_instance
PUBLIC TraceCollector_Reset
PUBLIC TraceCollector_RecordEvent
PUBLIC TraceCollector_GetFingerprint
PUBLIC TraceCollector_GetEventCount
PUBLIC TraceCollector_IsRecording
PUBLIC TraceCollector_StartRecording
PUBLIC TraceCollector_StopRecording

ENDIF ; RAWRXD_TRACE_COLLECTOR

; IC hit/miss counters (for profiling builds)
; Define RAWRXD_PROFILE_COVERAGE=1 to enable
IFNDEF RAWRXD_PROFILE_COVERAGE
RAWRXD_PROFILE_COVERAGE EQU 0
ENDIF

IF RAWRXD_PROFILE_COVERAGE
g_ic_hit_count    QWORD 0
g_ic_miss_count   QWORD 0
g_total_opcodes   QWORD 0
PUBLIC g_ic_hit_count
PUBLIC g_ic_miss_count
PUBLIC g_total_opcodes
ENDIF ; RAWRXD_PROFILE_COVERAGE

; Export coverage data for C++ integration
PUBLIC g_opcode_coverage

; ============================================================================
; Instruction Format
; [Opcode:8][Dest Reg:4][Src A:4][Src B:4][Reserved:12]
; ============================================================================
; Extract instruction fields
EXTRACT_OPCODE MACRO reg, instr
    movzx reg, byte ptr [instr]             ; Get opcode byte
ENDM

EXTRACT_DST MACRO reg, instr
    movzx reg, byte ptr [instr+1]           ; Get dest register
    and reg, 0x0F                           ; Mask to 4 bits
ENDM

EXTRACT_SRC_A MACRO reg, instr
    movzx reg, byte ptr [instr+1]           ; Get src A
    shr reg, 4                              ; Shift to low nibble
ENDM

EXTRACT_SRC_B MACRO reg, instr
    movzx reg, byte ptr [instr+2]           ; Get src B
    and reg, 0x0F                           ; Mask to 4 bits
ENDM

; ============================================================================
; NaN-Boxing Macros
; ============================================================================

; Check if value is a pointer (needs heap access)
IS_POINTER MACRO value_reg, label_true, label_false
    mov rax, value_reg
    shr rax, 47                             ; Get top 17 bits
    cmp rax, 0x1FFF8                        ; QNaN pattern
    jne label_false
    mov rax, value_reg
    shr rax, 48
    and rax, 0xF
    cmp rax, 4                              ; Tag 4+ = pointer
    jae label_true
    jmp label_false
ENDM

; Extract integer from NaN-boxed value
UNBOX_INT MACRO value_reg, dest_reg
    mov dest_reg, value_reg
    shl dest_reg, 16                        ; Shift out tag and NaN bits
    sar dest_reg, 16                        ; Arithmetic shift back (sign extend)
ENDM

; Box integer into NaN-boxed value
BOX_INT MACRO int_reg, dest_reg
    mov dest_reg, int_reg
    and dest_reg, 0x00007FFFFFFFFFFF        ; Mask to 47 bits
    or dest_reg, 0x7FF9000000000000         ; QNaN + Tag 1
ENDM

; Box boolean
BOX_BOOL MACRO bool_reg, dest_reg
    mov dest_reg, bool_reg
    and dest_reg, 1                         ; Ensure 0 or 1
    or dest_reg, 0x7FF2000000000000         ; QNaN + Tag 2
ENDM

; ============================================================================
; Arena Allocation Macro
; Entry: rcx = size (bytes)
; Exit:  rax = allocated pointer (16-byte aligned, or null if OOM)
; ============================================================================
ARENA_ALLOC MACRO
    LOCAL commit_more, oom, done
    
    ; Ensure 16-byte alignment for SSE operations (MOVAPS safety)
    mov rax, rcx
    add rax, 15
    and rax, -16                            ; Round up to 16 bytes
    mov rcx, rax
    
    ; Also ensure current bump is 16-byte aligned
    mov rax, r14
    add rax, 15
    and rax, -16
    mov r14, rax
    
    mov rax, r14                            ; Current bump (16-byte aligned)
    add rax, rcx                            ; New bump
    
    ; Check arena limit
    mov rdx, [r13 + 8]                      ; SovereignArena.committed
    cmp rax, rdx
    ja commit_more                          ; Need to commit more pages
    
    ; Allocation succeeds
    mov r14, rax                            ; Update bump
    mov rax, r14
    sub rax, rcx                            ; Return start of allocation
    jmp done
    
commit_more:
    ; Commit more virtual memory (simplified - assumes space available)
    ; In full implementation: VirtualAlloc call
    xor rax, rax                            ; Return null for now
    
oom:
    xor rax, rax                            ; Return null
    
done:
ENDM

; ============================================================================
; VM State Structure (for saving/restoring)
; ============================================================================
VMState STRUCT
    saved_rbx   QWORD ?                     ; PC
    saved_rsi   QWORD ?                     ; CODE_BASE
    saved_rdi   QWORD ?                     ; CONST_POOL
    saved_r12   QWORD ?                     ; GLOBAL
    saved_r13   QWORD ?                     ; ARENA_BASE
    saved_r14   QWORD ?                     ; BUMP
    saved_r15   QWORD ?                     ; IC_TABLE
    saved_r8    QWORD ?                     ; v0
    saved_r9    QWORD ?                     ; v1
    saved_r10   QWORD ?                     ; v2
    saved_r11   QWORD ?                     ; v3
    saved_rbp   QWORD ?                     ; FRAME
VMState ENDS

; ============================================================================
; External Imports (from RawrXD runtime)
; ============================================================================
EXTERN RawrXD_OutputLog : PROC
EXTERN RawrXD_IOCP_Schedule : PROC
EXTERN RawrXD_AllocateArena : PROC
EXTERN RawrXD_FreeArena : PROC

; ============================================================================
; Code Section
; ============================================================================
.CODE

ALIGN 16
; ============================================================================
; JsInterpreter_Run - Main interpreter loop
; Entry:  rcx = bytecode base pointer
;         rdx = bytecode size
;         r8  = constant pool base
;         r9  = global object pointer
;         [rsp+40] = arena base
;         [rsp+48] = arena bump
;         [rsp+56] = IC table base
; ============================================================================
JsInterpreter_Run PROC FRAME
    ; Save non-volatile registers
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 40                             ; Shadow space + alignment
    .allocstack 40
    .endprolog
    
    ; Initialize VM state from arguments
    mov rsi, rcx                            ; CODE_BASE = bytecode base
    mov rbx, rcx                            ; PC = start of bytecode
    mov rdi, r8                             ; CONST_POOL = constant pool
    mov r12, r9                             ; GLOBAL = global object
    mov r13, [rsp+40+72]                    ; ARENA_BASE (stack offset + saved regs)
    mov r14, [rsp+48+72]                    ; BUMP
    mov r15, [rsp+56+72]                    ; IC_TABLE
    
    ; Clear virtual registers
    xor r8, r8                              ; v0 = 0
    xor r9, r9                              ; v1 = 0
    xor r10, r10                            ; v2 = 0
    xor r11, r11                            ; v3 = 0
    
    ; Initialize frame pointer
    mov rbp, rsp
    sub rbp, 64                             ; Reserve space for local spill

; ============================================================================
; Coverage Tracking (optional, enabled via RAWRXD_PROFILE_COVERAGE)
; ============================================================================
IFNDEF RAWRXD_PROFILE_COVERAGE
RAWRXD_PROFILE_COVERAGE EQU 0
ENDIF

; ============================================================================
; Main Interpreter Loop
; ============================================================================
ALIGN 16
interpreter_loop:
    ; Fetch opcode and advance PC
    movzx rax, byte ptr [rbx]               ; rax = opcode (0-255)
    inc rbx                                 ; PC++
    
    ; Record opcode coverage (if enabled)
    IF RAWRXD_PROFILE_COVERAGE
        push rax
        push rcx
        mov rcx, OFFSET g_opcode_coverage     ; Coverage bitmap
        mov byte ptr [rcx + rax], 1             ; Mark as executed
        pop rcx
        pop rax
    ENDIF
    
    ; Direct threaded dispatch
    jmp qword ptr [dispatch_table + rax*8]

; ============================================================================
; Dispatch Table (256 entries, 8 bytes each = 2KB)
; ============================================================================
dispatch_table LABEL FWORD
ALIGN 16
    dq offset op_load_const                 ; 0x00
    dq offset op_load_int                   ; 0x01
    dq offset op_load_double                ; 0x02
    dq offset op_load_string                ; 0x03
    dq offset op_load_null                  ; 0x04
    dq offset op_load_undefined             ; 0x05
    dq offset op_load_true                  ; 0x06
    dq offset op_load_false                 ; 0x07
    dq offset op_load_zero                  ; 0x08
    dq offset op_load_one                   ; 0x09
    dq offset op_reserved_0A                ; 0x0A
    dq offset op_reserved_0B                ; 0x0B
    dq offset op_reserved_0C                ; 0x0C
    dq offset op_reserved_0D                ; 0x0D
    dq offset op_reserved_0E                ; 0x0E
    dq offset op_reserved_0F                ; 0x0F
    
    ; Register Movement (0x10-0x1F)
    dq offset op_move                       ; 0x10
    dq offset op_swap                       ; 0x11
    dq offset op_load_reg_0               ; 0x12
    dq offset op_load_reg_1               ; 0x13
    dq offset op_store_reg_0              ; 0x14
    dq offset op_store_reg_1              ; 0x15
    dq offset op_reserved_16              ; 0x16
    dq offset op_reserved_17              ; 0x17
    dq offset op_reserved_18              ; 0x18
    dq offset op_reserved_19              ; 0x19
    dq offset op_reserved_1A              ; 0x1A
    dq offset op_reserved_1B              ; 0x1B
    dq offset op_reserved_1C              ; 0x1C
    dq offset op_reserved_1D              ; 0x1D
    dq offset op_reserved_1E              ; 0x1E
    dq offset op_reserved_1F              ; 0x1F
    
    ; Arithmetic (0x20-0x2F)
    dq offset op_add                        ; 0x20
    dq offset op_sub                        ; 0x21
    dq offset op_mul                        ; 0x22
    dq offset op_div                        ; 0x23
    dq offset op_mod                        ; 0x24
    dq offset op_neg                        ; 0x25
    dq offset op_inc                        ; 0x26
    dq offset op_dec                        ; 0x27
    dq offset op_pow                        ; 0x28
    dq offset op_reserved_29                ; 0x29
    dq offset op_reserved_2A                ; 0x2A
    dq offset op_reserved_2B                ; 0x2B
    dq offset op_reserved_2C                ; 0x2C
    dq offset op_reserved_2D                ; 0x2D
    dq offset op_reserved_2E                ; 0x2E
    dq offset op_reserved_2F                ; 0x2F
    
    ; Bitwise (0x30-0x3F)
    dq offset op_bit_and                    ; 0x30
    dq offset op_bit_or                     ; 0x31
    dq offset op_bit_xor                    ; 0x32
    dq offset op_bit_not                    ; 0x33
    dq offset op_shl                        ; 0x34
    dq offset op_shr                        ; 0x35
    dq offset op_shr_u                      ; 0x36
    dq offset op_reserved_37                ; 0x37
    dq offset op_reserved_38                ; 0x38
    dq offset op_reserved_39                ; 0x39
    dq offset op_reserved_3A                ; 0x3A
    dq offset op_reserved_3B                ; 0x3B
    dq offset op_reserved_3C                ; 0x3C
    dq offset op_reserved_3D                ; 0x3D
    dq offset op_reserved_3E                ; 0x3E
    dq offset op_reserved_3F                ; 0x3F
    
    ; Comparison (0x40-0x4F)
    dq offset op_eq                         ; 0x40
    dq offset op_neq                        ; 0x41
    dq offset op_lt                         ; 0x42
    dq offset op_lte                        ; 0x43
    dq offset op_gt                         ; 0x44
    dq offset op_gte                        ; 0x45
    dq offset op_strict_eq                  ; 0x46
    dq offset op_strict_neq               ; 0x47
    dq offset op_compare                  ; 0x48
    dq offset op_reserved_49                ; 0x49
    dq offset op_reserved_4A                ; 0x4A
    dq offset op_reserved_4B                ; 0x4B
    dq offset op_reserved_4C                ; 0x4C
    dq offset op_reserved_4D                ; 0x4D
    dq offset op_reserved_4E                ; 0x4E
    dq offset op_reserved_4F                ; 0x4F
    
    ; Control Flow (0x50-0x5F)
    dq offset op_jmp                        ; 0x50
    dq offset op_jmp_cond                   ; 0x51
    dq offset op_jmp_not_cond             ; 0x52
    dq offset op_jmp_eq                     ; 0x53
    dq offset op_jmp_neq                    ; 0x54
    dq offset op_jmp_lt                     ; 0x55
    dq offset op_call                       ; 0x56
    dq offset op_call_native                ; 0x57
    dq offset op_return                     ; 0x58
    dq offset op_throw                      ; 0x59
    dq offset op_try_start                  ; 0x5A
    dq offset op_try_end                    ; 0x5B
    dq offset op_enter_scope                ; 0x5C
    dq offset op_exit_scope                 ; 0x5D
    dq offset op_reserved_5E                ; 0x5E
    dq offset op_reserved_5F                ; 0x5F
    
    ; Object Operations (0x60-0x6F)
    dq offset op_get_prop                   ; 0x60
    dq offset op_set_prop                   ; 0x61
    dq offset op_get_elem                   ; 0x62
    dq offset op_set_elem                   ; 0x63
    dq offset op_delete_prop                ; 0x64
    dq offset op_delete_elem                ; 0x65
    dq offset op_in                         ; 0x66
    dq offset op_instanceof                 ; 0x67
    dq offset op_new                        ; 0x68
    dq offset op_typeof                     ; 0x69
    dq offset op_has_own_prop               ; 0x6A
    dq offset op_get_proto                  ; 0x6B
    dq offset op_set_proto                  ; 0x6C
    dq offset op_reserved_6D                ; 0x6D
    dq offset op_reserved_6E                ; 0x6E
    dq offset op_reserved_6F                ; 0x6F
    
    ; Array/Object (0x70-0x7F)
    dq offset op_create_array               ; 0x70
    dq offset op_create_object              ; 0x71
    dq offset op_array_push                 ; 0x72
    dq offset op_array_pop                  ; 0x73
    dq offset op_array_get_len              ; 0x74
    dq offset op_array_set_len              ; 0x75
    dq offset op_object_set                 ; 0x76
    dq offset op_object_get_keys            ; 0x77
    dq offset op_reserved_78                ; 0x78
    dq offset op_reserved_79                ; 0x79
    dq offset op_reserved_7A                ; 0x7A
    dq offset op_reserved_7B                ; 0x7B
    dq offset op_reserved_7C                ; 0x7C
    dq offset op_reserved_7D                ; 0x7D
    dq offset op_reserved_7E                ; 0x7E
    dq offset op_reserved_7F                ; 0x7F
    
    ; Function Operations (0x80-0x8F)
    dq offset op_create_func                ; 0x80
    dq offset op_bind_this                  ; 0x81
    dq offset op_apply                      ; 0x82
    dq offset op_call_method                ; 0x83
    dq offset op_get_closure                ; 0x84
    dq offset op_set_closure               ; 0x85
    dq offset op_reserved_86                ; 0x86
    dq offset op_reserved_87                ; 0x87
    dq offset op_reserved_88                ; 0x88
    dq offset op_reserved_89                ; 0x89
    dq offset op_reserved_8A                ; 0x8A
    dq offset op_reserved_8B                ; 0x8B
    dq offset op_reserved_8C                ; 0x8C
    dq offset op_reserved_8D                ; 0x8D
    dq offset op_reserved_8E                ; 0x8E
    dq offset op_reserved_8F                ; 0x8F
    
    ; Iteration (0x90-0x9F)
    dq offset op_iter_start                 ; 0x90
    dq offset op_iter_next                  ; 0x91
    dq offset op_iter_has_next              ; 0x92
    dq offset op_for_in_start               ; 0x93
    dq offset op_for_in_next                ; 0x94
    dq offset op_for_of_start               ; 0x95
    dq offset op_for_of_next                ; 0x96
    dq offset op_reserved_97                ; 0x97
    dq offset op_reserved_98                ; 0x98
    dq offset op_reserved_99                ; 0x99
    dq offset op_reserved_9A                ; 0x9A
    dq offset op_reserved_9B                ; 0x9B
    dq offset op_reserved_9C                ; 0x9C
    dq offset op_reserved_9D                ; 0x9D
    dq offset op_reserved_9E                ; 0x9E
    dq offset op_reserved_9F                ; 0x9F
    
    ; Async Operations (0xA0-0xAF)
    dq offset op_await                      ; 0xA0
    dq offset op_promise_resolve            ; 0xA1
    dq offset op_promise_reject             ; 0xA2
    dq offset op_async_call                 ; 0xA3
    dq offset op_yield                      ; 0xA4
    dq offset op_yield_star                 ; 0xA5
    dq offset op_reserved_A6                ; 0xA6
    dq offset op_reserved_A7                ; 0xA7
    dq offset op_reserved_A8                ; 0xA8
    dq offset op_reserved_A9                ; 0xA9
    dq offset op_reserved_AA                ; 0xAA
    dq offset op_reserved_AB                ; 0xAB
    dq offset op_reserved_AC                ; 0xAC
    dq offset op_reserved_AD                ; 0xAD
    dq offset op_reserved_AE                ; 0xAE
    dq offset op_reserved_AF                ; 0xAF
    
    ; Optimized (0xB0-0xBF)
    dq offset op_add_int                    ; 0xB0
    dq offset op_sub_int                    ; 0xB1
    dq offset op_mul_int                    ; 0xB2
    dq offset op_inc_local                  ; 0xB3
    dq offset op_dec_local                  ; 0xB4
    dq offset op_get_local                  ; 0xB5
    dq offset op_set_local                  ; 0xB6
    dq offset op_get_global                 ; 0xB7
    dq offset op_set_global                 ; 0xB8
    dq offset op_reserved_B9                ; 0xB9
    dq offset op_reserved_BA                ; 0xBA
    dq offset op_reserved_BB                ; 0xBB
    dq offset op_reserved_BC                ; 0xBC
    dq offset op_reserved_BD                ; 0xBD
    dq offset op_reserved_BE                ; 0xBE
    dq offset op_reserved_BF                ; 0xBF
    
    ; Reserved (0xC0-0xEF)
    REPT 48
        dq offset op_unimplemented
    ENDR
    
    ; Debug (0xF0-0xFF)
    dq offset op_debug_break                ; 0xF0
    dq offset op_debug_log                  ; 0xF1
    dq offset op_assert                     ; 0xF2
    dq offset op_profile_start              ; 0xF3
    dq offset op_profile_end                ; 0xF4
    dq offset op_reserved_F5                ; 0xF5
    dq offset op_reserved_F6                ; 0xF6
    dq offset op_reserved_F7                ; 0xF7
    dq offset op_reserved_F8                ; 0xF8
    dq offset op_reserved_F9                ; 0xF9
    dq offset op_reserved_FA                ; 0xFA
    dq offset op_reserved_FB                ; 0xFB
    dq offset op_reserved_FC                ; 0xFC
    dq offset op_reserved_FD                ; 0xFD
    dq offset op_reserved_FE                ; 0xFE
    dq offset op_nop                        ; 0xFF

; ============================================================================
; Opcode Handlers - Constants (0x00-0x0F)
; ============================================================================

; OP_LOAD_CONST: r_dest = const_pool[idx]
; Encoding: [OP:1][DEST:1][IDX:2]
op_load_const:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    movzx rdx, word ptr [rbx+1]             ; rdx = const pool index
    add rbx, 3                              ; Advance PC
    
    ; Load constant from pool
    mov rax, [rdi + rdx*8]                    ; rax = constant value (NaN-boxed)
    
    ; Store to virtual register
    mov [rbp + rcx*8], rax                    ; Spill to frame
    jmp interpreter_loop

; OP_LOAD_INT: r_dest = immediate_int32
; Encoding: [OP:1][DEST:1][INT32:4]
op_load_int:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    movsxd rdx, dword ptr [rbx+1]           ; rdx = int32 (sign extended)
    add rbx, 5                              ; Advance PC
    
    ; Box the integer
    BOX_INT rdx, rax
    
    ; Store to virtual register
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_STRING: r_dest = string_table[idx]
; Encoding: [OP:1][DEST:1][IDX:2]
op_load_string:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    movzx rdx, word ptr [rbx+1]             ; rdx = string table index
    add rbx, 3                              ; Advance PC
    
    ; Load string pointer from string table
    ; String table is at r13 + string_table_offset
    ; For now: create NaN-boxed string pointer
    mov rax, [r13 + rdx*8]                  ; rax = string pointer
    or rax, TAG_STRING                      ; Tag as string
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_NULL: r_dest = null
op_load_null:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx                                 ; Advance PC
    
    mov rax, JS_NULL
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_UNDEFINED: r_dest = undefined
op_load_undefined:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx                                 ; Advance PC
    
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_TRUE: r_dest = true
op_load_true:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx                                 ; Advance PC
    
    mov rax, JS_TRUE
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_FALSE: r_dest = false
op_load_false:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx                                 ; Advance PC
    
    mov rax, JS_FALSE
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_ZERO: r_dest = 0 (optimization)
op_load_zero:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx                                 ; Advance PC
    
    mov rax, 0x7FF9000000000000             ; Boxed 0
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_ONE: r_dest = 1 (optimization)
op_load_one:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx                                 ; Advance PC
    
    mov rax, 0x7FF9000000000001             ; Boxed 1
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; Opcode Handlers - Arithmetic (0x20-0x2F)
; ============================================================================

; OP_ADD: r_dest = r_left + r_right
op_add:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = src A
    movzx rsi, byte ptr [rbx+2]             ; rsi = src B (shifted)
    and rsi, 0x0F
    add rbx, 3                              ; Advance PC
    
    ; Load operands
    mov rax, [rbp + rdx*8]                  ; rax = left
    mov r8, [rbp + rsi*8]                   ; r8 = right
    
    ; Check if both are integers (fast path)
    mov r9, 0x7FF9000000000000
    and rax, r9
    cmp rax, r9
    jne .add_slow
    
    mov rax, [rbp + rdx*8]                  ; Reload left
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .add_slow
    
    ; Integer fast path
    mov rax, [rbp + rdx*8]
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    add rax, r8
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
    
add_slow:
    ; Full JS add semantics
    ; Check if either operand is a string (string concatenation)
    mov r9, 0x7FF4000000000000              ; String tag mask
    mov r10, rax
    and r10, r9
    cmp r10, r9
    je .add_string_concat
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    je .add_string_concat
    
    ; Check for doubles
    mov r9, 0x7FF8000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .add_is_double_a
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .add_is_double_b
    
    ; Both are integers - overflow check
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    add rax, r8
    
    ; Check for overflow (result fits in 32-bit signed)
    cmp rax, 2147483647
    jg .add_overflow
    cmp rax, -2147483648
    jl .add_overflow
    
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
    
add_overflow:
    ; Convert to double and add
    cvtsi2sd xmm0, rax
    movsd [rbp + rcx*8 - 8], xmm0
    jmp interpreter_loop
    
add_is_double_a:
    ; First operand is double
    movsd xmm0, [rax - 0x7FF8000000000000]  ; Extract double
    ; Convert second to double
    UNBOX_INT r8, r8
    cvtsi2sd xmm1, r8
    addsd xmm0, xmm1
    movsd [rbp + rcx*8 - 8], xmm0
    jmp interpreter_loop
    
add_is_double_b:
    ; Second operand is double
    movsd xmm1, [r8 - 0x7FF8000000000000]   ; Extract double
    ; Convert first to double
    UNBOX_INT rax, rax
    cvtsi2sd xmm0, rax
    addsd xmm0, xmm1
    movsd [rbp + rcx*8 - 8], xmm0
    jmp interpreter_loop
    
add_string_concat:
    ; String concatenation - call runtime
    sub rsp, 32
    mov rcx, rax                            ; First string
    mov rdx, r8                             ; Second string
    mov r8, r13                             ; Arena base
    mov r9, r14                             ; Arena bump
    call JsString_Concat
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_SUB: r_dest = r_left - r_right
op_sub:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .sub_slow
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .sub_slow
    
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    sub rax, r8
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
    
sub_slow:
    ; Slow path: convert to doubles and subtract
    UNBOX_INT rax, rax
    cvtsi2sd xmm0, rax
    UNBOX_INT r8, r8
    cvtsi2sd xmm1, r8
    subsd xmm0, xmm1
    movsd [rbp + rcx*8 - 8], xmm0
    jmp interpreter_loop

; OP_MUL: r_dest = r_left * r_right
op_mul:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .mul_slow
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .mul_slow
    
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    imul rax, r8
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
    
mul_slow:
    ; Slow path: convert to doubles and multiply
    UNBOX_INT rax, rax
    cvtsi2sd xmm0, rax
    UNBOX_INT r8, r8
    cvtsi2sd xmm1, r8
    mulsd xmm0, xmm1
    movsd [rbp + rcx*8 - 8], xmm0
    jmp interpreter_loop

; OP_DIV: r_dest = r_left / r_right
op_div:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]                  ; rax = left
    mov r8, [rbp + rsi*8]                   ; r8 = right
    
    ; Check for division by zero
    cmp r8, 0x7FF9000000000000              ; Boxed 0
    je .div_by_zero
    cmp r8, JS_NULL
    je .div_by_zero
    cmp r8, JS_UNDEFINED
    je .div_undefined
    
    ; Check if both are integers
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .div_double
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .div_double
    
    ; Integer division
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    
    ; Check for exact division
    mov r9, rax
    mov r10, r8
    mov rax, r9
    cqo                                     ; Sign extend rax into rdx:rax
    idiv r8d                                ; Signed divide
    
    ; Check if remainder is 0
    test edx, edx
    jnz .div_result_double                  ; Has remainder, convert to double
    
    ; Exact integer result
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
    
div_result_double:
    ; Convert to double and divide
    cvtsi2sd xmm0, r9                       ; Left
    cvtsi2sd xmm1, r10                      ; Right
    divsd xmm0, xmm1
    movsd [rbp + rcx*8 - 8], xmm0
    jmp interpreter_loop
    
div_double:
    ; Double division
    sub rsp, 8
    movsd xmm0, [rax - 0x7FF8000000000000]  ; Extract left double
    movsd xmm1, [r8 - 0x7FF8000000000000]   ; Extract right double
    divsd xmm0, xmm1
    movsd [rbp + rcx*8 - 8], xmm0
    add rsp, 8
    jmp interpreter_loop
    
div_by_zero:
    ; Division by zero returns Infinity or -Infinity
    mov rax, 0x7FF0000000000000             ; +Infinity
    mov [rbp + rcx*8 - 8], rax
    jmp interpreter_loop
    
div_undefined:
    ; 0 / 0 or undefined operand returns NaN
    mov rax, 0x7FF8000000000000             ; NaN
    mov [rbp + rcx*8 - 8], rax
    jmp interpreter_loop

; OP_NEG: r_dest = -r_src
op_neg:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = src
    add rbx, 2                              ; Advance PC
    
    mov rax, [rbp + rdx*8]                  ; rax = value
    
    ; Check if integer
    mov r9, 0x7FF9000000000000
    mov r8, rax
    and r8, r9
    cmp r8, r9
    jne .neg_slow
    
    ; Integer negation
    UNBOX_INT rax, rax
    neg rax
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
    
neg_slow:
    ; Slow path: negate as double
    movsd xmm0, [rax - 0x7FF8000000000000]  ; Extract double
    xorpd xmm1, xmm1                        ; xmm1 = 0
    subsd xmm1, xmm0                        ; xmm1 = 0 - xmm0
    movsd [rbp + rcx*8 - 8], xmm1
    jmp interpreter_loop

; ============================================================================
; Opcode Handlers - Comparison (0x40-0x4F)
; ============================================================================

; OP_EQ: r_dest = r_left == r_right (loose equality)
op_eq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Fast path: same value
    cmp rax, r8
    sete al
    movzx rax, al
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LT: r_dest = r_left < r_right
op_lt:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .lt_slow
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .lt_slow
    
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    xor r9, r9
    cmp rax, r8
    setl r9b
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop
    
lt_slow:
    ; Slow path: convert to doubles and compare
    movsd xmm0, [rax - 0x7FF8000000000000]  ; Extract left double
    movsd xmm1, [r8 - 0x7FF8000000000000]  ; Extract right double
    xor r9, r9
    comisd xmm0, xmm1
    setb r9b                                ; Set if below (xmm0 < xmm1)
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop

; ============================================================================
; Opcode Handlers - Control Flow (0x50-0x5F)
; ============================================================================

; OP_JMP: pc += offset
op_jmp:
    movsxd rax, dword ptr [rbx]             ; rax = signed 32-bit offset
    add rbx, 4                              ; Advance past instruction
    add rbx, rax                            ; Jump
    jmp interpreter_loop

; OP_JMP_COND: if (r_cond) pc += offset
op_jmp_cond:
    movzx rcx, byte ptr [rbx]               ; rcx = condition register
    movsxd rdx, dword ptr [rbx+1]           ; rdx = offset
    add rbx, 5                              ; Advance PC
    
    mov rax, [rbp + rcx*8]                  ; rax = condition value
    
    ; Check if truthy
    cmp rax, JS_FALSE
    je .no_jump_cond
    cmp rax, JS_NULL
    je .no_jump_cond
    cmp rax, JS_UNDEFINED
    je .no_jump_cond
    cmp rax, 0x7FF9000000000000             ; Boxed 0
    je .no_jump_cond
    
    ; Jump
    add rbx, rdx
    
no_jump_cond:
    jmp interpreter_loop

; OP_RETURN: return r_val
op_return:
    movzx rcx, byte ptr [rbx]               ; rcx = value register
    inc rbx
    
    mov rax, [rbp + rcx*8]                  ; rax = return value
    
    ; Restore and return
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

; OP_NOP: no operation
op_nop:
    inc rbx
    jmp interpreter_loop

; ============================================================================
; Opcode Handlers - Object Operations (0x60-0x6F)
; ============================================================================

; OP_GET_PROP: r_dest = r_obj.property (with IC)
; Encoding: [OP:1][DEST:1][OBJ:1][PAD:1][STRING_IDX:4][IC_SLOT:4]
op_get_prop:
    movzx rcx, byte ptr [rbx]               ; rcx = dest reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = obj reg
    add rbx, 2
    movzx rsi, dword ptr [rbx]              ; rsi = string_idx
    movzx rdi, dword ptr [rbx+4]            ; rdi = ic_slot
    add rbx, 8
    
    ; Get object from register
    mov r8, [rbp + rdx*8]                   ; r8 = object (NaN-boxed)
    
    ; Check if pointer
    IS_POINTER r8, .get_prop_object, .get_prop_slow
    
get_prop_object:
    ; Full property access with inline caching
    ; r8 = object pointer (unboxed)
    ; rsi = string_idx (property name constant pool index)
    ; rdi = ic_slot (inline cache slot index)
    
    ; Get object shape
    mov r9, [r8]                            ; r9 = object->shape
    
    ; Check IC: compare shape to cached shape
    mov r10, [r15 + rdi*16]                 ; r10 = IC->cached_shape
    cmp r9, r10
    jne .get_prop_ic_miss
    
    ; IC hit: direct property access
    mov r11, [r15 + rdi*16 + 8]             ; r11 = IC->cached_offset
    mov rax, [r8 + r11]                     ; rax = object->slots[offset]
    mov [rbp + rcx*8], rax                  ; Store to destination register
    jmp interpreter_loop
    
get_prop_ic_miss:
    ; IC miss: need to look up property in shape
    ; r8 = object, r9 = shape, rsi = prop name index
    
    ; Get property name from constant pool
    mov rax, [r13 + rsi*8]                  ; rax = property name string
    
    ; Search shape property table
    movzx r10, word ptr [r9 + 4]            ; r10 = shape->prop_count
    test r10, r10
    jz .get_prop_not_found
    
    lea r11, [r9 + 16]                      ; r11 = shape->prop_table
    xor r12, r12                            ; r12 = current index
    
get_prop_search_loop:
    cmp r12, r10
    jae .get_prop_not_found
    
    mov r14, [r11 + r12*8]                  ; r14 = prop_table[i].name
    cmp r14, rax
    je .get_prop_found
    
    inc r12
    jmp .get_prop_search_loop
    
get_prop_found:
    ; Found property - get offset
    movzx r14, word ptr [r11 + r12*8 + 8]   ; r14 = prop_table[i].offset
    
    ; Update IC
    mov [r15 + rdi*16], r9                  ; IC->shape = current shape
    mov [r15 + rdi*16 + 8], r14             ; IC->offset = property offset
    
    ; Load property value
    mov rax, [r8 + r14]                     ; rax = object->slots[offset]
    mov [rbp + rcx*8], rax                  ; Store to destination
    jmp interpreter_loop
    
get_prop_not_found:
    ; Property not found - check prototype chain
    mov rax, [r9 + 8]                       ; rax = shape->prototype
    test rax, rax
    jz .get_prop_return_undefined
    
    ; Search prototype chain (simplified - just return undefined for now)
    jmp .get_prop_return_undefined
    
get_prop_return_undefined:
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
    
get_prop_slow:
    ; Full slow path: call runtime
    sub rsp, 32
    mov rcx, r8                             ; object
    mov rdx, [r13 + rsi*8]                  ; property name
    mov r8, r15
    add r8, rdi*16                          ; IC slot
    call JsObject_GetProperty
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_CREATE_OBJECT: r_dest = {}
op_create_object:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx
    
    ; Allocate empty object from arena
    mov rcx, 32                             ; Size of empty object (header only)
    ARENA_ALLOC
    
    ; Initialize object header
    mov qword ptr [rax], 0                  ; shape = null (empty object)
    mov qword ptr [rax + 8], 0              ; prototype = null
    mov qword ptr [rax + 16], 0             ; flags = 0
    mov qword ptr [rax + 24], 0             ; reserved
    
    ; Box and store
    or rax, TAG_OBJECT
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_CREATE_ARRAY: r_dest = []
op_create_array:
    movzx rcx, byte ptr [rbx]               ; rcx = dest register
    inc rbx
    
    ; Allocate array from arena
    mov rcx, 64                             ; Initial array capacity
    ARENA_ALLOC
    
    ; Initialize array header
    mov qword ptr [rax], 0                  ; shape = null (array shape)
    mov qword ptr [rax + 8], 0              ; prototype = Array.prototype
    mov dword ptr [rax + 16], 0             ; length = 0
    mov dword ptr [rax + 20], 16            ; capacity = 16 elements
    mov qword ptr [rax + 24], 0             ; elements pointer (inline)
    
    ; Box and store
    or rax, TAG_OBJECT
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; Opcode Handlers - Debug (0xF0-0xFF)
; ============================================================================

; OP_DEBUG_BREAK: breakpoint
op_debug_break:
    ; Trigger debug break (int 3 in debug builds)
    int 3
    inc rbx
    jmp interpreter_loop

; OP_DEBUG_LOG: console.log(r_val)
op_debug_log:
    movzx rcx, byte ptr [rbx]               ; rcx = value register
    inc rbx
    
    mov rdx, [rbp + rcx*8]                  ; rdx = value to log
    
    ; Call runtime log function
    sub rsp, 32                             ; Shadow space
    mov rcx, rdx                            ; First argument
    call RawrXD_OutputLog
    add rsp, 32
    
    jmp interpreter_loop

; ============================================================================
; Bitwise Operations (0x30-0x3F)
; ============================================================================

; OP_BIT_AND: r_dest = r_left & r_right
op_bit_and:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    ; Convert to int32 and AND
    call JsValue_ToInt32
    mov r9d, eax
    mov rcx, r8
    call JsValue_ToInt32
    and r9d, eax
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_BIT_OR: r_dest = r_left | r_right
op_bit_or:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    call JsValue_ToInt32
    mov r9d, eax
    mov rcx, r8
    call JsValue_ToInt32
    or r9d, eax
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_BIT_XOR: r_dest = r_left ^ r_right
op_bit_xor:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    call JsValue_ToInt32
    mov r9d, eax
    mov rcx, r8
    call JsValue_ToInt32
    xor r9d, eax
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_BIT_NOT: r_dest = ~r_src
op_bit_not:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov rax, [rbp + rdx*8]
    call JsValue_ToInt32
    not eax
    mov rcx, rax
    shl rcx, 32
    or rcx, TAG_INT32
    or rcx, QNAN_MASK
    movzx rax, byte ptr [rbx-2]
    mov [rbp + rax*8], rcx
    jmp interpreter_loop

; OP_SHL: r_dest = r_left << r_right
op_shl:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    call JsValue_ToInt32
    mov r9d, eax
    mov rcx, r8
    call JsValue_ToInt32
    and eax, 0x1F
    shl r9d, eax
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_SHR: r_dest = r_left >> r_right (signed)
op_shr:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    call JsValue_ToInt32
    mov r9d, eax
    mov rcx, r8
    call JsValue_ToInt32
    and eax, 0x1F
    sar r9d, eax
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_SHR_U: r_dest = r_left >>> r_right (unsigned)
op_shr_u:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    call JsValue_ToInt32
    mov r9d, eax
    mov rcx, r8
    call JsValue_ToInt32
    and eax, 0x1F
    shr r9d, eax
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; String & Data Operations
; ============================================================================

; OP_LOAD_STRING: r_dest = string_table[idx]
op_load_string:
    movzx rcx, byte ptr [rbx]
    movzx rdx, word ptr [rbx+1]
    add rbx, 3
    mov rax, [rdi + rdx*8]
    or rax, TAG_STRING
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LOAD_DOUBLE: r_dest = const_pool[idx] (double)
op_load_double:
    movzx rcx, byte ptr [rbx]
    movzx rdx, word ptr [rbx+1]
    add rbx, 3
    movsd xmm0, [rdi + rdx*8]
    movsd [rbp + rcx*8 - 8], xmm0
    jmp interpreter_loop

; OP_MOVE: r_dest = r_src
op_move:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov rax, [rbp + rdx*8]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_SWAP: swap r_a, r_b
op_swap:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov rax, [rbp + rcx*8]
    mov r8, [rbp + rdx*8]
    mov [rbp + rcx*8], r8
    mov [rbp + rdx*8], rax
    jmp interpreter_loop

; ============================================================================
; Arithmetic Extensions
; ============================================================================

; OP_MOD: r_dest = r_left % r_right
op_mod:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .mod_slow
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .mod_slow
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    test r8, r8
    jz .mod_nan
    xor edx, edx
    idiv r8d
    BOX_INT rdx, rdx
    mov [rbp + rcx*8], rdx
    jmp interpreter_loop
mod_nan:
    mov rax, 0x7FF8000000000000
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
mod_slow:
    jmp interpreter_loop

; OP_INC: r_dest = r_src + 1
op_inc:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov rax, [rbp + rdx*8]
    mov r9, 0x7FF9000000000000
    mov r8, rax
    and r8, r9
    cmp r8, r9
    jne .inc_slow
    UNBOX_INT rax, rax
    inc rax
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
inc_slow:
    jmp interpreter_loop

; OP_DEC: r_dest = r_src - 1
op_dec:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov rax, [rbp + rdx*8]
    mov r9, 0x7FF9000000000000
    mov r8, rax
    and r8, r9
    cmp r8, r9
    jne .dec_slow
    UNBOX_INT rax, rax
    dec rax
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
dec_slow:
    jmp interpreter_loop

; OP_POW: r_dest = r_left ** r_right
op_pow:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    sub rsp, 32
    mov rcx, [rbp + rdx*8]
    mov rdx, [rbp + rsi*8]
    call JsMath_Pow
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; Comparison Operations
; ============================================================================

; OP_NEQ: r_dest = r_left != r_right (loose)
op_neq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    cmp rax, r8
    setne al
    movzx rax, al
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_LTE: r_dest = r_left <= r_right
op_lte:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .lte_slow
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .lte_slow
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    xor r9, r9
    cmp rax, r8
    setle r9b
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop
lte_slow:
    ; Slow path: convert to doubles and compare
    movsd xmm0, [rax - 0x7FF8000000000000]  ; Extract left double
    movsd xmm1, [r8 - 0x7FF8000000000000]   ; Extract right double
    xor r9, r9
    comisd xmm0, xmm1
    setbe r9b                               ; Set if below or equal (xmm0 <= xmm1)
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop

; OP_GT: r_dest = r_left > r_right
op_gt:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .gt_slow
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .gt_slow
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    xor r9, r9
    cmp rax, r8
    setg r9b
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop
gt_slow:
    ; Slow path: convert to doubles and compare
    movsd xmm0, [rax - 0x7FF8000000000000]  ; Extract left double
    movsd xmm1, [r8 - 0x7FF8000000000000]   ; Extract right double
    xor r9, r9
    comisd xmm0, xmm1
    seta r9b                                ; Set if above (xmm0 > xmm1)
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop

; OP_GTE: r_dest = r_left >= r_right
op_gte:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .gte_slow
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .gte_slow
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    xor r9, r9
    cmp rax, r8
    setge r9b
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop
gte_slow:
    ; Slow path: convert to doubles and compare
    movsd xmm0, [rax - 0x7FF8000000000000]  ; Extract left double
    movsd xmm1, [r8 - 0x7FF8000000000000]   ; Extract right double
    xor r9, r9
    comisd xmm0, xmm1
    setae r9b                               ; Set if above or equal (xmm0 >= xmm1)
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp interpreter_loop

; OP_STRICT_EQ: r_dest = r_left === r_right
op_strict_eq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    cmp rax, r8
    sete al
    movzx rax, al
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_STRICT_NEQ: r_dest = r_left !== r_right
op_strict_neq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    cmp rax, r8
    setne al
    movzx rax, al
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; Control Flow Extensions
; ============================================================================

; OP_JMP_NOT_COND: if (!r_cond) pc += offset
op_jmp_not_cond:
    movzx rcx, byte ptr [rbx]
    movsxd rdx, dword ptr [rbx+1]
    add rbx, 5
    mov rax, [rbp + rcx*8]
    cmp rax, JS_FALSE
    je .do_jump_not
    cmp rax, JS_NULL
    je .do_jump_not
    cmp rax, JS_UNDEFINED
    je .do_jump_not
    cmp rax, 0x7FF9000000000000
    je .do_jump_not
    jmp interpreter_loop
do_jump_not:
    add rbx, rdx
    jmp interpreter_loop

; OP_JMP_EQ: if (r_left == r_right) pc += offset
op_jmp_eq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movsxd rsi, dword ptr [rbx+2]
    add rbx, 6
    mov rax, [rbp + rcx*8]
    mov r8, [rbp + rdx*8]
    cmp rax, r8
    jne .no_jmp_eq
    add rbx, rsi
no_jmp_eq:
    jmp interpreter_loop

; OP_JMP_NEQ: if (r_left != r_right) pc += offset
op_jmp_neq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movsxd rsi, dword ptr [rbx+2]
    add rbx, 6
    mov rax, [rbp + rcx*8]
    mov r8, [rbp + rdx*8]
    cmp rax, r8
    je .no_jmp_neq
    add rbx, rsi
no_jmp_neq:
    jmp interpreter_loop

; OP_JMP_LT: if (r_left < r_right) pc += offset
op_jmp_lt:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movsxd rsi, dword ptr [rbx+2]
    add rbx, 6
    mov rax, [rbp + rcx*8]
    mov r8, [rbp + rdx*8]
    cmp rax, r8
    jge .no_jmp_lt
    add rbx, rsi
no_jmp_lt:
    jmp interpreter_loop

; ============================================================================
; Function Operations
; ============================================================================

; OP_CALL: r_dest = r_func(r_args...)
op_call:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    sub rsp, 32 + rsi*8
    mov r9, rsi
    mov r10, 0
copy_args:
    cmp r10, r9
    jae .do_call
    movzx eax, byte ptr [rbx + r10]
    mov rax, [rbp + rax*8]
    mov [rsp + 32 + r10*8], rax
    inc r10
    jmp .copy_args
do_call:
    add rbx, rsi
    mov rcx, r8
    mov rdx, rsp
    mov r8, rsi
    mov r9, r12
    call JsFunction_Call
    add rsp, 32 + rsi*8
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_CALL_NATIVE: r_dest = native_func(r_args...)
op_call_native:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    and r8, 0x0000FFFFFFFFFFFF
    sub rsp, 32 + rsi*8
    mov r9, rsi
    mov r10, 0
copy_native_args:
    cmp r10, r9
    jae .do_native_call
    movzx eax, byte ptr [rbx + r10]
    mov rax, [rbp + rax*8]
    mov [rsp + 32 + r10*8], rax
    inc r10
    jmp .copy_native_args
do_native_call:
    add rbx, rsi
    mov rcx, r12
    mov rdx, rsp
    mov r8, rsi
    call r8
    add rsp, 32 + rsi*8
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; Exception Handling
; ============================================================================

; OP_THROW: throw r_val
op_throw:
    movzx rcx, byte ptr [rbx]
    inc rbx
    mov rax, [rbp + rcx*8]
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

; OP_TRY_START: begin try block
op_try_start:
    movsxd rax, dword ptr [rbx]
    add rbx, 4
    jmp interpreter_loop

; OP_TRY_END: end try block
op_try_end:
    inc rbx
    jmp interpreter_loop

; ============================================================================
; Scope Operations
; ============================================================================

; OP_ENTER_SCOPE: enter new variable scope
op_enter_scope:
    inc rbx
    jmp interpreter_loop

; OP_EXIT_SCOPE: exit current scope
op_exit_scope:
    inc rbx
    jmp interpreter_loop

; ============================================================================
; Array Operations
; ============================================================================

; OP_GET_ELEM: r_dest = r_obj[r_index]
op_get_elem:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    mov r9, [rbp + rsi*8]
    IS_POINTER r8, .get_elem_array, .get_elem_slow
get_elem_array:
    and r8, 0x0000FFFFFFFFFFFF
    mov rcx, r9
    call JsValue_ToInt32
    mov r10d, eax
    cmp r10d, [r8 + 16]
    jae .get_elem_undefined
    mov rax, [r8 + 24 + r10*8]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
get_elem_undefined:
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
get_elem_slow:
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsArray_GetElement
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_SET_ELEM: r_obj[r_index] = r_value
op_set_elem:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    mov r10, [rbp + rsi*8]
    IS_POINTER r8, .set_elem_array, .set_elem_slow
set_elem_array:
    and r8, 0x0000FFFFFFFFFFFF
    mov rcx, r9
    call JsValue_ToInt32
    mov r11d, eax
    cmp r11d, [r8 + 16]
    jae .set_elem_grow
set_elem_store:
    mov [r8 + 24 + r11*8], r10
    jmp interpreter_loop
set_elem_grow:
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    sub rsp, 32
    mov rcx, r8
    mov edx, r11d
    inc edx
    call JsArray_Grow
    add rsp, 32
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    jmp .set_elem_store
set_elem_slow:
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    mov r8, r10
    call JsArray_SetElement
    add rsp, 32
    jmp interpreter_loop

; OP_ARRAY_PUSH: r_array.push(r_value)
op_array_push:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    IS_POINTER r8, .push_array, .push_slow
push_array:
    and r8, 0x0000FFFFFFFFFFFF
    mov eax, [r8 + 16]
    mov r10d, eax
    inc r10d
    cmp r10d, [r8 + 20]
    ja .push_grow
    mov [r8 + 24 + rax*8], r9
    mov [r8 + 16], r10d
    jmp interpreter_loop
push_grow:
    push rcx
    push rdx
    push r8
    push r9
    push r10
    sub rsp, 32
    mov rcx, r8
    mov edx, r10d
    call JsArray_Grow
    add rsp, 32
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    jmp .push_array
push_slow:
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsArray_Push
    add rsp, 32
    jmp interpreter_loop

; OP_ARRAY_POP: r_dest = r_array.pop()
op_array_pop:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    IS_POINTER r8, .pop_array, .pop_slow
pop_array:
    and r8, 0x0000FFFFFFFFFFFF
    mov eax, [r8 + 16]
    test eax, eax
    jz .pop_undefined
    dec eax
    mov r9, [r8 + 24 + rax*8]
    mov [r8 + 16], eax
    mov [rbp + rcx*8], r9
    jmp interpreter_loop
pop_undefined:
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
pop_slow:
    sub rsp, 32
    mov rcx, r8
    call JsArray_Pop
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; Object Operations Extensions
; ============================================================================

; OP_SET_PROP: r_obj.property = r_value (with IC)
op_set_prop:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    movzx rsi, dword ptr [rbx]
    movzx rdi, dword ptr [rbx+4]
    add rbx, 8
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    IS_POINTER r8, .set_prop_object, .set_prop_slow
set_prop_object:
    mov r10, [r8]
    mov r11, [r15 + rdi*16]
    cmp r10, r11
    jne .set_prop_ic_miss
    mov eax, [r15 + rdi*16 + 8]
    mov [r8 + rax*8], r9
    inc dword ptr [r15 + rdi*16 + 12]
    jmp interpreter_loop
.set_prop_ic_miss:
    mov rcx, r10
    mov rdx, [rdi + rsi*8]
    call Shape_LookupProperty
    test rax, rax
    jz .set_prop_add
    movzx ecx, word ptr [rax + 6]
    shl ecx, 3
    movzx eax, word ptr [rax + 8]
    test eax, 1
    jz .set_prop_readonly
    mov [r15 + rdi*16], r10
    mov [r15 + rdi*16 + 8], ecx
    mov dword ptr [r15 + rdi*16 + 12], 1
    mov rax, [r8]
    mov [rax + rcx], r9
    jmp interpreter_loop
.set_prop_readonly:
    jmp interpreter_loop
.set_prop_add:
    jmp interpreter_loop
.set_prop_slow:
    sub rsp, 32
    mov rcx, r8
    mov rdx, [rdi + rsi*8]
    mov r8, r9
    call JsObject_SetProperty
    add rsp, 32
    jmp interpreter_loop

; OP_DELETE_PROP: delete obj.property
op_delete_prop:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsObject_DeleteProperty
    add rsp, 32
    BOX_BOOL rax, rax
    movzx rcx, byte ptr [rbx-2]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_DELETE_ELEM: delete obj[index]
op_delete_elem:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsObject_DeleteElement
    add rsp, 32
    BOX_BOOL rax, rax
    movzx rcx, byte ptr [rbx-2]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_IN: r_dest = r_prop in r_obj
op_in:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    mov r9, [rbp + rsi*8]
    sub rsp, 32
    mov rcx, r9
    mov rdx, r8
    call JsObject_HasProperty
    add rsp, 32
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_INSTANCEOF: r_dest = r_obj instanceof r_ctor
op_instanceof:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    mov r9, [rbp + rsi*8]
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsObject_InstanceOf
    add rsp, 32
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_TYPEOF: r_dest = typeof r_src
op_typeof:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    call JsValue_TypeOf
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_NEW: r_dest = new r_ctor(r_args...)
op_new:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    call JsObject_Create
    add rsp, 32
    mov r9, rax
    sub rsp, 32 + rsi*8
    mov r10, 0
.copy_new_args:
    cmp r10, rsi
    jae .do_new_call
    movzx eax, byte ptr [rbx + r10]
    mov rax, [rbp + rax*8]
    mov [rsp + 32 + r10*8], rax
    inc r10
    jmp .copy_new_args
.do_new_call:
    add rbx, rsi
    mov rcx, r8
    mov rdx, r9
    mov r8, rsp
    mov r9, rsi
    call JsFunction_Call
    add rsp, 32 + rsi*8
    mov [rbp + rcx*8], r9
    jmp interpreter_loop

; OP_HAS_OWN_PROP: r_dest = r_obj.hasOwnProperty(r_prop)
op_has_own_prop:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsObject_HasProperty
    add rsp, 32
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_GET_PROTO: r_dest = r_obj.__proto__
op_get_proto:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    IS_POINTER r8, .get_proto_obj, .get_proto_undefined
.get_proto_obj:
    and r8, 0x0000FFFFFFFFFFFF
    mov rax, [r8 + 8]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop
.get_proto_undefined:
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_SET_PROTO: r_obj.__proto__ = r_proto
op_set_proto:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    IS_POINTER r8, .set_proto_obj, .interpreter_loop
.set_proto_obj:
    and r8, 0x0000FFFFFFFFFFFF
    mov [r8 + 8], r9
    jmp interpreter_loop

; ============================================================================
; Object Literal Operations
; ============================================================================

; OP_OBJECT_SET: obj[key] = value
op_object_set:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    mov r10, [rbp + rsi*8]
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    mov r8, r10
    call JsObject_SetProperty
    add rsp, 32
    jmp interpreter_loop

; OP_OBJECT_GET_KEYS: r_dest = Object.keys(obj)
op_object_get_keys:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    call JsObject_GetKeys
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; ============================================================================
; Function Binding & Application
; ============================================================================

; OP_BIND_THIS: func = func.bind(this)
op_bind_this:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsFunction_BindThis
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_APPLY: r_dest = r_func.apply(r_this, r_args)
op_apply:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    mov r9, [rbp + rsi*8]
    movzx eax, byte ptr [rbx]
    mov r10, [rbp + rax*8]
    inc rbx
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    mov r8, r10
    call JsFunction_Apply
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_CALL_METHOD: r_dest = r_obj.method(r_args...)
op_call_method:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    mov r8, [rbp + rdx*8]
    mov r9, [rbp + rsi*8]
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    xor r9, r9
    call Object_GetPropertyIC
    add rsp, 32
    jmp op_call

; ============================================================================
; Closure Operations
; ============================================================================

; OP_GET_CLOSURE: r_dest = closure[slot]
op_get_closure:
    movzx rcx, byte ptr [rbx]
    movzx rdx, word ptr [rbx+1]
    add rbx, 3
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_SET_CLOSURE: closure[slot] = r_val
op_set_closure:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    jmp interpreter_loop

; ============================================================================
; Iteration Operations
; ============================================================================

; OP_ITER_START: iterator = r_obj[Symbol.iterator]()
op_iter_start:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    call JsIterator_Create
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_ITER_NEXT: r_dest = iterator.next()
op_iter_next:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    call JsIterator_Next
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_ITER_HAS_NEXT: r_dest = iterator.hasNext()
op_iter_has_next:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    call JsIterator_HasNext
    add rsp, 32
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_FOR_IN_START: iterator = for-in r_obj
op_for_in_start:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rcx, r8
    call JsIterator_ForIn
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

; OP_FOR_IN_NEXT: r_dest = for-in iterator.next()
op_for_in_next:
    jmp op_iter_next

; OP_FOR_OF_START: iterator = for-of r_obj
op_for_of_start:
    jmp op_iter_start

; OP_FOR_OF_NEXT: r_dest = for-of iterator.next()
op_for_of_next:
    jmp op_iter_next

; ============================================================================
; Async Operations (Stubs)
; ============================================================================

op_await:
    add rbx, 2
    jmp interpreter_loop

op_promise_resolve:
    add rbx, 2
    jmp interpreter_loop

op_promise_reject:
    add rbx, 2
    jmp interpreter_loop

op_async_call:
    add rbx, 3
    jmp interpreter_loop

op_yield:
    add rbx, 2
    jmp interpreter_loop

op_yield_star:
    add rbx, 2
    jmp interpreter_loop

; ============================================================================
; Optimized Operations (Stubs)
; ============================================================================

op_add_int:
    jmp op_add

op_sub_int:
    jmp op_sub

op_mul_int:
    jmp op_mul

op_inc_local:
    movzx rcx, byte ptr [rbx]
    inc rbx
    mov rax, [rbp + rcx*8]
    UNBOX_INT rax, rax
    inc rax
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

op_dec_local:
    movzx rcx, byte ptr [rbx]
    inc rbx
    mov rax, [rbp + rcx*8]
    UNBOX_INT rax, rax
    dec rax
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

op_get_local:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov rax, [rbp + rdx*8]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

op_set_local:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov rax, [rbp + rdx*8]
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

op_get_global:
    movzx rcx, byte ptr [rbx]
    movzx rdx, word ptr [rbx+1]
    add rbx, 3
    mov r8, r12
    sub rsp, 32
    mov rcx, r8
    xor r8, r8
    call JsObject_GetProperty
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp interpreter_loop

op_set_global:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    mov r8, [rbp + rdx*8]
    sub rsp, 32
    mov rdx, r8
    mov r8, rcx
    mov rcx, r12
    call JsObject_SetProperty
    add rsp, 32
    jmp interpreter_loop

; ============================================================================
; Debug Operations
; ============================================================================

op_assert:
    movzx rcx, byte ptr [rbx]
    inc rbx
    mov rax, [rbp + rcx*8]
    cmp rax, JS_FALSE
    je .assert_fail
    cmp rax, JS_NULL
    je .assert_fail
    cmp rax, JS_UNDEFINED
    je .assert_fail
    cmp rax, 0x7FF9000000000000
    je .assert_fail
    jmp interpreter_loop
.assert_fail:
    int 3
    jmp interpreter_loop

op_profile_start:
    inc rbx
    jmp interpreter_loop

op_profile_end:
    inc rbx
    jmp interpreter_loop

; ============================================================================
; Reserved Opcodes (No-op)
; ============================================================================
op_reserved_0A:
op_reserved_0B:
op_reserved_0C:
op_reserved_0D:
op_reserved_0E:
op_reserved_0F:
op_reserved_16:
op_reserved_17:
op_reserved_18:
op_reserved_19:
op_reserved_1A:
op_reserved_1B:
op_reserved_1C:
op_reserved_1D:
op_reserved_1E:
op_reserved_1F:
op_reserved_29:
op_reserved_2A:
op_reserved_2B:
op_reserved_2C:
op_reserved_2D:
op_reserved_2E:
op_reserved_2F:
op_reserved_37:
op_reserved_38:
op_reserved_39:
op_reserved_3A:
op_reserved_3B:
op_reserved_3C:
op_reserved_3D:
op_reserved_3E:
op_reserved_3F:
op_reserved_49:
op_reserved_4A:
op_reserved_4B:
op_reserved_4C:
op_reserved_4D:
op_reserved_4E:
op_reserved_4F:
op_reserved_5E:
op_reserved_5F:
op_reserved_6D:
op_reserved_6E:
op_reserved_6F:
    inc rbx
    jmp interpreter_loop
op_array_get_len:
op_array_set_len:
op_object_set:
op_object_get_keys:
op_reserved_78:
op_reserved_79:
op_reserved_7A:
op_reserved_7B:
op_reserved_7C:
op_reserved_7D:
op_reserved_7E:
op_reserved_7F:
op_create_func:
op_bind_this:
op_apply:
op_call_method:
op_get_closure:
op_set_closure:
op_reserved_86:
op_reserved_87:
op_reserved_88:
op_reserved_89:
op_reserved_8A:
op_reserved_8B:
op_reserved_8C:
op_reserved_8D:
op_reserved_8E:
op_reserved_8F:
op_iter_start:
op_iter_next:
op_iter_has_next:
op_for_in_start:
op_for_in_next:
op_for_of_start:
op_for_of_next:
op_reserved_97:
op_reserved_98:
op_reserved_99:
op_reserved_9A:
op_reserved_9B:
op_reserved_9C:
op_reserved_9D:
op_reserved_9E:
op_reserved_9F:
op_await:
op_promise_resolve:
op_promise_reject:
op_async_call:
op_yield:
op_yield_star:
op_reserved_A6:
op_reserved_A7:
op_reserved_A8:
op_reserved_A9:
op_reserved_AA:
op_reserved_AB:
op_reserved_AC:
op_reserved_AD:
op_reserved_AE:
op_reserved_AF:
op_add_int:
op_sub_int:
op_mul_int:
op_inc_local:
op_dec_local:
op_get_local:
op_set_local:
op_get_global:
op_set_global:
op_reserved_B9:
op_reserved_BA:
op_reserved_BB:
op_reserved_BC:
op_reserved_BD:
op_reserved_BE:
op_reserved_BF:
op_assert:
op_profile_start:
op_profile_end:
op_reserved_F5:
op_reserved_F6:
op_reserved_F7:
op_reserved_F8:
op_reserved_F9:
op_reserved_FA:
op_reserved_FB:
op_reserved_FC:
op_reserved_FD:
op_reserved_FE:
op_unimplemented:
    ; Unimplemented opcode - skip and continue
    inc rbx
    jmp interpreter_loop

JsInterpreter_Run ENDP

; ============================================================================
; C++ Interface Functions
; ============================================================================

; JsInterpreter_CreateArena - Allocate a new Sovereign Arena
; Entry:  rcx = initial size in bytes
; Exit:   rax = arena base pointer (null on failure)
JsInterpreter_CreateArena PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Round up to page size (4KB)
    add rcx, 4095
    and rcx, -4096
    
    ; Call VirtualAlloc
    mov rdx, rcx                            ; Size
    xor rcx, rcx                            ; Let system choose address
    mov r8, 0x2000                          ; MEM_RESERVE
    mov r9, 0x04                            ; PAGE_READWRITE
    call VirtualAlloc
    
    add rsp, 40
    pop rbx
    pop rbp
    ret
JsInterpreter_CreateArena ENDP

; ExecuteBytecode_MASM - C-compatible entry point for Milestone 1
; Entry:  rcx = Runtime* (opaque pointer, contains arena/state)
;         rdx = bytecode pointer
;         r8  = bytecode length
;         r9  = result pointer (uint64_t*)
; Exit:   rax = 1 (success) or 0 (failure)
;         [r9] = result value (if success)
ExecuteBytecode_MASM PROC FRAME
    ; Save non-volatile registers
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 56                             ; Shadow space + alignment + result storage
    .allocstack 56
    .endprolog
    
    ; Save result pointer for later
    mov [rsp + 48], r9                      ; Save result ptr to stack
    
    ; Save bytecode end pointer for bounds check
    mov rsi, rdx                            ; rsi = bytecode start
    mov r12, rdx                            ; r12 = PC = bytecode start
    add r12, r8                             ; r12 = bytecode end
    
    ; Set up interpreter state from Runtime structure
    ; Runtime layout:
    ;   +0: arenaBase (uint8_t*)
    ;   +8: arenaBump (uint8_t*)
    mov r13, [rcx]                          ; ARENA_BASE = runtime->arenaBase
    mov r14, [rcx + 8]                      ; BUMP = runtime->arenaBump
    mov r15, rcx                            ; Save Runtime* for later
    
    ; Set up execution context
    mov rbx, rdx                            ; PC = bytecode start
    xor rdi, rdi                            ; CONST_POOL = null
    xor r8, r8                              ; v0 = 0
    xor r9, r9                              ; v1 = 0
    xor r10, r10                            ; v2 = 0
    xor r11, r11                            ; v3 = 0
    
    ; Initialize frame pointer
    mov rbp, rsp
    sub rbp, 64

; ============================================================================
; Main Interpreter Loop (simplified for Milestone 1)
; ============================================================================
ALIGN 16
.interpreter_loop:
    ; Bounds check: PC < bytecode_end
    cmp rbx, r12
    jae .execution_complete                 ; Reached end of bytecode
    
    ; Fetch opcode and advance PC
    movzx rax, byte ptr [rbx]               ; rax = opcode
    inc rbx                                 ; PC++
    
    ; Simple switch on opcode
    cmp rax, 0                              ; OP_LOAD_CONST
    je .op_load_const
    cmp rax, 1                              ; OP_LOAD_INT
    je .op_load_int
    cmp rax, 0x50                           ; OP_RETURN
    je .op_return
    
    ; Unknown opcode - return error
    jmp .error_unknown_opcode

; ---------------------------------------------------------------------------
; OP_LOAD_INT (0x01): Load 32-bit immediate into register
; Format: OP_LOAD_INT <int32> <dst_reg>
; ---------------------------------------------------------------------------
.op_load_int:
    ; Bounds check for operands (need 5 more bytes)
    mov rdx, rbx
    sub rdx, rsi                            ; rdx = current offset
    add rdx, 5
    cmp rdx, r12
    sub rdx, rsi
    ja .error_truncated
    
    ; Read int32 (little-endian)
    mov eax, dword ptr [rbx]                ; eax = int32 value
    add rbx, 4                              ; PC += 4
    
    ; Read destination register
    movzx rcx, byte ptr [rbx]               ; rcx = register index
    inc rbx                                 ; PC++
    
    ; Encode as NaN-boxed int32: 0x7FF8000100000000 | (value & 0xFFFFFFFF)
    mov rdx, 7FF8000100000000h              ; QNaN | TAG_INT32
    and rax, 0FFFFFFFFh                     ; Clear upper bits
    or rdx, rax                             ; Combine with value
    
    ; Store to register based on index
    cmp cl, 0
    je .store_r0
    cmp cl, 1
    je .store_r1
    cmp cl, 2
    je .store_r2
    cmp cl, 3
    je .store_r3
    jmp interpreter_loop
    
.store_r0:
    mov r8, rdx
    jmp interpreter_loop
.store_r1:
    mov r9, rdx
    jmp interpreter_loop
.store_r2:
    mov r10, rdx
    jmp interpreter_loop
.store_r3:
    mov r11, rdx
    jmp interpreter_loop

; ---------------------------------------------------------------------------
; OP_RETURN (0x50): Return value from register
; Format: OP_RETURN <src_reg>
; ---------------------------------------------------------------------------
.op_return:
    ; Bounds check
    cmp rbx, r12
    jae .error_truncated
    
    ; Read source register
    movzx rax, byte ptr [rbx]               ; rax = register index
    inc rbx                                 ; PC++
    
    ; Load value from register
    cmp al, 0
    je .load_r0
    cmp al, 1
    je .load_r1
    cmp al, 2
    je .load_r2
    cmp al, 3
    je .load_r3
    xor rax, rax                            ; Default to 0
    jmp .return_value
    
.load_r0:
    mov rax, r8
    jmp .return_value
.load_r1:
    mov rax, r9
    jmp .return_value
.load_r2:
    mov rax, r10
    jmp .return_value
.load_r3:
    mov rax, r11
    jmp .return_value

.return_value:
    ; Store result
    mov rcx, [rsp + 48]                     ; Load result pointer
    mov [rcx], rax                          ; Store return value
    
    ; Update runtime arena bump
    mov [r15 + 8], r14                      ; runtime->arenaBump = BUMP
    
    ; Return success
    mov rax, 1
    jmp .cleanup

; ---------------------------------------------------------------------------
; OP_LOAD_CONST (0x00): Load constant from pool
; Format: OP_LOAD_CONST <const_idx> <dst_reg>
; For Milestone 1: skip operands
; ---------------------------------------------------------------------------
.op_load_const:
    add rbx, 2                              ; Skip operands
    jmp interpreter_loop

; ---------------------------------------------------------------------------
; Error Handlers
; ---------------------------------------------------------------------------
.error_unknown_opcode:
    xor rax, rax                            ; Return 0 (failure)
    jmp .cleanup

.error_truncated:
    xor rax, rax                            ; Return 0 (failure)
    jmp .cleanup

.execution_complete:
    ; Reached end without return - return undefined
    mov rcx, [rsp + 48]                     ; Load result pointer
    mov qword ptr [rcx], 7FF3000000000001h  ; JS_UNDEFINED
    mov rax, 1                              ; Success
    jmp .cleanup

.cleanup:
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
ExecuteBytecode_MASM ENDP

; ============================================================================
; Trace Collector C Interface Functions
; ============================================================================

IF RAWRXD_TRACE_COLLECTOR

; TraceCollector_Reset - Reset the trace collector state
; Entry:  None
; Exit:   None (resets global state)
TraceCollector_Reset PROC FRAME
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Clear fingerprint
    mov g_trace_collector_instance.fingerprint_low, 0x6C6229273393B7F1h  ; FNV offset basis (low)
    mov g_trace_collector_instance.fingerprint_high, 0x3243F6A8885A308Dh   ; FNV offset basis (high)
    
    ; Clear event count and buffer
    mov g_trace_collector_instance.event_count, 0
    mov g_trace_collector_instance.buffer_head, 0
    mov g_trace_collector_instance.buffer_tail, 0
    mov g_trace_collector_instance.buffer_count, 0
    mov g_trace_collector_instance.pattern_match_id, 0
    mov g_trace_collector_instance.match_confidence, 0
    
    ; Clear is_recording flag
    mov g_trace_collector_instance.is_recording, 0
    
    ; Clear event buffer (optional - 8KB)
    lea rdi, g_trace_collector_instance.event_buffer
    mov rcx, 1024                           ; 1024 QWORDs
    xor rax, rax
    rep stosq
    
    add rsp, 40
    pop rdi
    ret
TraceCollector_Reset ENDP

; TraceCollector_StartRecording - Begin trace collection
; Entry:  None
; Exit:   None
TraceCollector_StartRecording PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov g_trace_collector_instance.is_recording, 1
    
    add rsp, 40
    ret
TraceCollector_StartRecording ENDP

; TraceCollector_StopRecording - Stop trace collection
; Entry:  None
; Exit:   None
TraceCollector_StopRecording PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov g_trace_collector_instance.is_recording, 0
    
    add rsp, 40
    ret
TraceCollector_StopRecording ENDP

; TraceCollector_IsRecording - Check if recording is active
; Entry:  None
; Exit:   rax = 1 if recording, 0 if not
TraceCollector_IsRecording PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    movzx rax, g_trace_collector_instance.is_recording
    
    add rsp, 40
    ret
TraceCollector_IsRecording ENDP

; TraceCollector_GetFingerprint - Get the current execution fingerprint
; Entry:  rcx = pointer to 16-byte buffer (uint64_t[2])
; Exit:   None (writes fingerprint to buffer)
TraceCollector_GetFingerprint PROC FRAME
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rdi, rcx                            ; rdi = destination buffer
    
    ; Write low 64 bits
    mov rax, g_trace_collector_instance.fingerprint_low
    mov [rdi], rax
    
    ; Write high 64 bits
    mov rax, g_trace_collector_instance.fingerprint_high
    mov [rdi + 8], rax
    
    add rsp, 40
    pop rdi
    ret
TraceCollector_GetFingerprint ENDP

; TraceCollector_GetEventCount - Get number of recorded events
; Entry:  None
; Exit:   rax = event count
TraceCollector_GetEventCount PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov eax, g_trace_collector_instance.event_count
    
    add rsp, 40
    ret
TraceCollector_GetEventCount ENDP

; TraceCollector_RecordEvent - Manually record an event (for C++ integration)
; Entry:  rcx = event type (0-255)
;         rdx = event data (64-bit value)
; Exit:   None
TraceCollector_RecordEvent PROC FRAME
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Check if recording is active
    movzx eax, g_trace_collector_instance.is_recording
    test eax, eax
    jz .done
    
    ; Get buffer position
    mov eax, g_trace_collector_instance.buffer_head
    and eax, 1023                           ; Wrap to buffer size
    
    ; Calculate event address
    lea rdi, g_trace_collector_instance.event_buffer
    lea rdi, [rdi + rax*8]
    
    ; Store event: [type:8][data:56]
    mov byte ptr [rdi], cl                  ; Event type
    mov [rdi + 1], rdx                      ; Event data (7 bytes, but store full QWORD)
    
    ; Update fingerprint
    mov rax, g_trace_collector_instance.fingerprint_low
    xor rax, rcx                            ; XOR with event type
    xor rax, rdx                            ; XOR with event data
    mov rcx, 0x100000001B3h                 ; FNV prime
    mul rcx                                 ; Multiply
    mov g_trace_collector_instance.fingerprint_low, rax
    mov g_trace_collector_instance.fingerprint_high, rdx
    
    ; Increment counters
    inc g_trace_collector_instance.event_count
    inc g_trace_collector_instance.buffer_head
    
.done:
    add rsp, 40
    pop rsi
    pop rdi
    ret
TraceCollector_RecordEvent ENDP

ENDIF ; RAWRXD_TRACE_COLLECTOR

; End of file
END
