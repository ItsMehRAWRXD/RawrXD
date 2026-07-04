; RawrXD-Script Bytecode Contract - MASM Side
; Mirrors bytecode_contract.hpp for C++ ↔ MASM interoperability
;
; This file must be kept in sync with bytecode_contract.hpp
; Version: 1.0.0

; ============================================================================
; BYTECODE FILE FORMAT CONSTANTS
; ============================================================================

; Magic number: "RAWR"
BC_MAGIC EQU 052415752h  ; 'R' 'A' 'W' 'R' little-endian

; Version: 1.0.0
BC_VERSION_MAJOR EQU 1
BC_VERSION_MINOR EQU 0
BC_VERSION_PATCH EQU 0
BC_VERSION EQU (BC_VERSION_MAJOR SHL 12) OR (BC_VERSION_MINOR SHL 4) OR BC_VERSION_PATCH

; Header flags
BC_FLAG_STRICT_MODE     EQU 00001h
BC_FLAG_HAS_DEBUG_INFO  EQU 00002h
BC_FLAG_PROFILE_COVERAGE EQU 00004h
BC_FLAG_PROFILE_IC      EQU 00008h

; Header offsets (64-byte header)
BC_HDR_MAGIC            EQU 0
BC_HDR_VERSION          EQU 4
BC_HDR_FLAGS            EQU 6
BC_HDR_CODE_OFFSET      EQU 8
BC_HDR_CODE_SIZE        EQU 12
BC_HDR_CONST_OFFSET     EQU 16
BC_HDR_CONST_COUNT      EQU 20
BC_HDR_STRING_OFFSET    EQU 24
BC_HDR_STRING_SIZE      EQU 28
BC_HDR_IC_OFFSET        EQU 32
BC_HDR_IC_COUNT         EQU 36
BC_HDR_LINE_OFFSET      EQU 40

; ============================================================================
; INSTRUCTION FORMAT
; ============================================================================
; Fixed 4-byte (32-bit) instructions
; [Opcode:8][Dst:4][SrcA:4][SrcB:4][Reserved:12]

; Instruction field extraction macros
EXTRACT_OPCODE MACRO reg, instr
    movzx   reg, byte ptr [instr]
ENDM

EXTRACT_DST MACRO reg, instr
    movzx   reg, byte ptr [instr+1]
    and     reg, 0Fh
ENDM

EXTRACT_SRC_A MACRO reg, instr
    movzx   reg, byte ptr [instr+1]
    shr     reg, 4
ENDM

EXTRACT_SRC_B MACRO reg, instr
    movzx   reg, byte ptr [instr+2]
    and     reg, 0Fh
ENDM

EXTRACT_IMM12 MACRO reg, instr
    movzx   reg, word ptr [instr+2]
    and     reg, 0FFFh
ENDM

EXTRACT_IMM12_SIGNED MACRO reg, instr
    movsx   reg, word ptr [instr+2]
    and     reg, 0FFFh
    test    reg, 0800h
    jz      @F
    or      reg, 0F000h
@@:
ENDM

; Build instruction from fields
BUILD_INSTRUCTION MACRO opcode, dst, srcA, srcB, imm
    (((opcode) SHL 24) OR ((dst) AND 0Fh) SHL 20) OR \
    (((srcA) AND 0Fh) SHL 16) OR (((srcB) AND 0Fh) SHL 12) OR ((imm) AND 0FFFh))
ENDM

; ============================================================================
; OPCODES
; ============================================================================
; Must match bytecode_contract.hpp exactly

; Control Flow (0x00-0x0F)
OP_NOP              EQU 000h
OP_RETURN           EQU 001h
OP_RETURN_UNDEFINED EQU 002h
OP_JUMP             EQU 003h
OP_JUMP_IF_TRUE     EQU 004h
OP_JUMP_IF_FALSE    EQU 005h
OP_JUMP_IF_EQUAL    EQU 006h
OP_JUMP_IF_NOT_EQUAL EQU 007h
OP_CALL             EQU 008h
OP_CALL_NATIVE      EQU 009h
OP_TAIL_CALL        EQU 00Ah
OP_ENTER_TRY        EQU 00Bh
OP_LEAVE_TRY        EQU 00Ch
OP_THROW            EQU 00Dh
OP_DEBUGGER         EQU 00Eh
OP_HALT             EQU 00Fh

; Constants (0x10-0x1F)
OP_LOAD_CONST       EQU 010h
OP_LOAD_UNDEFINED   EQU 011h
OP_LOAD_NULL        EQU 012h
OP_LOAD_TRUE        EQU 013h
OP_LOAD_FALSE       EQU 014h
OP_LOAD_ZERO        EQU 015h
OP_LOAD_ONE         EQU 016h
OP_LOAD_INT         EQU 017h
OP_LOAD_STRING      EQU 018h
OP_LOAD_GLOBAL      EQU 019h
OP_STORE_GLOBAL     EQU 01Ah
OP_LOAD_ENV         EQU 01Bh
OP_STORE_ENV        EQU 01Ch
OP_RESERVE          EQU 01Dh
OP_MOVE             EQU 01Eh
OP_SWAP             EQU 01Fh

; Arithmetic (0x20-0x2F)
OP_ADD              EQU 020h
OP_SUB              EQU 021h
OP_MUL              EQU 022h
OP_DIV              EQU 023h
OP_MOD              EQU 024h
OP_NEG              EQU 025h
OP_INC              EQU 026h
OP_DEC              EQU 027h
OP_POW              EQU 028h
OP_SQRT             EQU 029h
OP_ABS              EQU 02Ah
OP_MIN              EQU 02Bh
OP_MAX              EQU 02Ch
OP_CLAMP            EQU 02Dh
OP_FLOOR            EQU 02Eh
OP_CEIL             EQU 02Fh

; Bitwise (0x30-0x3F)
OP_BIT_AND          EQU 030h
OP_BIT_OR           EQU 031h
OP_BIT_XOR          EQU 032h
OP_BIT_NOT          EQU 033h
OP_SHIFT_LEFT       EQU 034h
OP_SHIFT_RIGHT      EQU 035h
OP_SHIFT_RIGHT_UNSIGNED EQU 036h
OP_ROTATE_LEFT      EQU 037h
OP_ROTATE_RIGHT     EQU 038h
OP_POP_COUNT        EQU 039h
OP_LEADING_ZERO     EQU 03Ah
OP_TRAILING_ZERO    EQU 03Bh
OP_BIT_EXTRACT      EQU 03Ch
OP_BIT_INSERT       EQU 03Dh
OP_BIT_CLEAR        EQU 03Eh
OP_BIT_SET          EQU 03Fh

; Comparison (0x40-0x4F)
OP_EQ               EQU 040h
OP_NE               EQU 041h
OP_LT               EQU 042h
OP_LE               EQU 043h
OP_GT               EQU 044h
OP_GE               EQU 045h
OP_STRICT_EQ        EQU 046h
OP_STRICT_NE        EQU 047h
OP_IS_NULL          EQU 048h
OP_IS_UNDEFINED     EQU 049h
OP_IS_NULL_OR_UNDEFINED EQU 04Ah
OP_IS_CALLABLE      EQU 04Bh
OP_IS_CONSTRUCTOR   EQU 04Ch
OP_INSTANCE_OF      EQU 04Dh
OP_IN               EQU 04Eh
OP_COMPARE          EQU 04Fh

; Logical (0x50-0x5F)
OP_LOGICAL_AND      EQU 050h
OP_LOGICAL_OR       EQU 051h
OP_LOGICAL_NOT      EQU 052h
OP_COALESCE         EQU 053h
OP_OPTIONAL_CHAIN   EQU 054h
OP_TO_BOOLEAN       EQU 055h
OP_TO_NUMBER        EQU 056h
OP_TO_STRING        EQU 057h
OP_TO_OBJECT        EQU 058h
OP_TO_PRIMITIVE     EQU 059h
OP_TYPE_OF          EQU 05Ah
OP_VOID             EQU 05Bh
OP_DELETE           EQU 05Ch
OP_INCR             EQU 05Dh
OP_DECR             EQU 05Eh
OP_SPREAD           EQU 05Fh

; Memory/Objects (0x60-0x6F)
OP_NEW_OBJECT       EQU 060h
OP_NEW_OBJECT_WITH_SIZE EQU 061h
OP_GET_PROP         EQU 062h
OP_SET_PROP         EQU 063h
OP_DEFINE_PROP      EQU 064h
OP_DELETE_PROP      EQU 065h
OP_HAS_PROP         EQU 066h
OP_GET_OWN_PROP     EQU 067h
OP_KEYS             EQU 068h
OP_VALUES           EQU 069h
OP_ENTRIES          EQU 06Ah
OP_ASSIGN           EQU 06Bh
OP_FREEZE           EQU 06Ch
OP_SEAL             EQU 06Dh
OP_CLONE            EQU 06Eh
OP_EXTEND           EQU 06Fh

; Arrays (0x70-0x7F)
OP_NEW_ARRAY        EQU 070h
OP_NEW_ARRAY_WITH_SIZE EQU 071h
OP_ARRAY_PUSH       EQU 072h
OP_ARRAY_POP        EQU 073h
OP_ARRAY_SHIFT      EQU 074h
OP_ARRAY_UNSHIFT    EQU 075h
OP_ARRAY_SLICE      EQU 076h
OP_ARRAY_SPLICE     EQU 077h
OP_ARRAY_INDEX_OF   EQU 078h
OP_ARRAY_INCLUDES   EQU 079h
OP_ARRAY_FIND       EQU 07Ah
OP_ARRAY_FILTER     EQU 07Bh
OP_ARRAY_MAP        EQU 07Ch
OP_ARRAY_REDUCE     EQU 07Dh
OP_ARRAY_FOR_EACH   EQU 07Eh
OP_ARRAY_LENGTH     EQU 07Fh

; Functions (0x80-0x8F)
OP_NEW_FUNCTION     EQU 080h
OP_NEW_ARROW        EQU 081h
OP_NEW_METHOD       EQU 082h
OP_NEW_GETTER       EQU 083h
OP_NEW_SETTER       EQU 084h
OP_BIND             EQU 085h
OP_APPLY            EQU 086h
OP_CALL_METHOD      EQU 087h
OP_SUPER_CALL       EQU 088h
OP_SUPER_GET        EQU 089h
OP_SUPER_SET        EQU 08Ah
OP_NEW_CLASS        EQU 08Bh
OP_NEW_GENERATOR    EQU 08Ch
OP_YIELD            EQU 08Dh
OP_YIELD_STAR       EQU 08Eh
OP_AWAIT            EQU 08Fh

; Exceptions (0x90-0x9F)
OP_TRY_START        EQU 090h
OP_CATCH            EQU 091h
OP_FINALLY          EQU 092h
OP_TRY_END          EQU 093h
OP_THROW            EQU 094h
OP_RETHROW          EQU 095h
OP_GET_EXCEPTION    EQU 096h
OP_CLEAR_EXCEPTION  EQU 097h
OP_PUSH_EXCEPTION   EQU 098h
OP_POP_EXCEPTION    EQU 099h
OP_GET_STACK_TRACE  EQU 09Ah
OP_CAPTURE_STACK    EQU 09Bh
OP_RESUME           EQU 09Ch
OP_SUSPEND          EQU 09Dh
OP_RESUME_GENERATOR EQU 09Eh
OP_COMPLETE_GENERATOR EQU 09Fh

; Type Operations (0xA0-0xAF)
OP_IS_NUMBER        EQU 0A0h
OP_IS_STRING        EQU 0A1h
OP_IS_BOOLEAN       EQU 0A2h
OP_IS_OBJECT        EQU 0A3h
OP_IS_FUNCTION      EQU 0A4h
OP_IS_SYMBOL        EQU 0A5h
OP_IS_BIG_INT       EQU 0A6h
OP_IS_ARRAY         EQU 0A7h
OP_IS_INTEGER       EQU 0A8h
OP_IS_FINITE         EQU 0A9h
OP_IS_NAN           EQU 0AAh
OP_IS_SAFE_INTEGER  EQU 0ABh
OP_IS_EXTENSIBLE    EQU 0ACh
OP_IS_SEALED        EQU 0ADh
OP_IS_FROZEN        EQU 0AEh
OP_IS_PROXY         EQU 0AFh

; String Operations (0xB0-0xBF)
OP_STRING_CONCAT    EQU 0B0h
OP_STRING_SLICE     EQU 0B1h
OP_STRING_SUBSTRING EQU 0B2h
OP_STRING_SUBSTR    EQU 0B3h
OP_STRING_INDEX_OF  EQU 0B4h
OP_STRING_LAST_INDEX_OF EQU 0B5h
OP_STRING_INCLUDES  EQU 0B6h
OP_STRING_STARTS_WITH EQU 0B7h
OP_STRING_ENDS_WITH EQU 0B8h
OP_STRING_REPEAT    EQU 0B9h
OP_STRING_TRIM      EQU 0BAh
OP_STRING_TRIM_START EQU 0BBh
OP_STRING_TRIM_END  EQU 0BCh
OP_STRING_PAD_START EQU 0BDh
OP_STRING_PAD_END   EQU 0BEh
OP_STRING_REPLACE   EQU 0BFh

; System/Debug (0xF0-0xFF)
OP_BREAKPOINT       EQU 0F0h
OP_TRACE            EQU 0F1h
OP_ASSERT           EQU 0F2h
OP_PROFILE_START    EQU 0F3h
OP_PROFILE_END      EQU 0F4h
OP_COVERAGE         EQU 0F5h
OP_LOG              EQU 0F6h
OP_WARN             EQU 0F7h
OP_ERROR            EQU 0F8h
OP_INFO             EQU 0F9h
OP_DEBUG            EQU 0FAh
OP_TIME             EQU 0FBh
OP_TIME_END         EQU 0FCh
OP_COUNT            EQU 0FDh
OP_COUNT_RESET      EQU 0FEh
OP_HALT_FINAL       EQU 0FFh

; ============================================================================
; NAAN-BOXING CONSTANTS (must match C++ side)
; ============================================================================

QNAN_MASK       EQU 07FF8000000000000h
TAG_INT32       EQU 00001000000000000h
TAG_BOOL        EQU 00002000000000000h
TAG_NULL        EQU 00003000000000000h
TAG_STRING      EQU 00004000000000000h
TAG_OBJECT      EQU 00005000000000000h
TAG_NATIVE      EQU 00006000000000000h

JS_NULL         EQU 07FF3000000000000h
JS_UNDEFINED    EQU 07FF3000000000001h
JS_TRUE         EQU 07FF2000000000001h
JS_FALSE        EQU 07FF2000000000000h

; ============================================================================
; REGISTER MAPPING (x64 calling convention)
; ============================================================================
; These registers are preserved across calls (callee-saved)
; and used for VM state

REG_PC          EQU rbx     ; Program Counter - bytecode instruction pointer
REG_CODE_BASE   EQU rsi     ; Base of current bytecode section
REG_CONST_POOL  EQU rdi     ; Constant pool base pointer
REG_GLOBAL      EQU r12     ; Global object pointer
REG_ARENA_BASE  EQU r13     ; Sovereign Arena base
REG_BUMP        EQU r14     ; Arena bump allocator offset
REG_IC_TABLE    EQU r15     ; Inline Cache table base

; Volatile registers (caller-saved) used as virtual registers
REG_V0          EQU r8      ; Virtual register 0 (accumulator)
REG_V1          EQU r9      ; Virtual register 1
REG_V2          EQU r10     ; Virtual register 2
REG_V3          EQU r11     ; Virtual register 3

; Scratch registers
REG_SCRATCH     EQU rax     ; General scratch / return value
REG_ARG0        EQU rcx     ; First argument / scratch
REG_ARG1        EQU rdx     ; Second argument / scratch
REG_FRAME       EQU rbp     ; Call frame base pointer
REG_STACK       EQU rsp     ; Hardware stack pointer

; ============================================================================
; IC (INLINE CACHE) CONSTANTS
; ============================================================================

IC_STATE_UNINITIALIZED  EQU 0
IC_STATE_MONOMORPHIC    EQU 1
IC_STATE_POLYMORPHIC    EQU 2
IC_STATE_MEGAMORPHIC    EQU 3

IC_SLOT_SIZE            EQU 16      ; Size of IC slot in bytes
IC_SLOT_STATE_OFFSET    EQU 0
IC_SLOT_SHAPE_OFFSET    EQU 4
IC_SLOT_OFFSET_OFFSET   EQU 8

; ============================================================================
; C++ TO MASM CALLING CONVENTION
; ============================================================================
; extern "C" bool ExecuteBytecode_MASM(
;     void* runtime,           ; rcx
;     const uint8_t* bytecode, ; rdx
;     size_t bytecodeLen,      ; r8
;     uint64_t* result         ; r9
; );

; Argument positions for ExecuteBytecode_MASM
ARG_RUNTIME     EQU rcx
ARG_BYTECODE    EQU rdx
ARG_BYTECODE_LEN EQU r8
ARG_RESULT      EQU r9

; ============================================================================
; DISPATCH TABLE
; ============================================================================
; 256-entry jump table for opcode dispatch
; Each entry is 8 bytes (QWORD)

DISPATCH_TABLE_SIZE EQU 256 * 8

; Macro to build dispatch table entry
DISPATCH_ENTRY MACRO opcode, handler
    QWORD handler
ENDM

; ============================================================================
; COVERAGE HOOKS (optional, enabled via RAWRXD_PROFILE_COVERAGE)
; ============================================================================

IF RAWRXD_PROFILE_COVERAGE
    EXTERN g_opcode_coverage:BYTE
    EXTERN g_ic_hit_count:QWORD
    EXTERN g_ic_miss_count:QWORD
    EXTERN g_total_opcodes:QWORD
ENDIF

; Macro to record opcode execution
RECORD_OPCODE MACRO opcode
    IF RAWRXD_PROFILE_COVERAGE
        inc byte ptr [g_opcode_coverage + opcode]
        inc qword ptr [g_total_opcodes]
    ENDIF
ENDM

; Macro to record IC hit
RECORD_IC_HIT MACRO
    IF RAWRXD_PROFILE_COVERAGE
        inc qword ptr [g_ic_hit_count]
    ENDIF
ENDM

; Macro to record IC miss
RECORD_IC_MISS MACRO
    IF RAWRXD_PROFILE_COVERAGE
        inc qword ptr [g_ic_miss_count]
    ENDIF
ENDM

; ============================================================================
; COMPILE-TIME CONTRACT VERIFICATION (MASM SIDE)
; ============================================================================
; These .ERR directives ensure MASM and C++ stay in sync.
; If any trigger, the contract has drifted and must be reconciled.

; Instruction size verification
IF (OP_HALT_FINAL - OP_NOP + 1) NE 256
    .ERR Opcode count mismatch - expected 256 opcodes
ENDIF

; Opcode value verification (spot checks against C++ enum)
IF OP_NOP NE 000h
    .ERR OP_NOP mismatch with C++
ENDIF
IF OP_RETURN NE 001h
    .ERR OP_RETURN mismatch with C++
ENDIF
IF OP_LOAD_CONST NE 010h
    .ERR OP_LOAD_CONST mismatch with C++
ENDIF
IF OP_ADD NE 020h
    .ERR OP_ADD mismatch with C++
ENDIF
IF OP_BIT_AND NE 030h
    .ERR OP_BIT_AND mismatch with C++
ENDIF
IF OP_EQ NE 040h
    .ERR OP_EQ mismatch with C++
ENDIF
IF OP_LOGICAL_AND NE 050h
    .ERR OP_LOGICAL_AND mismatch with C++
ENDIF
IF OP_NEW_OBJECT NE 060h
    .ERR OP_NEW_OBJECT mismatch with C++
ENDIF
IF OP_NEW_ARRAY NE 070h
    .ERR OP_NEW_ARRAY mismatch with C++
ENDIF
IF OP_NEW_FUNCTION NE 080h
    .ERR OP_NEW_FUNCTION mismatch with C++
ENDIF
IF OP_TRY_START NE 090h
    .ERR OP_TRY_START mismatch with C++
ENDIF
IF OP_IS_NUMBER NE 0A0h
    .ERR OP_IS_NUMBER mismatch with C++
ENDIF
IF OP_STRING_CONCAT NE 0B0h
    .ERR OP_STRING_CONCAT mismatch with C++
ENDIF
IF OP_BREAKPOINT NE 0F0h
    .ERR OP_BREAKPOINT mismatch with C++
ENDIF
IF OP_HALT_FINAL NE 0FFh
    .ERR OP_HALT_FINAL mismatch with C++
ENDIF

; Magic number verification
IF BC_MAGIC NE 052415752h
    .ERR BC_MAGIC mismatch with C++
ENDIF

; IC slot size verification
IF IC_SLOT_SIZE NE 16
    .ERR IC_SLOT_SIZE mismatch with C++
ENDIF

; Register mapping verification (ensure no duplicates)
IF REG_PC EQ REG_GLOBAL
    .ERR Register collision: PC and GLOBAL
ENDIF
IF REG_PC EQ REG_ARENA_BASE
    .ERR Register collision: PC and ARENA_BASE
ENDIF
IF REG_GLOBAL EQ REG_ARENA_BASE
    .ERR Register collision: GLOBAL and ARENA_BASE
ENDIF

; ============================================================================
; END OF BYTECODE CONTRACT
; ============================================================================
