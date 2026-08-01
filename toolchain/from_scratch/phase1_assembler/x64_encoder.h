/*==========================================================================
 * Phase 1: x64 Instruction Encoder - Fully Reverse Engineered
 *
 * Encodes x64 instructions from parsed assembly into machine code bytes.
 * Handles the complete x64 encoding including:
 *   - REX prefix generation (W, R, X, B bits)
 *   - ModR/M byte construction
 *   - SIB byte for scaled index addressing
 *   - 8/32-bit displacement encoding
 *   - Immediate operand encoding (imm8, imm16, imm32, imm64)
 *   - RIP-relative addressing (default x64 mode)
 *   - VEX/EVEX prefix stubs for AVX/AVX-512
 *
 * Register encoding (3-bit values, extended by REX.R/B):
 *   RAX=0 RCX=1 RDX=2 RBX=3 RSP=4 RBP=5 RSI=6 RDI=7
 *   R8=0+REX.B  R9=1+REX.B ... R15=7+REX.B
 *
 * ModR/M byte layout: [mod:2][reg:3][rm:3]
 *   mod=00: [rm] or RIP-relative
 *   mod=01: [rm]+disp8
 *   mod=10: [rm]+disp32
 *   mod=11: register direct
 *
 * SIB byte layout: [scale:2][index:3][base:3]
 *   scale: 0=1x, 1=2x, 2=4x, 3=8x
 *=========================================================================*/
#ifndef X64_ENCODER_H
#define X64_ENCODER_H

#include <stdint.h>
#include <stddef.h>

/* ---- Register IDs ---- */
typedef enum {
  REG_RAX=0, REG_RCX=1, REG_RDX=2, REG_RBX=3,
  REG_RSP=4, REG_RBP=5, REG_RSI=6, REG_RDI=7,
  REG_R8=8,  REG_R9=9,  REG_R10=10, REG_R11=11,
  REG_R12=12, REG_R13=13, REG_R14=14, REG_R15=15,
  X64_REG_NONE=0xFF
} x64_reg_t;

/* ---- 32-bit register aliases (same encoding, different size context) ---- */
#define REG_EAX REG_RAX
#define REG_ECX REG_RCX
#define REG_EDX REG_RDX
#define REG_EBX REG_RBX
#define REG_ESP REG_RSP
#define REG_EBP REG_RBP
#define REG_ESI REG_RSI
#define REG_EDI REG_RDI
#define REG_R8D REG_R8
#define REG_R9D REG_R9
#define REG_R10D REG_R10
#define REG_R11D REG_R11
#define REG_R12D REG_R12
#define REG_R13D REG_R13
#define REG_R14D REG_R14
#define REG_R15D REG_R15

/* ---- 16-bit register aliases ---- */
#define REG_AX REG_RAX
#define REG_CX REG_RCX
#define REG_DX REG_RDX
#define REG_BX REG_RBX
#define REG_SP REG_RSP
#define REG_BP REG_RBP
#define REG_SI REG_RSI
#define REG_DI REG_RDI

/* ---- 8-bit register aliases ---- */
#define REG_AL REG_RAX
#define REG_CL REG_RCX
#define REG_DL REG_RDX
#define REG_BL REG_RBX
#define REG_SPL REG_RSP
#define REG_BPL REG_RBP
#define REG_SIL REG_RSI
#define REG_DIL REG_RDI

/* ---- Segment registers ---- */
#define REG_FS ((x64_reg_t)100)
#define REG_GS ((x64_reg_t)101)

/* ---- Operand types ---- */
typedef enum {
  OP_NONE = 0,
  OP_REG,           /* register */
  OP_IMM,           /* immediate value */
  OP_MEM,           /* [base + index*scale + disp] */
  OP_RIP_REL,       /* [rip + disp32] */
  OP_LABEL,         /* symbolic label (resolved later) */
  OP_LOCK,          /* LOCK prefix */
  OP_REP,           /* REP prefix */
  OP_REPE,          /* REPE/REPZ prefix */
  OP_REPNE,         /* REPNE/REPNZ prefix */
  OP_SEG            /* Segment override (FS/GS) */
} operand_type_t;

/* ---- Operand size ---- */
typedef enum {
  SZ_NONE = 0,
  SZ_BYTE = 1,
  SZ_WORD = 2,
  SZ_DWORD = 4,
  SZ_QWORD = 8
} operand_size_t;

/* ---- Memory operand ---- */
typedef struct {
  x64_reg_t base;
  x64_reg_t index;
  uint8_t   scale;    /* 1, 2, 4, 8 */
  int32_t   disp;
  int       has_disp;
} mem_operand_t;

/* ---- Operand ---- */
typedef struct {
  operand_type_t type;
  operand_size_t size;
  union {
    x64_reg_t     reg;
    int64_t       imm;
    mem_operand_t mem;
    char          label[128];
  };
} x64_operand_t;

/* ---- Encoded instruction result ---- */
typedef struct {
  uint8_t  bytes[15];    /* max x64 instruction = 15 bytes */
  int      len;
  uint32_t reloc_offset; /* offset of relocation field within bytes */
  uint16_t reloc_type;   /* 0 = none, else REL_AMD64_* */
  char     reloc_symbol[128];
} x64_encoded_t;

/* ---- Instruction mnemonics ---- */
typedef enum {
  /* Data movement */
  MNEM_MOV, MNEM_MOVZX, MNEM_MOVSX, MNEM_LEA, MNEM_XCHG,
  MNEM_PUSH, MNEM_POP,
  /* Arithmetic */
  MNEM_ADD, MNEM_SUB, MNEM_MUL, MNEM_IMUL, MNEM_DIV, MNEM_IDIV,
  MNEM_INC, MNEM_DEC, MNEM_NEG, MNEM_NOT,
  MNEM_AND, MNEM_OR, MNEM_XOR, MNEM_TEST,
  MNEM_SHL, MNEM_SHR, MNEM_SAR, MNEM_ROL, MNEM_ROR,
  MNEM_CMP,
  /* Control flow */
  MNEM_JMP, MNEM_CALL, MNEM_RET, MNEM_INT,
  MNEM_JE, MNEM_JNE, MNEM_JZ, MNEM_JNZ,
  MNEM_JA, MNEM_JAE, MNEM_JB, MNEM_JBE,
  MNEM_JG, MNEM_JGE, MNEM_JL, MNEM_JLE,
  MNEM_JS, MNEM_JNS, MNEM_JO, MNEM_JNO,
  /* SETcc instructions */
  MNEM_SETA, MNEM_SETAE, MNEM_SETB, MNEM_SETBE,
  MNEM_SETC, MNEM_SETE, MNEM_SETG, MNEM_SETGE,
  MNEM_SETL, MNEM_SETLE, MNEM_SETNA, MNEM_SETNAE,
  MNEM_SETNB, MNEM_SETNBE, MNEM_SETNC, MNEM_SETNE,
  MNEM_SETNG, MNEM_SETNGE, MNEM_SETNL, MNEM_SETNLE,
  MNEM_SETNO, MNEM_SETNP, MNEM_SETNS, MNEM_SETNZ,
  MNEM_SETO, MNEM_SETP, MNEM_SETPE, MNEM_SETPO,
  MNEM_SETS, MNEM_SETZ,
  /* CMOVcc instructions */
  MNEM_CMOVA, MNEM_CMOVAE, MNEM_CMOVB, MNEM_CMOVBE,
  MNEM_CMOVC, MNEM_CMOVE, MNEM_CMOVG, MNEM_CMOVGE,
  MNEM_CMOVL, MNEM_CMOVLE, MNEM_CMOVNA, MNEM_CMOVNAE,
  MNEM_CMOVNB, MNEM_CMOVNBE, MNEM_CMOVNC, MNEM_CMOVNE,
  MNEM_CMOVNG, MNEM_CMOVNGE, MNEM_CMOVNL, MNEM_CMOVNLE,
  MNEM_CMOVNO, MNEM_CMOVNP, MNEM_CMOVNS, MNEM_CMOVNZ,
  MNEM_CMOVO, MNEM_CMOVP, MNEM_CMOVPE, MNEM_CMOVPO,
  MNEM_CMOVS, MNEM_CMOVZ,
  /* String/misc */
  MNEM_NOP, MNEM_CLC, MNEM_STC, MNEM_CLD, MNEM_STD,
  MNEM_SYSCALL, MNEM_CPUID, MNEM_RDTSC,
  MNEM_CDQ, MNEM_CQO,
  /* SSE basics */
  MNEM_MOVAPS, MNEM_MOVUPS,
  /* Atomic operations */
  MNEM_XADD, MNEM_CMPXCHG,
  /* Bit manipulation */
  MNEM_BT, MNEM_BTS, MNEM_BTR, MNEM_BTC,
  /* Rotate with carry */
  MNEM_RCL, MNEM_RCR,
  /* String operations (explicit) */
  MNEM_MOVSB, MNEM_MOVSW, MNEM_MOVSD, MNEM_MOVSQ,
  MNEM_STOSB, MNEM_STOSW, MNEM_STOSD, MNEM_STOSQ,
  MNEM_LODSB, MNEM_LODSW, MNEM_LODSD, MNEM_LODSQ,
  MNEM_SCASB, MNEM_SCASW, MNEM_SCASD, MNEM_SCASQ,
  MNEM_CMPSB, MNEM_CMPSW, MNEM_CMPSD, MNEM_CMPSQ,
  MNEM_INSB, MNEM_INSW, MNEM_INSD,
  MNEM_OUTSB, MNEM_OUTSW, MNEM_OUTSD,
  /* Generic string operations (for parser) */
  MNEM_MOVS, MNEM_STOS, MNEM_LODS, MNEM_SCAS, MNEM_CMPS,
  /* Stack frame instructions */
  MNEM_ENTER, MNEM_LEAVE,
  /* Byte swap */
  MNEM_BSWAP,
  /* Memory fences */
  MNEM_PAUSE, MNEM_LFENCE, MNEM_SFENCE, MNEM_MFENCE,
  /* Undefined instruction */
  MNEM_UD2,
  /* Push/Pop flags */
  MNEM_PUSHF, MNEM_POPF,
  /* Fast system calls */
  MNEM_SYSENTER, MNEM_SYSEXIT,
  /* Convert instructions */
  MNEM_CWD, MNEM_CDQE,
  /* MOVSXD */
  MNEM_MOVSXD,
  /* Interrupt/IO */
  MNEM_CLI, MNEM_STI, MNEM_HLT, MNEM_IN, MNEM_OUT,
  /* System instructions */
  MNEM_RDTSCP, MNEM_RDMSR, MNEM_WRMSR, MNEM_RDPID,
  MNEM_INVD, MNEM_WBINVD, MNEM_CLFLUSH, MNEM_CLFLUSHOPT, MNEM_CLWB,
  MNEM_UNKNOWN
} x64_mnemonic_t;

/* ---- API ---- */
x64_encoded_t x64_encode(x64_mnemonic_t mnem, x64_operand_t *op1, x64_operand_t *op2);
x64_encoded_t x64_encode_with_prefix(x64_mnemonic_t mnem, uint8_t prefix, x64_operand_t *op1, x64_operand_t *op2);
x64_mnemonic_t x64_parse_mnemonic(const char *s);
x64_reg_t x64_parse_register(const char *s, operand_size_t *out_size);
const char *x64_mnemonic_name(x64_mnemonic_t m);

#endif
