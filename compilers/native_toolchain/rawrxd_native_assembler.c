/*
 * RAWRXD NATIVE ASSEMBLER - Complete MASM-compatible assembler
 * Supports: x86 (32-bit), x64 (64-bit), x32 (ILP32)
 * No external dependencies - completely self-contained
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>

/* ============================================================================
 * ARCHITECTURE MODES
 * ============================================================================ */
typedef enum {
    ARCH_X86 = 0,   /* 32-bit x86 */
    ARCH_X64 = 1,   /* 64-bit x64 (LP64) */
    ARCH_X32 = 2    /* 64-bit x32 (ILP32) */
} ArchMode;

static ArchMode g_arch = ARCH_X64;
static int g_bits = 64;

/* ============================================================================
 * INSTRUCTION ENCODING TABLES
 * ============================================================================ */

/* Operand types */
#define OP_NONE     0
#define OP_REG8     1
#define OP_REG16    2
#define OP_REG32    3
#define OP_REG64    4
#define OP_IMM8     5
#define OP_IMM16    6
#define OP_IMM32    7
#define OP_IMM64    8
#define OP_MEM8     9
#define OP_MEM16    10
#define OP_MEM32    11
#define OP_MEM64    12
#define OP_REL8     13
#define OP_REL16    14
#define OP_REL32    15
#define OP_XMM      16   /* XMM register (128-bit) */
#define OP_YMM      17   /* YMM register (256-bit) */
#define OP_ZMM      18   /* ZMM register (512-bit) */
#define OP_MEM128   19   /* 128-bit memory operand */
#define OP_MEM256   20   /* 256-bit memory operand */
#define OP_MEM512   21   /* 512-bit memory operand */

/* Register IDs */
typedef enum {
    /* 8-bit registers */
    REG_AL = 0, REG_CL, REG_DL, REG_BL, REG_AH, REG_CH, REG_DH, REG_BH,
    REG_R8B, REG_R9B, REG_R10B, REG_R11B, REG_R12B, REG_R13B, REG_R14B, REG_R15B,
    /* 16-bit registers */
    REG_AX = 16, REG_CX, REG_DX, REG_BX, REG_SP, REG_BP, REG_SI, REG_DI,
    REG_R8W, REG_R9W, REG_R10W, REG_R11W, REG_R12W, REG_R13W, REG_R14W, REG_R15W,
    /* 32-bit registers */
    REG_EAX = 32, REG_ECX, REG_EDX, REG_EBX, REG_ESP, REG_EBP, REG_ESI, REG_EDI,
    REG_R8D, REG_R9D, REG_R10D, REG_R11D, REG_R12D, REG_R13D, REG_R14D, REG_R15D,
    /* 64-bit registers */
    REG_RAX = 48, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
    REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
    /* Segment registers */
    REG_ES = 64, REG_CS, REG_SS, REG_DS, REG_FS, REG_GS,
    /* Control registers */
    REG_CR0 = 70, REG_CR2, REG_CR3, REG_CR4, REG_CR8,
    /* Debug registers */
    REG_DR0 = 75, REG_DR1, REG_DR2, REG_DR3, REG_DR6, REG_DR7,
    /* MMX registers */
    REG_MM0 = 81, REG_MM1, REG_MM2, REG_MM3, REG_MM4, REG_MM5, REG_MM6, REG_MM7,
    /* XMM registers */
    REG_XMM0 = 89, REG_XMM1, REG_XMM2, REG_XMM3, REG_XMM4, REG_XMM5, REG_XMM6, REG_XMM7,
    REG_XMM8, REG_XMM9, REG_XMM10, REG_XMM11, REG_XMM12, REG_XMM13, REG_XMM14, REG_XMM15,
    /* YMM registers */
    REG_YMM0 = 105, REG_YMM1, REG_YMM2, REG_YMM3, REG_YMM4, REG_YMM5, REG_YMM6, REG_YMM7,
    REG_YMM8, REG_YMM9, REG_YMM10, REG_YMM11, REG_YMM12, REG_YMM13, REG_YMM14, REG_YMM15,
    /* ZMM registers (AVX-512) */
    REG_ZMM0 = 121, REG_ZMM1, REG_ZMM2, REG_ZMM3, REG_ZMM4, REG_ZMM5, REG_ZMM6, REG_ZMM7,
    REG_ZMM8, REG_ZMM9, REG_ZMM10, REG_ZMM11, REG_ZMM12, REG_ZMM13, REG_ZMM14, REG_ZMM15,
    REG_NONE = 255
} Register;

/* Register info structure */
typedef struct {
    const char *name;
    Register reg;
    int size;
    int id;      /* 0-7 for base, extended for R8-R15 */
    int needs_rex;
} RegInfo;

static const RegInfo g_registers[] = {
    /* 8-bit */
    {"al", REG_AL, 1, 0, 0}, {"cl", REG_CL, 1, 1, 0}, {"dl", REG_DL, 1, 2, 0}, {"bl", REG_BL, 1, 3, 0},
    {"ah", REG_AH, 1, 4, 0}, {"ch", REG_CH, 1, 5, 0}, {"dh", REG_DH, 1, 6, 0}, {"bh", REG_BH, 1, 7, 0},
    {"r8b", REG_R8B, 1, 0, 1}, {"r9b", REG_R9B, 1, 1, 1}, {"r10b", REG_R10B, 1, 2, 1}, {"r11b", REG_R11B, 1, 3, 1},
    {"r12b", REG_R12B, 1, 4, 1}, {"r13b", REG_R13B, 1, 5, 1}, {"r14b", REG_R14B, 1, 6, 1}, {"r15b", REG_R15B, 1, 7, 1},
    {"spl", REG_AH, 1, 4, 1}, {"bpl", REG_CH, 1, 5, 1}, {"sil", REG_DH, 1, 6, 1}, {"dil", REG_BH, 1, 7, 1},
    /* 16-bit */
    {"ax", REG_AX, 2, 0, 0}, {"cx", REG_CX, 2, 1, 0}, {"dx", REG_DX, 2, 2, 0}, {"bx", REG_BX, 2, 3, 0},
    {"sp", REG_SP, 2, 4, 0}, {"bp", REG_BP, 2, 5, 0}, {"si", REG_SI, 2, 6, 0}, {"di", REG_DI, 2, 7, 0},
    {"r8w", REG_R8W, 2, 0, 1}, {"r9w", REG_R9W, 2, 1, 1}, {"r10w", REG_R10W, 2, 2, 1}, {"r11w", REG_R11W, 2, 3, 1},
    {"r12w", REG_R12W, 2, 4, 1}, {"r13w", REG_R13W, 2, 5, 1}, {"r14w", REG_R14W, 2, 6, 1}, {"r15w", REG_R15W, 2, 7, 1},
    /* 32-bit */
    {"eax", REG_EAX, 4, 0, 0}, {"ecx", REG_ECX, 4, 1, 0}, {"edx", REG_EDX, 4, 2, 0}, {"ebx", REG_EBX, 4, 3, 0},
    {"esp", REG_ESP, 4, 4, 0}, {"ebp", REG_EBP, 4, 5, 0}, {"esi", REG_ESI, 4, 6, 0}, {"edi", REG_EDI, 4, 7, 0},
    {"r8d", REG_R8D, 4, 0, 1}, {"r9d", REG_R9D, 4, 1, 1}, {"r10d", REG_R10D, 4, 2, 1}, {"r11d", REG_R11D, 4, 3, 1},
    {"r12d", REG_R12D, 4, 4, 1}, {"r13d", REG_R13D, 4, 5, 1}, {"r14d", REG_R14D, 4, 6, 1}, {"r15d", REG_R15D, 4, 7, 1},
    /* 64-bit */
    {"rax", REG_RAX, 8, 0, 0}, {"rcx", REG_RCX, 8, 1, 0}, {"rdx", REG_RDX, 8, 2, 0}, {"rbx", REG_RBX, 8, 3, 0},
    {"rsp", REG_RSP, 8, 4, 0}, {"rbp", REG_RBP, 8, 5, 0}, {"rsi", REG_RSI, 8, 6, 0}, {"rdi", REG_RDI, 8, 7, 0},
    {"r8", REG_R8, 8, 0, 1}, {"r9", REG_R9, 8, 1, 1}, {"r10", REG_R10, 8, 2, 1}, {"r11", REG_R11, 8, 3, 1},
    {"r12", REG_R12, 8, 4, 1}, {"r13", REG_R13, 8, 5, 1}, {"r14", REG_R14, 8, 6, 1}, {"r15", REG_R15, 8, 7, 1},
    /* Segment */
    {"es", REG_ES, 2, 0, 0}, {"cs", REG_CS, 2, 1, 0}, {"ss", REG_SS, 2, 2, 0},
    {"ds", REG_DS, 2, 3, 0}, {"fs", REG_FS, 2, 4, 0}, {"gs", REG_GS, 2, 5, 0},
    /* Control */
    {"cr0", REG_CR0, 4, 0, 0}, {"cr2", REG_CR2, 4, 2, 0}, {"cr3", REG_CR3, 4, 3, 0},
    {"cr4", REG_CR4, 4, 4, 0}, {"cr8", REG_CR8, 4, 0, 1},
    /* Debug */
    {"dr0", REG_DR0, 4, 0, 0}, {"dr1", REG_DR1, 4, 1, 0}, {"dr2", REG_DR2, 4, 2, 0},
    {"dr3", REG_DR3, 4, 3, 0}, {"dr6", REG_DR6, 4, 6, 0}, {"dr7", REG_DR7, 4, 7, 0},
    /* MMX */
    {"mm0", REG_MM0, 8, 0, 0}, {"mm1", REG_MM1, 8, 1, 0}, {"mm2", REG_MM2, 8, 2, 0}, {"mm3", REG_MM3, 8, 3, 0},
    {"mm4", REG_MM4, 8, 4, 0}, {"mm5", REG_MM5, 8, 5, 0}, {"mm6", REG_MM6, 8, 6, 0}, {"mm7", REG_MM7, 8, 7, 0},
    /* XMM */
    {"xmm0", REG_XMM0, 16, 0, 0}, {"xmm1", REG_XMM1, 16, 1, 0}, {"xmm2", REG_XMM2, 16, 2, 0}, {"xmm3", REG_XMM3, 16, 3, 0},
    {"xmm4", REG_XMM4, 16, 4, 0}, {"xmm5", REG_XMM5, 16, 5, 0}, {"xmm6", REG_XMM6, 16, 6, 0}, {"xmm7", REG_XMM7, 16, 7, 0},
    {"xmm8", REG_XMM8, 16, 0, 1}, {"xmm9", REG_XMM9, 16, 1, 1}, {"xmm10", REG_XMM10, 16, 2, 1}, {"xmm11", REG_XMM11, 16, 3, 1},
    {"xmm12", REG_XMM12, 16, 4, 1}, {"xmm13", REG_XMM13, 16, 5, 1}, {"xmm14", REG_XMM14, 16, 6, 1}, {"xmm15", REG_XMM15, 16, 7, 1},
    /* YMM */
    {"ymm0", REG_YMM0, 32, 0, 0}, {"ymm1", REG_YMM1, 32, 1, 0}, {"ymm2", REG_YMM2, 32, 2, 0}, {"ymm3", REG_YMM3, 32, 3, 0},
    {"ymm4", REG_YMM4, 32, 4, 0}, {"ymm5", REG_YMM5, 32, 5, 0}, {"ymm6", REG_YMM6, 32, 6, 0}, {"ymm7", REG_YMM7, 32, 7, 0},
    {"ymm8", REG_YMM8, 32, 0, 1}, {"ymm9", REG_YMM9, 32, 1, 1}, {"ymm10", REG_YMM10, 32, 2, 1}, {"ymm11", REG_YMM11, 32, 3, 1},
    {"ymm12", REG_YMM12, 32, 4, 1}, {"ymm13", REG_YMM13, 32, 5, 1}, {"ymm14", REG_YMM14, 32, 6, 1}, {"ymm15", REG_YMM15, 32, 7, 1},
    /* ZMM (AVX-512) - 512-bit registers */
    {"zmm0", REG_ZMM0, 64, 0, 0}, {"zmm1", REG_ZMM1, 64, 1, 0}, {"zmm2", REG_ZMM2, 64, 2, 0}, {"zmm3", REG_ZMM3, 64, 3, 0},
    {"zmm4", REG_ZMM4, 64, 4, 0}, {"zmm5", REG_ZMM5, 64, 5, 0}, {"zmm6", REG_ZMM6, 64, 6, 0}, {"zmm7", REG_ZMM7, 64, 7, 0},
    {"zmm8", REG_ZMM8, 64, 0, 1}, {"zmm9", REG_ZMM9, 64, 1, 1}, {"zmm10", REG_ZMM10, 64, 2, 1}, {"zmm11", REG_ZMM11, 64, 3, 1},
    {"zmm12", REG_ZMM12, 64, 4, 1}, {"zmm13", REG_ZMM13, 64, 5, 1}, {"zmm14", REG_ZMM14, 64, 6, 1}, {"zmm15", REG_ZMM15, 64, 7, 1},
    {NULL, REG_NONE, 0, 0, 0}
};

/* Instruction encoding structure */
typedef struct {
    const char *mnemonic;
    uint8_t opcode[8];  /* Increased to 8 bytes for EVEX prefixes (AVX-512) */
    int opcode_len;
    int op1_type;
    int op2_type;
    int op3_type;
    int needs_modrm;
    int reg_field;  /* -1 = modrm reg field, 0-7 = fixed reg field */
    int immediate_size;
    int prefix;     /* 0x66, 0xF2, 0xF3, or 0 */
} InstructionEncoding;

/* Comprehensive instruction table - x86/x64/x32 compatible */
static const InstructionEncoding g_instructions[] = {
    /* Data movement - immediate forms first to avoid misclassification */
    {"mov", {0xB0}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"mov", {0xB8}, 1, OP_REG16, OP_IMM16, OP_NONE, 0, -1, 2, 0x66},
    {"mov", {0xB8}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"mov", {0xB8}, 1, OP_REG64, OP_IMM64, OP_NONE, 0, -1, 8, 0},
    {"mov", {0x88}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"mov", {0x89}, 1, OP_REG16, OP_REG16, OP_NONE, 1, -1, 0, 0x66},
    {"mov", {0x89}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"mov", {0x89}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"mov", {0x8A}, 1, OP_REG8, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"mov", {0x8B}, 1, OP_REG16, OP_MEM16, OP_NONE, 1, -1, 0, 0x66},
    {"mov", {0x8B}, 1, OP_REG32, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"mov", {0x8B}, 1, OP_REG64, OP_MEM64, OP_NONE, 1, -1, 0, 0},
    {"mov", {0x88}, 1, OP_MEM8, OP_REG8, OP_NONE, 1, 0, 0, 0},
    {"mov", {0x89}, 1, OP_MEM16, OP_REG16, OP_NONE, 1, 0, 0, 0x66},
    {"mov", {0x89}, 1, OP_MEM32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"mov", {0x89}, 1, OP_MEM64, OP_REG64, OP_NONE, 1, 0, 0, 0},
    {"mov", {0xC6}, 1, OP_MEM8, OP_IMM8, OP_NONE, 1, 0, 1, 0},
    {"mov", {0xC7}, 1, OP_MEM16, OP_IMM16, OP_NONE, 1, 0, 2, 0x66},
    {"mov", {0xC7}, 1, OP_MEM32, OP_IMM32, OP_NONE, 1, 0, 4, 0},
    {"mov", {0xC7}, 1, OP_MEM64, OP_IMM32, OP_NONE, 1, 0, 4, 0},
    {"movzx", {0x0F, 0xB6}, 2, OP_REG16, OP_REG8, OP_NONE, 1, -1, 0, 0x66},
    {"movzx", {0x0F, 0xB6}, 2, OP_REG32, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"movzx", {0x0F, 0xB6}, 2, OP_REG64, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"movzx", {0x0F, 0xB6}, 2, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"movzx", {0x0F, 0xB6}, 2, OP_REG64, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"movzx", {0x0F, 0xB7}, 2, OP_REG32, OP_REG16, OP_NONE, 1, -1, 0, 0},
    {"movzx", {0x0F, 0xB7}, 2, OP_REG64, OP_REG16, OP_NONE, 1, -1, 0, 0},
    {"movzx", {0x0F, 0xB7}, 2, OP_REG32, OP_MEM16, OP_NONE, 1, -1, 0, 0},
    {"movzx", {0x0F, 0xB7}, 2, OP_REG64, OP_MEM16, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBE}, 2, OP_REG16, OP_REG8, OP_NONE, 1, -1, 0, 0x66},
    {"movsx", {0x0F, 0xBE}, 2, OP_REG32, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBE}, 2, OP_REG64, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBE}, 2, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBE}, 2, OP_REG64, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBF}, 2, OP_REG32, OP_REG16, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBF}, 2, OP_REG64, OP_REG16, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBF}, 2, OP_REG32, OP_MEM16, OP_NONE, 1, -1, 0, 0},
    {"movsx", {0x0F, 0xBF}, 2, OP_REG64, OP_MEM16, OP_NONE, 1, -1, 0, 0},
    {"movsxd", {0x63}, 1, OP_REG64, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"movsxd", {0x63}, 1, OP_REG64, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"cmove", {0x0F, 0x44}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cmove", {0x0F, 0x44}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cmovne", {0x0F, 0x45}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cmovne", {0x0F, 0x45}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cmovl", {0x0F, 0x4C}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cmovl", {0x0F, 0x4C}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cmovge", {0x0F, 0x4D}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cmovge", {0x0F, 0x4D}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cmovle", {0x0F, 0x4E}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cmovle", {0x0F, 0x4E}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cmovg", {0x0F, 0x4F}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cmovg", {0x0F, 0x4F}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"xchg", {0x86}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"xchg", {0x87}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"xchg", {0x87}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"push", {0x50}, 1, OP_REG16, OP_NONE, OP_NONE, 0, -1, 0, 0x66},
    {"push", {0x50}, 1, OP_REG64, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"push", {0x6A}, 1, OP_IMM8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"push", {0x68}, 1, OP_IMM32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"pop", {0x58}, 1, OP_REG16, OP_NONE, OP_NONE, 0, -1, 0, 0x66},
    {"pop", {0x58}, 1, OP_REG64, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lea", {0x8D}, 1, OP_REG32, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"lea", {0x8D}, 1, OP_REG64, OP_MEM64, OP_NONE, 1, -1, 0, 0},

    /* Arithmetic */
    {"add", {0x00}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 0, 0, 0},
    {"add", {0x01}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"add", {0x01}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 0, 0, 0},
    {"add", {0x02}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"add", {0x03}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"add", {0x03}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"add", {0x04}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"add", {0x05}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"add", {0x05}, 1, OP_REG64, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"add", {0x80}, 1, OP_REG8, OP_IMM8, OP_NONE, 1, 0, 1, 0},
    {"add", {0x81}, 1, OP_REG32, OP_IMM32, OP_NONE, 1, 0, 4, 0},
    {"add", {0x81}, 1, OP_REG64, OP_IMM32, OP_NONE, 1, 0, 4, 0},
    {"add", {0x83}, 1, OP_REG32, OP_IMM8, OP_NONE, 1, 0, 1, 0},
    {"add", {0x83}, 1, OP_REG64, OP_IMM8, OP_NONE, 1, 0, 1, 0},
    {"sub", {0x28}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 0, 0, 0},
    {"sub", {0x29}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"sub", {0x29}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 0, 0, 0},
    {"sub", {0x2A}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"sub", {0x2B}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"sub", {0x2B}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"sub", {0x2C}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"sub", {0x2D}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"sub", {0x2D}, 1, OP_REG64, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"sub", {0x80}, 1, OP_REG8, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"sub", {0x81}, 1, OP_REG32, OP_IMM32, OP_NONE, 1, 5, 4, 0},
    {"sub", {0x81}, 1, OP_REG64, OP_IMM32, OP_NONE, 1, 5, 4, 0},
    {"sub", {0x83}, 1, OP_REG32, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"sub", {0x83}, 1, OP_REG64, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"adc", {0x10}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 0, 0, 0},
    {"adc", {0x11}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"adc", {0x11}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 0, 0, 0},
    {"sbb", {0x18}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 0, 0, 0},
    {"sbb", {0x19}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"sbb", {0x19}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 0, 0, 0},
    {"inc", {0x40}, 1, OP_REG32, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"inc", {0xFF}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"inc", {0xFF}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"dec", {0x48}, 1, OP_REG32, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"dec", {0xFF}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 1, 0, 0},
    {"dec", {0xFF}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 1, 0, 0},
    {"neg", {0xF6}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 3, 0, 0},
    {"neg", {0xF7}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 3, 0, 0},
    {"neg", {0xF7}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 3, 0, 0},
    {"not", {0xF6}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 2, 0, 0},
    {"not", {0xF7}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 2, 0, 0},
    {"not", {0xF7}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 2, 0, 0},

    /* Multiplication and Division */
    {"mul", {0xF6}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"mul", {0xF7}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"mul", {0xF7}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"imul", {0xF6}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 5, 0, 0},
    {"imul", {0xF7}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 5, 0, 0},
    {"imul", {0xF7}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 5, 0, 0},
    {"imul", {0x0F, 0xAF}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"imul", {0x0F, 0xAF}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"imul", {0x6B}, 1, OP_REG32, OP_IMM8, OP_NONE, 1, -1, 1, 0},
    {"imul", {0x6B}, 1, OP_REG64, OP_IMM8, OP_NONE, 1, -1, 1, 0},
    {"imul", {0x69}, 1, OP_REG32, OP_IMM32, OP_NONE, 1, -1, 4, 0},
    {"imul", {0x69}, 1, OP_REG64, OP_IMM32, OP_NONE, 1, -1, 4, 0},
    {"div", {0xF6}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 6, 0, 0},
    {"div", {0xF7}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 6, 0, 0},
    {"div", {0xF7}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 6, 0, 0},
    {"idiv", {0xF6}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 7, 0, 0},
    {"idiv", {0xF7}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 7, 0, 0},
    {"idiv", {0xF7}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 7, 0, 0},
    {"cqo", {0x48, 0x99}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cdq", {0x99}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cwd", {0x66, 0x99}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cbw", {0x66, 0x98}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cwde", {0x98}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cdqe", {0x48, 0x98}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* Logical */
    {"and", {0x20}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 0, 0, 0},
    {"and", {0x21}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"and", {0x21}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 0, 0, 0},
    {"and", {0x22}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"and", {0x23}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"and", {0x23}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"and", {0x24}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"and", {0x25}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"and", {0x25}, 1, OP_REG64, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"or", {0x08}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 1, 0, 0},
    {"or", {0x09}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 1, 0, 0},
    {"or", {0x09}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 1, 0, 0},
    {"or", {0x0A}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"or", {0x0B}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"or", {0x0B}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"or", {0x0C}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"or", {0x0D}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"or", {0x0D}, 1, OP_REG64, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"xor", {0x30}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 6, 0, 0},
    {"xor", {0x31}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 6, 0, 0},
    {"xor", {0x31}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 6, 0, 0},
    {"xor", {0x32}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"xor", {0x33}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"xor", {0x33}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"xor", {0x34}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"xor", {0x35}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"xor", {0x35}, 1, OP_REG64, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"not", {0xF6}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 2, 0, 0},
    {"not", {0xF7}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 2, 0, 0},
    {"not", {0xF7}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 2, 0, 0},

    /* Shifts and Rotates */
    {"shl", {0xD0}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"shl", {0xD1}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"shl", {0xD1}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"shl", {0xC0}, 1, OP_REG8, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"shl", {0xC1}, 1, OP_REG32, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"shl", {0xC1}, 1, OP_REG64, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"shl", {0xD2}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 4, 0, 0},
    {"shl", {0xD3}, 1, OP_REG32, OP_REG8, OP_NONE, 1, 4, 0, 0},
    {"shl", {0xD3}, 1, OP_REG64, OP_REG8, OP_NONE, 1, 4, 0, 0},
    {"shr", {0xD0}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 5, 0, 0},
    {"shr", {0xD1}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 5, 0, 0},
    {"shr", {0xD1}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 5, 0, 0},
    {"shr", {0xC0}, 1, OP_REG8, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"shr", {0xC1}, 1, OP_REG32, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"shr", {0xC1}, 1, OP_REG64, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"shr", {0xD2}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 5, 0, 0},
    {"shr", {0xD3}, 1, OP_REG32, OP_REG8, OP_NONE, 1, 5, 0, 0},
    {"shr", {0xD3}, 1, OP_REG64, OP_REG8, OP_NONE, 1, 5, 0, 0},
    {"sar", {0xD0}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 7, 0, 0},
    {"sar", {0xD1}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 7, 0, 0},
    {"sar", {0xD1}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 7, 0, 0},
    {"sar", {0xC0}, 1, OP_REG8, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"sar", {0xC1}, 1, OP_REG32, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"sar", {0xC1}, 1, OP_REG64, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"rol", {0xD0}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"rol", {0xD1}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"ror", {0xD0}, 1, OP_REG8, OP_NONE, OP_NONE, 1, 1, 0, 0},
    {"ror", {0xD1}, 1, OP_REG32, OP_NONE, OP_NONE, 1, 1, 0, 0},

    /* Comparison */
    {"cmp", {0x38}, 1, OP_REG8, OP_REG8, OP_NONE, 1, 7, 0, 0},
    {"cmp", {0x39}, 1, OP_REG32, OP_REG32, OP_NONE, 1, 7, 0, 0},
    {"cmp", {0x39}, 1, OP_REG64, OP_REG64, OP_NONE, 1, 7, 0, 0},
    {"cmp", {0x3A}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"cmp", {0x3B}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cmp", {0x3B}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cmp", {0x3C}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"cmp", {0x3D}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"cmp", {0x3D}, 1, OP_REG64, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"cmp", {0x80}, 1, OP_REG8, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"cmp", {0x81}, 1, OP_REG32, OP_IMM32, OP_NONE, 1, 7, 4, 0},
    {"cmp", {0x81}, 1, OP_REG64, OP_IMM32, OP_NONE, 1, 7, 4, 0},
    {"cmp", {0x83}, 1, OP_REG32, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"cmp", {0x83}, 1, OP_REG64, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"test", {0x84}, 1, OP_REG8, OP_REG8, OP_NONE, 1, -1, 0, 0},
    {"test", {0x85}, 1, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"test", {0x85}, 1, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"test", {0xA8}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"test", {0xA9}, 1, OP_REG32, OP_IMM32, OP_NONE, 0, -1, 4, 0},
    {"test", {0xA9}, 1, OP_REG64, OP_IMM32, OP_NONE, 0, -1, 4, 0},

    /* Set byte on condition */
    {"sete", {0x0F, 0x94}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setne", {0x0F, 0x95}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setl", {0x0F, 0x9C}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setle", {0x0F, 0x9E}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setg", {0x0F, 0x9F}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setge", {0x0F, 0x9D}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"seta", {0x0F, 0x97}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setae", {0x0F, 0x93}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setb", {0x0F, 0x92}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setbe", {0x0F, 0x96}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"sets", {0x0F, 0x98}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setns", {0x0F, 0x99}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"seto", {0x0F, 0x90}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setno", {0x0F, 0x91}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setp", {0x0F, 0x9A}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},
    {"setnp", {0x0F, 0x9B}, 2, OP_REG8, OP_NONE, OP_NONE, 1, 0, 0, 0},

    /* Branches */
    {"jmp", {0xEB}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jmp", {0xE9}, 1, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jmp", {0xFF}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"jmp", {0xFF}, 1, OP_MEM64, OP_NONE, OP_NONE, 1, 4, 0, 0},
    {"call", {0xE8}, 1, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"call", {0xFF}, 1, OP_REG64, OP_NONE, OP_NONE, 1, 2, 0, 0},
    {"call", {0xFF}, 1, OP_MEM64, OP_NONE, OP_NONE, 1, 2, 0, 0},
    {"ret", {0xC3}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"ret", {0xC2}, 1, OP_IMM16, OP_NONE, OP_NONE, 0, -1, 2, 0},
    {"je", {0x74}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"je", {0x0F, 0x84}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jz", {0x74}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},  /* Alias for JE */
    {"jz", {0x0F, 0x84}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jne", {0x75}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jne", {0x0F, 0x85}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jnz", {0x75}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},  /* Alias for JNE */
    {"jnz", {0x0F, 0x85}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jl", {0x7C}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jl", {0x0F, 0x8C}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jle", {0x7E}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jle", {0x0F, 0x8E}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jg", {0x7F}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jg", {0x0F, 0x8F}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jge", {0x7D}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jge", {0x0F, 0x8D}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"ja", {0x77}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"ja", {0x0F, 0x87}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jae", {0x73}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jae", {0x0F, 0x83}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jb", {0x72}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jb", {0x0F, 0x82}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jbe", {0x76}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jbe", {0x0F, 0x86}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"js", {0x78}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"js", {0x0F, 0x88}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jns", {0x79}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jns", {0x0F, 0x89}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jo", {0x70}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jo", {0x0F, 0x80}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jno", {0x71}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jno", {0x0F, 0x81}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jp", {0x7A}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jp", {0x0F, 0x8A}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jnp", {0x7B}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jnp", {0x0F, 0x8B}, 2, OP_REL32, OP_NONE, OP_NONE, 0, -1, 4, 0},
    {"jcxz", {0xE3}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0x66},
    {"jecxz", {0xE3}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"jrcxz", {0xE3}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"loop", {0xE2}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"loope", {0xE1}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"loopne", {0xE0}, 1, OP_REL8, OP_NONE, OP_NONE, 0, -1, 1, 0},

    /* System */
    {"syscall", {0x0F, 0x05}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"sysret", {0x0F, 0x07}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"sysenter", {0x0F, 0x34}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"sysexit", {0x0F, 0x35}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"int", {0xCD}, 1, OP_IMM8, OP_NONE, OP_NONE, 0, -1, 1, 0},
    {"int3", {0xCC}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"into", {0xCE}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"iret", {0xCF}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"iretd", {0xCF}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"iretq", {0x48, 0xCF}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cli", {0xFA}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"sti", {0xFB}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cld", {0xFC}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"std", {0xFD}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"clc", {0xF8}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"stc", {0xF9}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cmc", {0xF5}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lahf", {0x9F}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"sahf", {0x9E}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"pushf", {0x9C}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"pushfd", {0x9C}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"pushfq", {0x9C}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"popf", {0x9D}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"popfd", {0x9D}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"popfq", {0x9D}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cpuid", {0x0F, 0xA2}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rdtsc", {0x0F, 0x31}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rdtscp", {0x0F, 0x01, 0xF9}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rdmsr", {0x0F, 0x32}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"wrmsr", {0x0F, 0x30}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"invd", {0x0F, 0x08}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"wbinvd", {0x0F, 0x09}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"hlt", {0xF4}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"nop", {0x90}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"pause", {0xF3, 0x90}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"ud2", {0x0F, 0x0B}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lfence", {0x0F, 0xAE, 0xE8}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"sfence", {0x0F, 0xAE, 0xF8}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"mfence", {0x0F, 0xAE, 0xF0}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* SSE Instructions - Packed single-precision floating-point */
    {"movaps", {0x0F, 0x28}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movaps", {0x0F, 0x28}, 2, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"movaps", {0x0F, 0x29}, 2, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movups", {0x0F, 0x10}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movups", {0x0F, 0x10}, 2, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"movups", {0x0F, 0x11}, 2, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movss", {0xF3, 0x0F, 0x10}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movss", {0xF3, 0x0F, 0x10}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"movss", {0xF3, 0x0F, 0x11}, 3, OP_MEM32, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"addss", {0xF3, 0x0F, 0x58}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"addss", {0xF3, 0x0F, 0x58}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"subss", {0xF3, 0x0F, 0x5C}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"subss", {0xF3, 0x0F, 0x5C}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"mulss", {0xF3, 0x0F, 0x59}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"mulss", {0xF3, 0x0F, 0x59}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"divss", {0xF3, 0x0F, 0x5E}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"divss", {0xF3, 0x0F, 0x5E}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"sqrtss", {0xF3, 0x0F, 0x51}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"sqrtss", {0xF3, 0x0F, 0x51}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"maxss", {0xF3, 0x0F, 0x5F}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"minss", {0xF3, 0x0F, 0x5D}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"rcpss", {0xF3, 0x0F, 0x53}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"rsqrtss", {0xF3, 0x0F, 0x52}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"addps", {0x0F, 0x58}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"addps", {0x0F, 0x58}, 2, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"subps", {0x0F, 0x5C}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"subps", {0x0F, 0x5C}, 2, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"mulps", {0x0F, 0x59}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"mulps", {0x0F, 0x59}, 2, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"divps", {0x0F, 0x5E}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"divps", {0x0F, 0x5E}, 2, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"maxps", {0x0F, 0x5F}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"minps", {0x0F, 0x5D}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"sqrtps", {0x0F, 0x51}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"rsqrtps", {0x0F, 0x52}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"rcpps", {0x0F, 0x53}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"andps", {0x0F, 0x54}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"andnps", {0x0F, 0x55}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"orps", {0x0F, 0x56}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"xorps", {0x0F, 0x57}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cmpps", {0x0F, 0xC2}, 2, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"shufps", {0x0F, 0xC6}, 2, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"unpcklps", {0x0F, 0x14}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"unpckhps", {0x0F, 0x15}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvtpi2ps", {0x0F, 0x2A}, 2, OP_XMM, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cvtps2pi", {0x0F, 0x2D}, 2, OP_REG64, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvtsi2ss", {0xF3, 0x0F, 0x2A}, 3, OP_XMM, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cvtss2si", {0xF3, 0x0F, 0x2D}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvttss2si", {0xF3, 0x0F, 0x2C}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},

    /* SSE2 Instructions - Packed double-precision floating-point */
    {"movapd", {0x66, 0x0F, 0x28}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movapd", {0x66, 0x0F, 0x28}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"movapd", {0x66, 0x0F, 0x29}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movupd", {0x66, 0x0F, 0x10}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movupd", {0x66, 0x0F, 0x10}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"movupd", {0x66, 0x0F, 0x11}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movsd", {0xF2, 0x0F, 0x10}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movsd", {0xF2, 0x0F, 0x10}, 3, OP_XMM, OP_MEM64, OP_NONE, 1, -1, 0, 0},
    {"movsd", {0xF2, 0x0F, 0x11}, 3, OP_MEM64, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"addpd", {0x66, 0x0F, 0x58}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"addpd", {0x66, 0x0F, 0x58}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"subpd", {0x66, 0x0F, 0x5C}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"subpd", {0x66, 0x0F, 0x5C}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"mulpd", {0x66, 0x0F, 0x59}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"mulpd", {0x66, 0x0F, 0x59}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"divpd", {0x66, 0x0F, 0x5E}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"divpd", {0x66, 0x0F, 0x5E}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"maxpd", {0x66, 0x0F, 0x5F}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"minpd", {0x66, 0x0F, 0x5D}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"sqrtpd", {0x66, 0x0F, 0x51}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"andpd", {0x66, 0x0F, 0x54}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"andnpd", {0x66, 0x0F, 0x55}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"orpd", {0x66, 0x0F, 0x56}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"xorpd", {0x66, 0x0F, 0x57}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cmppd", {0x66, 0x0F, 0xC2}, 3, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"shufpd", {0x66, 0x0F, 0xC6}, 3, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"cvtps2pd", {0x0F, 0x5A}, 2, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvtpd2ps", {0x66, 0x0F, 0x5A}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvtsi2sd", {0xF2, 0x0F, 0x2A}, 3, OP_XMM, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"cvtsi2sd", {0xF2, 0x0F, 0x2A}, 3, OP_XMM, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"cvtsd2si", {0xF2, 0x0F, 0x2D}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvtsd2si", {0xF2, 0x0F, 0x2D}, 3, OP_REG64, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvttsd2si", {0xF2, 0x0F, 0x2C}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"cvttsd2si", {0xF2, 0x0F, 0x2C}, 3, OP_REG64, OP_XMM, OP_NONE, 1, -1, 0, 0},

    /* SSE/AVX integer SIMD */
    {"movdqa", {0x66, 0x0F, 0x6F}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movdqa", {0x66, 0x0F, 0x6F}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"movdqa", {0x66, 0x0F, 0x7F}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movdqu", {0xF3, 0x0F, 0x6F}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movdqu", {0xF3, 0x0F, 0x6F}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"movdqu", {0xF3, 0x0F, 0x7F}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movd", {0x66, 0x0F, 0x6E}, 3, OP_XMM, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"movd", {0x66, 0x0F, 0x6E}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"movd", {0x66, 0x0F, 0x7E}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movd", {0x66, 0x0F, 0x7E}, 3, OP_MEM32, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movq", {0x66, 0x0F, 0xD6}, 3, OP_MEM64, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"movq", {0xF3, 0x0F, 0x7E}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"movq", {0xF3, 0x0F, 0x7E}, 3, OP_XMM, OP_MEM64, OP_NONE, 1, -1, 0, 0},
    {"paddb", {0x66, 0x0F, 0xFC}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"paddb", {0x66, 0x0F, 0xFC}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"paddw", {0x66, 0x0F, 0xFD}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"paddw", {0x66, 0x0F, 0xFD}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"paddd", {0x66, 0x0F, 0xFE}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"paddd", {0x66, 0x0F, 0xFE}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"paddq", {0x66, 0x0F, 0xD4}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"paddq", {0x66, 0x0F, 0xD4}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"psubb", {0x66, 0x0F, 0xF8}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"psubb", {0x66, 0x0F, 0xF8}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"psubw", {0x66, 0x0F, 0xF9}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"psubw", {0x66, 0x0F, 0xF9}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"psubd", {0x66, 0x0F, 0xFA}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"psubd", {0x66, 0x0F, 0xFA}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"psubq", {0x66, 0x0F, 0xFB}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"psubq", {0x66, 0x0F, 0xFB}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"pmullw", {0x66, 0x0F, 0xD5}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"pmullw", {0x66, 0x0F, 0xD5}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"pmulld", {0x66, 0x0F, 0x38, 0x40}, 4, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"pmulld", {0x66, 0x0F, 0x38, 0x40}, 4, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"pmuludq", {0x66, 0x0F, 0xF4}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"pmuludq", {0x66, 0x0F, 0xF4}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"pxor", {0x66, 0x0F, 0xEF}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"pxor", {0x66, 0x0F, 0xEF}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"por", {0x66, 0x0F, 0xEB}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"por", {0x66, 0x0F, 0xEB}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"pand", {0x66, 0x0F, 0xDB}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"pand", {0x66, 0x0F, 0xDB}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"pandn", {0x66, 0x0F, 0xDF}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"pandn", {0x66, 0x0F, 0xDF}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"psllw", {0x66, 0x0F, 0x71}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"pslld", {0x66, 0x0F, 0x72}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"psllq", {0x66, 0x0F, 0x73}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"psrlw", {0x66, 0x0F, 0x71}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"psrld", {0x66, 0x0F, 0x72}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"psrlq", {0x66, 0x0F, 0x73}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"psraw", {0x66, 0x0F, 0x71}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"psrad", {0x66, 0x0F, 0x72}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"pslldq", {0x66, 0x0F, 0x73}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"psrldq", {0x66, 0x0F, 0x73}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 3, 1, 0},
    {"punpcklbw", {0x66, 0x0F, 0x60}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpcklbw", {0x66, 0x0F, 0x60}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"punpcklwd", {0x66, 0x0F, 0x61}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpcklwd", {0x66, 0x0F, 0x61}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"punpckldq", {0x66, 0x0F, 0x62}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpckldq", {0x66, 0x0F, 0x62}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"punpcklqdq", {0x66, 0x0F, 0x6C}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpcklqdq", {0x66, 0x0F, 0x6C}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"punpckhbw", {0x66, 0x0F, 0x68}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpckhbw", {0x66, 0x0F, 0x68}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"punpckhwd", {0x66, 0x0F, 0x69}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpckhwd", {0x66, 0x0F, 0x69}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"punpckhdq", {0x66, 0x0F, 0x6A}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpckhdq", {0x66, 0x0F, 0x6A}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"punpckhqdq", {0x66, 0x0F, 0x6D}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"punpckhqdq", {0x66, 0x0F, 0x6D}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    /* SSE insert/extract */
    {"pinsrw", {0x66, 0x0F, 0xC4}, 3, OP_XMM, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"pinsrw", {0x66, 0x0F, 0xC4}, 3, OP_XMM, OP_MEM16, OP_IMM8, 1, -1, 1, 0},
    {"pinsrb", {0x66, 0x0F, 0x3A, 0x20}, 4, OP_XMM, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"pinsrb", {0x66, 0x0F, 0x3A, 0x20}, 4, OP_XMM, OP_MEM8, OP_IMM8, 1, -1, 1, 0},
    {"pinsrd", {0x66, 0x0F, 0x3A, 0x22}, 4, OP_XMM, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"pinsrd", {0x66, 0x0F, 0x3A, 0x22}, 4, OP_XMM, OP_MEM32, OP_IMM8, 1, -1, 1, 0},
    {"pextrw", {0x66, 0x0F, 0xC5}, 3, OP_REG32, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pextrw", {0x66, 0x0F, 0x3A, 0x15}, 4, OP_MEM16, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pextrb", {0x66, 0x0F, 0x3A, 0x14}, 4, OP_REG32, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pextrb", {0x66, 0x0F, 0x3A, 0x14}, 4, OP_MEM8, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pextrd", {0x66, 0x0F, 0x3A, 0x16}, 4, OP_REG32, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pextrd", {0x66, 0x0F, 0x3A, 0x16}, 4, OP_MEM32, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pshufd", {0x66, 0x0F, 0x70}, 3, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pshufd", {0x66, 0x0F, 0x70}, 3, OP_XMM, OP_MEM128, OP_IMM8, 1, -1, 1, 0},
    {"pshuflw", {0xF2, 0x0F, 0x70}, 3, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pshuflw", {0xF2, 0x0F, 0x70}, 3, OP_XMM, OP_MEM128, OP_IMM8, 1, -1, 1, 0},
    {"pshufhw", {0xF3, 0x0F, 0x70}, 3, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"pshufhw", {0xF3, 0x0F, 0x70}, 3, OP_XMM, OP_MEM128, OP_IMM8, 1, -1, 1, 0},
    {"pcmpeqb", {0x66, 0x0F, 0x74}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pcmpeqw", {0x66, 0x0F, 0x75}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pcmpeqd", {0x66, 0x0F, 0x76}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pcmpeqq", {0x66, 0x0F, 0x38, 0x29}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pcmpgtb", {0x66, 0x0F, 0x64}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pcmpgtw", {0x66, 0x0F, 0x65}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pcmpgtd", {0x66, 0x0F, 0x66}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pcmpgtq", {0x66, 0x0F, 0x38, 0x37}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pmaxub", {0x66, 0x0F, 0xDE}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pmaxuw", {0x66, 0x0F, 0x38, 0x3E}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pmaxud", {0x66, 0x0F, 0x38, 0x3F}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pminub", {0x66, 0x0F, 0xDA}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pminuw", {0x66, 0x0F, 0x38, 0x3A}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"pminud", {0x66, 0x0F, 0x38, 0x3B}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},

    /* AVX Instructions - VEX-encoded */
    {"vmovaps", {0xC5, 0xF8, 0x28}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vmovaps", {0xC5, 0xF8, 0x28}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x10}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x10}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x11}, 3, OP_MEM256, OP_YMM, OP_NONE, 1, 0, 0, 0},
    {"vmovss", {0xC5, 0xFA, 0x10}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovss", {0xC5, 0xFA, 0x10}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vaddps", {0xC5, 0xF8, 0x58}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vaddps", {0xC5, 0xF8, 0x58}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vsubps", {0xC5, 0xF8, 0x5C}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vmulps", {0xC5, 0xF8, 0x59}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vmulps", {0xC5, 0xF8, 0x59}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vdivps", {0xC5, 0xF8, 0x5E}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vmaxps", {0xC5, 0xF8, 0x5F}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vminps", {0xC5, 0xF8, 0x5D}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vsqrtps", {0xC5, 0xF8, 0x51}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vrsqrtps", {0xC5, 0xF8, 0x52}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vrcpps", {0xC5, 0xF8, 0x53}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vandps", {0xC5, 0xF8, 0x54}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vandnps", {0xC5, 0xF8, 0x55}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vorps", {0xC5, 0xF8, 0x56}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vxorps", {0xC5, 0xF8, 0x57}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vxorps", {0xC5, 0xF8, 0x57}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vxorps", {0xC5, 0xF8, 0x57}, 3, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},
    {"vcmpps", {0xC5, 0xF8, 0xC2}, 3, OP_YMM, OP_YMM, OP_IMM8, 1, -1, 1, 0},
    /* AVX scalar single-precision */
    {"vmovss", {0xC5, 0xFA, 0x10}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovss", {0xC5, 0xFA, 0x10}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vmulss", {0xC5, 0xFA, 0x59}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vmulss", {0xC5, 0xFA, 0x59}, 3, OP_XMM, OP_XMM, OP_MEM32, 1, -1, 0, 0},
    {"vaddss", {0xC5, 0xFA, 0x58}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vaddss", {0xC5, 0xFA, 0x58}, 3, OP_XMM, OP_XMM, OP_MEM32, 1, -1, 0, 0},
    {"vsubss", {0xC5, 0xFA, 0x5C}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vsubss", {0xC5, 0xFA, 0x5C}, 3, OP_XMM, OP_XMM, OP_MEM32, 1, -1, 0, 0},
    {"vdivss", {0xC5, 0xFA, 0x5E}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vdivss", {0xC5, 0xFA, 0x5E}, 3, OP_XMM, OP_XMM, OP_MEM32, 1, -1, 0, 0},
    {"vsqrtss", {0xC5, 0xFA, 0x51}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vsqrtss", {0xC5, 0xFA, 0x51}, 3, OP_XMM, OP_XMM, OP_MEM32, 1, -1, 0, 0},
    /* F16C - Half-precision conversions */
    {"vcvtph2ps", {0xC4, 0xE2, 0x79, 0x13}, 4, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vcvtph2ps", {0xC4, 0xE2, 0x79, 0x13}, 4, OP_XMM, OP_MEM64, OP_NONE, 1, -1, 0, 0},
    {"vcvtph2ps", {0xC4, 0xE2, 0x7D, 0x13}, 4, OP_YMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vcvtph2ps", {0xC4, 0xE2, 0x7D, 0x13}, 4, OP_YMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"vcvtps2ph", {0xC4, 0xE3, 0x79, 0x1D}, 4, OP_XMM, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"vcvtps2ph", {0xC4, 0xE3, 0x79, 0x1D}, 4, OP_MEM64, OP_XMM, OP_IMM8, 1, -1, 1, 0},
    {"vcvtps2ph", {0xC4, 0xE3, 0x7D, 0x1D}, 4, OP_XMM, OP_YMM, OP_IMM8, 1, -1, 1, 0},
    {"vcvtps2ph", {0xC4, 0xE3, 0x7D, 0x1D}, 4, OP_MEM128, OP_YMM, OP_IMM8, 1, -1, 1, 0},
    {"vshufps", {0xC5, 0xF8, 0xC6}, 3, OP_YMM, OP_YMM, OP_IMM8, 1, -1, 1, 0},
    {"vunpcklps", {0xC5, 0xF8, 0x14}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vunpckhps", {0xC5, 0xF8, 0x15}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vcvtps2pd", {0xC5, 0xF8, 0x5A}, 3, OP_YMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vcvtpd2ps", {0xC5, 0xF9, 0x5A}, 3, OP_XMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vcvtsi2ss", {0xC5, 0xFA, 0x2A}, 3, OP_XMM, OP_XMM, OP_REG32, 1, -1, 0, 0},
    {"vcvtss2si", {0xC5, 0xFA, 0x2D}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vcvttss2si", {0xC5, 0xFA, 0x2C}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},

    /* AVX double-precision */
    {"vmovapd", {0xC5, 0xF9, 0x28}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vmovupd", {0xC5, 0xF9, 0x10}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vmovsd", {0xC5, 0xFB, 0x10}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vaddpd", {0xC5, 0xF9, 0x58}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vsubpd", {0xC5, 0xF9, 0x5C}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vmulpd", {0xC5, 0xF9, 0x59}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vdivpd", {0xC5, 0xF9, 0x5E}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vmaxpd", {0xC5, 0xF9, 0x5F}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vminpd", {0xC5, 0xF9, 0x5D}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vsqrtpd", {0xC5, 0xF9, 0x51}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vandpd", {0xC5, 0xF9, 0x54}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vandnpd", {0xC5, 0xF9, 0x55}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vorpd", {0xC5, 0xF9, 0x56}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vxorpd", {0xC5, 0xF9, 0x57}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vcmppd", {0xC5, 0xF9, 0xC2}, 3, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vshufpd", {0xC5, 0xF9, 0xC6}, 3, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},

    /* AVX integer SIMD */
    {"vmovdqa", {0xC5, 0xF9, 0x6F}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu", {0xC5, 0xFA, 0x6F}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vmovd", {0xC5, 0xF9, 0x6E}, 3, OP_XMM, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vmovd", {0xC5, 0xF9, 0x6E}, 3, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vmovd", {0xC5, 0xF9, 0x7E}, 3, OP_REG32, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovd", {0xC5, 0xF9, 0x7E}, 3, OP_MEM32, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovq", {0xC5, 0xF9, 0xD6}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vpaddb", {0xC5, 0xF9, 0xFC}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpaddw", {0xC5, 0xF9, 0xFD}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpaddd", {0xC5, 0xF9, 0xFE}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpaddq", {0xC5, 0xF9, 0xD4}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpsubb", {0xC5, 0xF9, 0xF8}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpsubw", {0xC5, 0xF9, 0xF9}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpsubd", {0xC5, 0xF9, 0xFA}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpsubq", {0xC5, 0xF9, 0xFB}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpmullw", {0xC5, 0xF9, 0xD5}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpmulld", {0xC4, 0xE2, 0x79, 0x40}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpmuludq", {0xC5, 0xF9, 0xF4}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpxor", {0xC5, 0xF9, 0xEF}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpor", {0xC5, 0xF9, 0xEB}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpand", {0xC5, 0xF9, 0xDB}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpandn", {0xC5, 0xF9, 0xDF}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpsllw", {0xC5, 0xF9, 0x71}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpslld", {0xC5, 0xF9, 0x72}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpsllq", {0xC5, 0xF9, 0x73}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpsrlw", {0xC5, 0xF9, 0x71}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"vpsrld", {0xC5, 0xF9, 0x72}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"vpsrlq", {0xC5, 0xF9, 0x73}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"vpsraw", {0xC5, 0xF9, 0x71}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"vpsrad", {0xC5, 0xF9, 0x72}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"vpslldq", {0xC5, 0xF9, 0x73}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"vpsrldq", {0xC5, 0xF9, 0x73}, 3, OP_REG32, OP_IMM8, OP_NONE, 1, 3, 1, 0},
    {"vpunpcklbw", {0xC5, 0xF9, 0x60}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpunpcklwd", {0xC5, 0xF9, 0x61}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpunpckldq", {0xC5, 0xF9, 0x62}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpunpcklqdq", {0xC5, 0xF9, 0x6C}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpunpckhbw", {0xC5, 0xF9, 0x68}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpunpckhwd", {0xC5, 0xF9, 0x69}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpunpckhdq", {0xC5, 0xF9, 0x6A}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpunpckhqdq", {0xC5, 0xF9, 0x6D}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpshufd", {0xC5, 0xF9, 0x70}, 3, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vpshuflw", {0xC5, 0xFA, 0x70}, 3, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vpshufhw", {0xC5, 0xFB, 0x70}, 3, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vpbroadcastb", {0xC4, 0xE2, 0x79, 0x78}, 4, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"vpbroadcastw", {0xC4, 0xE2, 0x79, 0x79}, 4, OP_REG32, OP_MEM16, OP_NONE, 1, -1, 0, 0},
    {"vpbroadcastd", {0xC4, 0xE2, 0x79, 0x58}, 4, OP_REG32, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vpbroadcastq", {0xC4, 0xE2, 0x79, 0x59}, 4, OP_REG32, OP_MEM64, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastss", {0xC4, 0xE2, 0x79, 0x18}, 4, OP_YMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastss", {0xC4, 0xE2, 0x79, 0x18}, 4, OP_XMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastss", {0xC4, 0xE2, 0x7D, 0x18}, 4, OP_YMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastss", {0xC4, 0xE2, 0x79, 0x18}, 4, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastss", {0xC4, 0xE2, 0x7D, 0x18}, 4, OP_ZMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastss", {0xC4, 0xE2, 0x7D, 0x18}, 4, OP_ZMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastsd", {0xC4, 0xE2, 0x79, 0x19}, 4, OP_REG32, OP_MEM64, OP_NONE, 1, -1, 0, 0},
    {"vpclmulqdq", {0xC4, 0xE3, 0x79, 0x44}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vaesenc", {0xC4, 0xE2, 0x79, 0xDC}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vaesenclast", {0xC4, 0xE2, 0x79, 0xDD}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vaesdec", {0xC4, 0xE2, 0x79, 0xDE}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vaesdeclast", {0xC4, 0xE2, 0x79, 0xDF}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vaeskeygenassist", {0xC4, 0xE3, 0x79, 0xDF}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vpclmullqlqdq", {0xC4, 0xE3, 0x79, 0x44}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},

    /* FMA Instructions */
    {"vfmadd213ps", {0xC4, 0xE2, 0x69, 0xA8}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd213pd", {0xC4, 0xE2, 0x69, 0xA8}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd213ss", {0xC4, 0xE2, 0x69, 0xA9}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd213sd", {0xC4, 0xE2, 0x69, 0xA9}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd132ps", {0xC4, 0xE2, 0x69, 0x98}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd132pd", {0xC4, 0xE2, 0x69, 0x98}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd132ss", {0xC4, 0xE2, 0x69, 0x99}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd132sd", {0xC4, 0xE2, 0x69, 0x99}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd231ps", {0xC4, 0xE2, 0x69, 0xB8}, 4, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vfmadd231ps", {0xC4, 0xE2, 0x69, 0xB8}, 4, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vfmadd231ps", {0xC4, 0xE2, 0x69, 0xB8}, 4, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vfmadd231ps", {0xC4, 0xE2, 0x69, 0xB8}, 4, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},
    {"vfmadd231pd", {0xC4, 0xE2, 0x69, 0xB8}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd231ss", {0xC4, 0xE2, 0x69, 0xB9}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmadd231sd", {0xC4, 0xE2, 0x69, 0xB9}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfnmadd213ps", {0xC4, 0xE2, 0x69, 0xAC}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfnmadd213pd", {0xC4, 0xE2, 0x69, 0xAC}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfnmadd132ps", {0xC4, 0xE2, 0x69, 0x9C}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfnmadd132pd", {0xC4, 0xE2, 0x69, 0x9C}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfnmadd231ps", {0xC4, 0xE2, 0x69, 0xBC}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfnmadd231pd", {0xC4, 0xE2, 0x69, 0xBC}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmsub213ps", {0xC4, 0xE2, 0x69, 0xAA}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmsub213pd", {0xC4, 0xE2, 0x69, 0xAA}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmsub132ps", {0xC4, 0xE2, 0x69, 0x9A}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmsub132pd", {0xC4, 0xE2, 0x69, 0x9A}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmsub231ps", {0xC4, 0xE2, 0x69, 0xBA}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vfmsub231pd", {0xC4, 0xE2, 0x69, 0xBA}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},

    /* AVX-512 Instructions (subset for kernels) */
    {"vpmovsxbd", {0xC4, 0xE2, 0x79, 0x21}, 4, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"vpmovsxbq", {0xC4, 0xE2, 0x79, 0x22}, 4, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"vpmovsxdq", {0xC4, 0xE2, 0x79, 0x25}, 4, OP_REG32, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxwd", {0xC4, 0xE2, 0x79, 0x33}, 4, OP_REG32, OP_MEM16, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxdq", {0xC4, 0xE2, 0x79, 0x35}, 4, OP_REG32, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vpmovsxbw", {0xC4, 0xE2, 0x79, 0x20}, 4, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxbw", {0xC4, 0xE2, 0x79, 0x30}, 4, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxbd", {0xC4, 0xE2, 0x79, 0x31}, 4, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxbq", {0xC4, 0xE2, 0x79, 0x32}, 4, OP_REG32, OP_MEM8, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxwq", {0xC4, 0xE2, 0x79, 0x34}, 4, OP_REG32, OP_MEM16, OP_NONE, 1, -1, 0, 0},

    /* AVX2 Gather/Scatter */
    {"vpgatherdd", {0xC4, 0xE2, 0x79, 0x90}, 4, OP_REG32, OP_MEM32, OP_REG32, 1, -1, 0, 0},
    {"vpgatherdq", {0xC4, 0xE2, 0x79, 0x90}, 4, OP_REG32, OP_MEM64, OP_REG32, 1, -1, 0, 0},
    {"vpgatherqd", {0xC4, 0xE2, 0x79, 0x91}, 4, OP_REG32, OP_MEM32, OP_REG32, 1, -1, 0, 0},
    {"vpgatherqq", {0xC4, 0xE2, 0x79, 0x91}, 4, OP_REG32, OP_MEM64, OP_REG32, 1, -1, 0, 0},
    {"vgatherdps", {0xC4, 0xE2, 0x79, 0x92}, 4, OP_REG32, OP_MEM32, OP_REG32, 1, -1, 0, 0},
    {"vgatherdpd", {0xC4, 0xE2, 0x79, 0x92}, 4, OP_REG32, OP_MEM64, OP_REG32, 1, -1, 0, 0},
    {"vgatherqps", {0xC4, 0xE2, 0x79, 0x93}, 4, OP_REG32, OP_MEM32, OP_REG32, 1, -1, 0, 0},
    {"vgatherqpd", {0xC4, 0xE2, 0x79, 0x93}, 4, OP_REG32, OP_MEM64, OP_REG32, 1, -1, 0, 0},

    /* AVX-512 mask registers */
    {"kmovw", {0xC5, 0xF8, 0x90}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"kmovb", {0xC5, 0xF9, 0x90}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"kmovd", {0xC5, 0xFB, 0x90}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"kmovq", {0xC4, 0xE1, 0xF8, 0x90}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"kandw", {0xC5, 0xF8, 0x41}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"kandb", {0xC5, 0xF9, 0x41}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"kandnw", {0xC5, 0xF8, 0x42}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"kandnb", {0xC5, 0xF9, 0x42}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"korw", {0xC5, 0xF8, 0x45}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"korb", {0xC5, 0xF9, 0x45}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"kxorw", {0xC5, 0xF8, 0x47}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"kxorb", {0xC5, 0xF9, 0x47}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"knotw", {0xC5, 0xF8, 0x44}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"knotb", {0xC5, 0xF9, 0x44}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"ktestw", {0xC5, 0xF8, 0x99}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"ktestb", {0xC5, 0xF9, 0x99}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"kortestw", {0xC5, 0xF8, 0x98}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"kortestb", {0xC5, 0xF9, 0x98}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},

    /* Additional SSE instructions for kernels */
    {"haddps", {0xF2, 0x0F, 0x7C}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"haddps", {0xF2, 0x0F, 0x7C}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"hsubps", {0xF2, 0x0F, 0x7D}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"haddpd", {0x66, 0x0F, 0x7C}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"hsubpd", {0x66, 0x0F, 0x7D}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"addsubps", {0xF2, 0x0F, 0xD0}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"addsubpd", {0x66, 0x0F, 0xD0}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"dpps", {0x66, 0x0F, 0x3A, 0x40}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"dppd", {0x66, 0x0F, 0x3A, 0x41}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"movntps", {0x0F, 0x2B}, 2, OP_MEM32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"movntpd", {0x66, 0x0F, 0x2B}, 3, OP_MEM32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"movntdq", {0x66, 0x0F, 0xE7}, 3, OP_MEM32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"movnti", {0x0F, 0xC3}, 2, OP_MEM32, OP_REG32, OP_NONE, 1, 0, 0, 0},
    {"prefetcht0", {0x0F, 0x18, 0x08}, 3, OP_MEM8, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"prefetcht1", {0x0F, 0x18, 0x10}, 3, OP_MEM8, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"prefetcht2", {0x0F, 0x18, 0x18}, 3, OP_MEM8, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"prefetchnta", {0x0F, 0x18, 0x00}, 3, OP_MEM8, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"clflush", {0x0F, 0xAE, 0x38}, 3, OP_MEM8, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lfence", {0x0F, 0xAE, 0xE8}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"mfence", {0x0F, 0xAE, 0xF0}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"sfence", {0x0F, 0xAE, 0xF8}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* Additional AVX instructions for kernels */
    {"vhaddps", {0xC5, 0xF8, 0x7C}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vhsubps", {0xC5, 0xF8, 0x7D}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vhaddpd", {0xC5, 0xF9, 0x7C}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vhsubpd", {0xC5, 0xF9, 0x7D}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vaddsubps", {0xC5, 0xF8, 0xD0}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vaddsubpd", {0xC5, 0xF9, 0xD0}, 3, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vdpps", {0xC4, 0xE3, 0x79, 0x40}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vdppd", {0xC4, 0xE3, 0x79, 0x41}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vextractf128", {0xC4, 0xE3, 0x79, 0x19}, 4, OP_MEM128, OP_YMM, OP_IMM8, 1, 0, 1, 0},
    {"vextractf128", {0xC4, 0xE3, 0x79, 0x19}, 4, OP_XMM, OP_YMM, OP_IMM8, 1, -1, 1, 0},
    {"vinsertf128", {0xC4, 0xE3, 0x79, 0x18}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vperm2f128", {0xC4, 0xE3, 0x79, 0x06}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vpermilps", {0xC4, 0xE3, 0x79, 0x0C}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vpermilpd", {0xC4, 0xE3, 0x79, 0x0D}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vblendps", {0xC4, 0xE3, 0x79, 0x0C}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vblendpd", {0xC4, 0xE3, 0x79, 0x0D}, 4, OP_REG32, OP_REG32, OP_IMM8, 1, -1, 1, 0},
    {"vblendvps", {0xC4, 0xE3, 0x79, 0x4A}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vblendvpd", {0xC4, 0xE3, 0x79, 0x4B}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vpblendvb", {0xC4, 0xE3, 0x79, 0x4C}, 4, OP_REG32, OP_REG32, OP_REG32, 1, -1, 0, 0},
    {"vtestps", {0xC4, 0xE2, 0x79, 0x0E}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vtestpd", {0xC4, 0xE2, 0x79, 0x0F}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vptest", {0xC4, 0xE2, 0x79, 0x17}, 4, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vpmovmskb", {0xC5, 0xF9, 0xD7}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vmovmskps", {0xC5, 0xF8, 0x50}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"vmovmskpd", {0xC5, 0xF9, 0x50}, 3, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},

    /* String operations */
    {"movsb", {0xA4}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"movsw", {0x66, 0xA5}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"movsd", {0xA5}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"movsq", {0x48, 0xA5}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"stosb", {0xAA}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"stosw", {0x66, 0xAB}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"stosd", {0xAB}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"stosq", {0x48, 0xAB}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lodsb", {0xAC}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lodsw", {0x66, 0xAD}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lodsd", {0xAD}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"lodsq", {0x48, 0xAD}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"scasb", {0xAE}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"scasw", {0x66, 0xAF}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"scasd", {0xAF}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"scasq", {0x48, 0xAF}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cmpsb", {0xA6}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cmpsw", {0x66, 0xA7}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cmpsd", {0xA7}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cmpsq", {0x48, 0xA7}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rep", {0xF3}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"repe", {0xF3}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"repz", {0xF3}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"repne", {0xF2}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"repnz", {0xF2}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* I/O */
    {"in", {0xE4}, 1, OP_REG8, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"in", {0xE5}, 1, OP_REG32, OP_IMM8, OP_NONE, 0, -1, 1, 0},
    {"in", {0xEC}, 1, OP_REG8, OP_REG8, OP_NONE, 0, -1, 0, 0},
    {"in", {0xED}, 1, OP_REG32, OP_REG8, OP_NONE, 0, -1, 0, 0},
    {"out", {0xE6}, 1, OP_IMM8, OP_REG8, OP_NONE, 0, -1, 1, 0},
    {"out", {0xE7}, 1, OP_IMM8, OP_REG32, OP_NONE, 0, -1, 1, 0},
    {"out", {0xEE}, 1, OP_REG8, OP_REG8, OP_NONE, 0, -1, 0, 0},
    {"out", {0xEF}, 1, OP_REG8, OP_REG32, OP_NONE, 0, -1, 0, 0},
    {"insb", {0x6C}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"insw", {0x66, 0x6D}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"insd", {0x6D}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"outsb", {0x6E}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"outsw", {0x66, 0x6F}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"outsd", {0x6F}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* Bit operations */
    {"bt", {0x0F, 0xA3}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"bt", {0x0F, 0xA3}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"bt", {0x0F, 0xBA}, 2, OP_REG32, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"bt", {0x0F, 0xBA}, 2, OP_REG64, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"bts", {0x0F, 0xAB}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"bts", {0x0F, 0xAB}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"bts", {0x0F, 0xBA}, 2, OP_REG32, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"bts", {0x0F, 0xBA}, 2, OP_REG64, OP_IMM8, OP_NONE, 1, 5, 1, 0},
    {"btr", {0x0F, 0xB3}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"btr", {0x0F, 0xB3}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"btr", {0x0F, 0xBA}, 2, OP_REG32, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"btr", {0x0F, 0xBA}, 2, OP_REG64, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"btc", {0x0F, 0xBB}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"btc", {0x0F, 0xBB}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"btc", {0x0F, 0xBA}, 2, OP_REG32, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"btc", {0x0F, 0xBA}, 2, OP_REG64, OP_IMM8, OP_NONE, 1, 7, 1, 0},
    {"bsf", {0x0F, 0xBC}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"bsf", {0x0F, 0xBC}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"bsr", {0x0F, 0xBD}, 2, OP_REG32, OP_REG32, OP_NONE, 1, -1, 0, 0},
    {"bsr", {0x0F, 0xBD}, 2, OP_REG64, OP_REG64, OP_NONE, 1, -1, 0, 0},
    {"bswap", {0x0F, 0xC8}, 2, OP_REG32, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"bswap", {0x48, 0x0F, 0xC8}, 3, OP_REG64, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* BCD arithmetic */
    {"aaa", {0x37}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"aas", {0x3F}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"daa", {0x27}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"das", {0x2F}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"aad", {0xD5, 0x0A}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"aam", {0xD4, 0x0A}, 2, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* Segment overrides */
    {"ds", {0x3E}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"es", {0x26}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"ss", {0x36}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"cs", {0x2E}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"fs", {0x64}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"gs", {0x65}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* Prefixes */
    {"lock", {0xF0}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"data16", {0x66}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"addr32", {0x67}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex", {0x40}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.b", {0x41}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.x", {0x42}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.xb", {0x43}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.r", {0x44}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.rb", {0x45}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.rx", {0x46}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.rxb", {0x47}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.w", {0x48}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.wb", {0x49}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.wx", {0x4A}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.wxb", {0x4B}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.wr", {0x4C}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.wrb", {0x4D}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.wrx", {0x4E}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},
    {"rex.wrxb", {0x4F}, 1, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* XCHG with accumulator */
    {"xchg", {0x90}, 1, OP_REG32, OP_REG32, OP_NONE, 0, -1, 0, 0},
    {"xchg", {0x90}, 1, OP_REG64, OP_REG64, OP_NONE, 0, -1, 0, 0},

    /* ============================================================================
     * AVX/AVX2 INSTRUCTIONS - VEX-encoded 256-bit SIMD
     * ============================================================================ */

    /* AVX - 256-bit floating point moves */
    {"vmovaps", {0xC5, 0xF8, 0x28}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vmovaps", {0xC5, 0xF8, 0x28}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},
    {"vmovaps", {0xC5, 0xF8, 0x29}, 3, OP_MEM256, OP_YMM, OP_NONE, 1, 0, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x10}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x10}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x11}, 3, OP_MEM256, OP_YMM, OP_NONE, 1, 0, 0, 0},

    /* AVX - 256-bit integer moves */
    {"vmovdqa", {0xC5, 0xF9, 0x6F}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa", {0xC5, 0xF9, 0x6F}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa", {0xC5, 0xF9, 0x7F}, 3, OP_MEM256, OP_YMM, OP_NONE, 1, 0, 0, 0},
    {"vmovdqu", {0xC5, 0xFA, 0x6F}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu", {0xC5, 0xFA, 0x6F}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu", {0xC5, 0xFA, 0x7F}, 3, OP_MEM256, OP_YMM, OP_NONE, 1, 0, 0, 0},

    /* AVX - 128-bit VEX versions (for completeness) */
    {"vmovaps", {0xC5, 0xF8, 0x28}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovaps", {0xC5, 0xF8, 0x28}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"vmovaps", {0xC5, 0xF8, 0x29}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x10}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x10}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0xC5, 0xF8, 0x11}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"vmovdqa", {0xC5, 0xF9, 0x6F}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa", {0xC5, 0xF9, 0x6F}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa", {0xC5, 0xF9, 0x7F}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},
    {"vmovdqu", {0xC5, 0xFA, 0x6F}, 3, OP_XMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu", {0xC5, 0xFA, 0x6F}, 3, OP_XMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu", {0xC5, 0xFA, 0x7F}, 3, OP_MEM128, OP_XMM, OP_NONE, 1, 0, 0, 0},

    /* AVX - Floating point arithmetic (3-operand) */
    {"vaddps", {0xC5, 0xF8, 0x58}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vaddps", {0xC5, 0xF8, 0x58}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vsubps", {0xC5, 0xF8, 0x5C}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vsubps", {0xC5, 0xF8, 0x5C}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vmulps", {0xC5, 0xF8, 0x59}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vmulps", {0xC5, 0xF8, 0x59}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vdivps", {0xC5, 0xF8, 0x5E}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vdivps", {0xC5, 0xF8, 0x5E}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vsqrtps", {0xC5, 0xF8, 0x51}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vsqrtps", {0xC5, 0xF8, 0x51}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},
    {"vmaxps", {0xC5, 0xF8, 0x5F}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vminps", {0xC5, 0xF8, 0x5D}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},

    /* AVX - Horizontal add */
    {"vhaddps", {0xC5, 0xF8, 0x7C}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vhaddps", {0xC5, 0xF8, 0x7C}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vhaddps", {0xC5, 0xF8, 0x7C}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vhaddps", {0xC5, 0xF8, 0x7C}, 3, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},

    /* AVX - Bitwise operations (3-operand) */
    {"vandps", {0xC5, 0xF8, 0x54}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vandps", {0xC5, 0xF8, 0x54}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vandnps", {0xC5, 0xF8, 0x55}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vorps", {0xC5, 0xF8, 0x56}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vxorps", {0xC5, 0xF8, 0x57}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vxorps", {0xC5, 0xF8, 0x57}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},

    /* AVX - State management */
    {"vzeroupper", {0xC5, 0xF8, 0x77}, 3, OP_NONE, OP_NONE, OP_NONE, 0, -1, 0, 0},

    /* AVX2 - Integer XOR (3-operand) */
    {"vpxor", {0xC5, 0xF9, 0xEF}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpxor", {0xC5, 0xF9, 0xEF}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vpxor", {0xC5, 0xF9, 0xEF}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpxor", {0xC5, 0xF9, 0xEF}, 3, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},

    /* AVX2 - Pack/Unpack */
    {"vpunpcklwd", {0xC5, 0xF9, 0x61}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpunpcklwd", {0xC5, 0xF9, 0x61}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vpunpckhwd", {0xC5, 0xF9, 0x69}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpunpckhwd", {0xC5, 0xF9, 0x69}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vpunpckldq", {0xC5, 0xF9, 0x62}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpunpckhdq", {0xC5, 0xF9, 0x6A}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},

    /* AVX2 - Integer arithmetic */
    {"vpaddw", {0xC5, 0xF9, 0xFD}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpaddd", {0xC5, 0xF9, 0xFE}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsubw", {0xC5, 0xF9, 0xF9}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsubd", {0xC5, 0xF9, 0xFA}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},

    /* AVX2 - Compare */
    {"vpcmpeqw", {0xC5, 0xF9, 0x75}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpcmpeqd", {0xC5, 0xF9, 0x76}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},

    /* AVX2 - AND/OR */
    {"vpand", {0xC5, 0xF9, 0xDB}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpand", {0xC5, 0xF9, 0xDB}, 3, OP_YMM, OP_YMM, OP_MEM256, 1, -1, 0, 0},
    {"vpandn", {0xC5, 0xF9, 0xDF}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpor", {0xC5, 0xF9, 0xEB}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},

    /* AVX2 - Sign/zero extend */
    {"vpmovzxbw", {0xC4, 0xE2, 0x7D, 0x30}, 4, OP_YMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxbw", {0xC4, 0xE2, 0x7D, 0x30}, 4, OP_YMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxwd", {0xC4, 0xE2, 0x7D, 0x33}, 4, OP_YMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vpmovzxdq", {0xC4, 0xE2, 0x7D, 0x35}, 4, OP_YMM, OP_XMM, OP_NONE, 1, -1, 0, 0},

    /* AVX2 - Convert */
    {"vcvtdq2ps", {0xC5, 0xF8, 0x5B}, 3, OP_YMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vcvtdq2ps", {0xC5, 0xF8, 0x5B}, 3, OP_YMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},

    /* AVX2 - Multiply */
    {"vpmullw", {0xC5, 0xF9, 0xD5}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpmulld", {0xC4, 0xE2, 0x7D, 0x40}, 4, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},

    /* AVX2 - Shuffle */
    {"vpshufd", {0xC5, 0xFA, 0x70}, 3, OP_YMM, OP_YMM, OP_IMM8, 1, -1, 1, 0},
    {"vpshufd", {0xC5, 0xFA, 0x70}, 3, OP_YMM, OP_MEM256, OP_IMM8, 1, -1, 1, 0},

    /* AVX2 - Non-temporal store */
    {"vmovntdq", {0xC5, 0xF9, 0xE7}, 3, OP_MEM256, OP_YMM, OP_NONE, 1, 0, 0, 0},

    /* AVX2 - Shift instructions (3-operand) */
    {"vpsrlw", {0xC5, 0xF9, 0xD1}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsrlw", {0xC5, 0xF9, 0xD1}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    /* vpsrlw xmm/ymm, xmm/ymm, imm8 - uses opcode C5 F9 71 /2 ib */
    {"vpsrlw", {0xC5, 0xF9, 0x71}, 3, OP_YMM, OP_YMM, OP_IMM8, 1, 2, 1, 0},
    {"vpsrlw", {0xC5, 0xF9, 0x71}, 3, OP_XMM, OP_XMM, OP_IMM8, 1, 2, 1, 0},
    {"vpsrld", {0xC5, 0xF9, 0xD2}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsrld", {0xC5, 0xF9, 0xD2}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpsrld", {0xC5, 0xF9, 0x72}, 3, OP_YMM, OP_YMM, OP_IMM8, 1, 2, 1, 0},
    {"vpsrld", {0xC5, 0xF9, 0x72}, 3, OP_XMM, OP_XMM, OP_IMM8, 1, 2, 1, 0},
    {"vpsrlq", {0xC5, 0xF9, 0xD3}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsrlq", {0xC5, 0xF9, 0xD3}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpsrlq", {0xC5, 0xF9, 0x73}, 3, OP_YMM, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"vpsrlq", {0xC5, 0xF9, 0x73}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 2, 1, 0},
    {"vpsraw", {0xC5, 0xF9, 0xE1}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsraw", {0xC5, 0xF9, 0xE1}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpsraw", {0xC5, 0xF9, 0x71}, 3, OP_YMM, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"vpsraw", {0xC5, 0xF9, 0x71}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"vpsrad", {0xC5, 0xF9, 0xE2}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsrad", {0xC5, 0xF9, 0xE2}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpsrad", {0xC5, 0xF9, 0x72}, 3, OP_YMM, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"vpsrad", {0xC5, 0xF9, 0x72}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 4, 1, 0},
    {"vpsllw", {0xC5, 0xF9, 0xF1}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsllw", {0xC5, 0xF9, 0xF1}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpsllw", {0xC5, 0xF9, 0x71}, 3, OP_YMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpsllw", {0xC5, 0xF9, 0x71}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpslld", {0xC5, 0xF9, 0xF2}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpslld", {0xC5, 0xF9, 0xF2}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpslld", {0xC5, 0xF9, 0x72}, 3, OP_YMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpslld", {0xC5, 0xF9, 0x72}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpsllq", {0xC5, 0xF9, 0xF3}, 3, OP_YMM, OP_YMM, OP_YMM, 1, -1, 0, 0},
    {"vpsllq", {0xC5, 0xF9, 0xF3}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vpsllq", {0xC5, 0xF9, 0x73}, 3, OP_YMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},
    {"vpsllq", {0xC5, 0xF9, 0x73}, 3, OP_XMM, OP_IMM8, OP_NONE, 1, 6, 1, 0},

    /* AVX - Floating point arithmetic (128-bit) */
    {"vaddps", {0xC5, 0xF8, 0x58}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vaddps", {0xC5, 0xF8, 0x58}, 3, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},
    {"vsubps", {0xC5, 0xF8, 0x5C}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vsubps", {0xC5, 0xF8, 0x5C}, 3, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},
    {"vmulps", {0xC5, 0xF8, 0x59}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vmulps", {0xC5, 0xF8, 0x59}, 3, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},
    {"vdivps", {0xC5, 0xF8, 0x5E}, 3, OP_XMM, OP_XMM, OP_XMM, 1, -1, 0, 0},
    {"vdivps", {0xC5, 0xF8, 0x5E}, 3, OP_XMM, OP_XMM, OP_MEM128, 1, -1, 0, 0},

    /* ============================================================================
     * AVX-512 INSTRUCTIONS - EVEX-encoded 512-bit SIMD
     * Note: Full EVEX encoding requires 4-byte prefix. These are simplified forms.
     * ============================================================================ */

    /* AVX-512 - 512-bit floating point moves (EVEX encoded) */
    {"vmovups", {0x62, 0xF1, 0x7C, 0x48, 0x10}, 5, OP_ZMM, OP_ZMM, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0x62, 0xF1, 0x7C, 0x48, 0x10}, 5, OP_ZMM, OP_MEM512, OP_NONE, 1, -1, 0, 0},
    {"vmovups", {0x62, 0xF1, 0x7C, 0x48, 0x11}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},

    /* AVX-512 - Floating point arithmetic (EVEX encoded) */
    {"vaddps", {0x62, 0xF1, 0x74, 0x48, 0x58}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vaddps", {0x62, 0xF1, 0x74, 0x48, 0x58}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vsubps", {0x62, 0xF1, 0x74, 0x48, 0x5C}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vsubps", {0x62, 0xF1, 0x74, 0x48, 0x5C}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vmulps", {0x62, 0xF1, 0x74, 0x48, 0x59}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vmulps", {0x62, 0xF1, 0x74, 0x48, 0x59}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vdivps", {0x62, 0xF1, 0x74, 0x48, 0x5E}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vdivps", {0x62, 0xF1, 0x74, 0x48, 0x5E}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},

    /* AVX-512 - Bitwise operations (EVEX encoded) */
    {"vxorps", {0x62, 0xF1, 0x74, 0x48, 0x57}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vxorps", {0x62, 0xF1, 0x74, 0x48, 0x57}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vandps", {0x62, 0xF1, 0x74, 0x48, 0x54}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vandps", {0x62, 0xF1, 0x74, 0x48, 0x54}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},

    /* AVX-512 - FMA (Fused Multiply-Add) - EVEX encoded */
    {"vfmadd231ps", {0x62, 0xF2, 0x75, 0x48, 0xB8}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vfmadd231ps", {0x62, 0xF2, 0x75, 0x48, 0xB8}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vfmadd213ps", {0x62, 0xF2, 0x75, 0x48, 0xA8}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vfmadd132ps", {0x62, 0xF2, 0x75, 0x48, 0x98}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},

    /* AVX-512 - Broadcast (EVEX encoded) */
    {"vbroadcastss", {0x62, 0xF2, 0x7D, 0x48, 0x18}, 5, OP_ZMM, OP_MEM32, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastss", {0x62, 0xF2, 0x7D, 0x48, 0x18}, 5, OP_ZMM, OP_XMM, OP_NONE, 1, -1, 0, 0},

    /* AVX-512 - Integer moves (EVEX encoded) */
    {"vmovdqu64", {0x62, 0xF1, 0xFD, 0x48, 0x6F}, 5, OP_ZMM, OP_ZMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu64", {0x62, 0xF1, 0xFD, 0x48, 0x6F}, 5, OP_ZMM, OP_MEM512, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu64", {0x62, 0xF1, 0xFD, 0x48, 0x7F}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},
    {"vmovdqu32", {0x62, 0xF1, 0x7D, 0x48, 0x6F}, 5, OP_ZMM, OP_ZMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu32", {0x62, 0xF1, 0x7D, 0x48, 0x6F}, 5, OP_ZMM, OP_MEM512, OP_NONE, 1, -1, 0, 0},
    {"vmovdqu32", {0x62, 0xF1, 0x7D, 0x48, 0x7F}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},
    {"vmovdqa64", {0x62, 0xF1, 0xFD, 0x48, 0x6F}, 5, OP_ZMM, OP_ZMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa64", {0x62, 0xF1, 0xFD, 0x48, 0x6F}, 5, OP_ZMM, OP_MEM512, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa64", {0x62, 0xF1, 0xFD, 0x48, 0x7F}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},
    {"vmovdqa32", {0x62, 0xF1, 0x7D, 0x48, 0x6F}, 5, OP_ZMM, OP_ZMM, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa32", {0x62, 0xF1, 0x7D, 0x48, 0x6F}, 5, OP_ZMM, OP_MEM512, OP_NONE, 1, -1, 0, 0},
    {"vmovdqa32", {0x62, 0xF1, 0x7D, 0x48, 0x7F}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},

    /* AVX-512 - Integer arithmetic (EVEX encoded) */
    {"vpaddd", {0x62, 0xF1, 0x7D, 0x48, 0xFE}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpaddd", {0x62, 0xF1, 0x7D, 0x48, 0xFE}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vpaddq", {0x62, 0xF1, 0xFD, 0x48, 0xD4}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpaddq", {0x62, 0xF1, 0xFD, 0x48, 0xD4}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vpsubd", {0x62, 0xF1, 0x7D, 0x48, 0xFA}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpsubd", {0x62, 0xF1, 0x7D, 0x48, 0xFA}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vpsubq", {0x62, 0xF1, 0xFD, 0x48, 0xFB}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpsubq", {0x62, 0xF1, 0xFD, 0x48, 0xFB}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},

    /* AVX-512 - Bitwise (EVEX encoded) */
    {"vpxord", {0x62, 0xF1, 0x7D, 0x48, 0xEF}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpxord", {0x62, 0xF1, 0x7D, 0x48, 0xEF}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vpxorq", {0x62, 0xF1, 0xFD, 0x48, 0xEF}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpxorq", {0x62, 0xF1, 0xFD, 0x48, 0xEF}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vpandd", {0x62, 0xF1, 0x7D, 0x48, 0xDB}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpandd", {0x62, 0xF1, 0x7D, 0x48, 0xDB}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vpandq", {0x62, 0xF1, 0xFD, 0x48, 0xDB}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpandq", {0x62, 0xF1, 0xFD, 0x48, 0xDB}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vpord", {0x62, 0xF1, 0x7D, 0x48, 0xEB}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpord", {0x62, 0xF1, 0x7D, 0x48, 0xEB}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},
    {"vporq", {0x62, 0xF1, 0xFD, 0x48, 0xEB}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vporq", {0x62, 0xF1, 0xFD, 0x48, 0xEB}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},

    /* AVX-512 - Compare (EVEX encoded) */
    {"vpcmpeqd", {0x62, 0xF1, 0x7D, 0x48, 0x76}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpcmpeqq", {0x62, 0xF1, 0xFD, 0x48, 0x29}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},

    /* AVX-512 - Convert (EVEX encoded) */
    {"vcvtph2ps", {0x62, 0xF3, 0x7D, 0x48, 0x13}, 5, OP_ZMM, OP_YMM, OP_NONE, 1, -1, 0, 0},
    {"vcvtps2ph", {0x62, 0xF3, 0x7D, 0x48, 0x1D}, 5, OP_YMM, OP_ZMM, OP_IMM8, 1, -1, 1, 0},

    /* AVX-512 - FMA (Fused Multiply-Add) double precision */
    {"vfmadd231pd", {0x62, 0xF2, 0xF5, 0x48, 0xB8}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vfmadd213pd", {0x62, 0xF2, 0xF5, 0x48, 0xA8}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vfmadd132pd", {0x62, 0xF2, 0xF5, 0x48, 0x98}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},

    /* AVX-512 - Broadcast (EVEX encoded) - additional variants */
    {"vbroadcastsd", {0x62, 0xF2, 0xFD, 0x48, 0x19}, 5, OP_ZMM, OP_MEM64, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastsd", {0x62, 0xF2, 0xFD, 0x48, 0x19}, 5, OP_ZMM, OP_XMM, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastf32x4", {0x62, 0xF2, 0x7D, 0x48, 0x1A}, 5, OP_ZMM, OP_MEM128, OP_NONE, 1, -1, 0, 0},
    {"vbroadcastf64x4", {0x62, 0xF2, 0xFD, 0x48, 0x1B}, 5, OP_ZMM, OP_MEM256, OP_NONE, 1, -1, 0, 0},

    /* AVX-512 - Permute/Shuffle (EVEX encoded) */
    {"vpermd", {0x62, 0xF2, 0x7D, 0x48, 0x36}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vpermq", {0x62, 0xF3, 0xFD, 0x48, 0x00}, 5, OP_ZMM, OP_ZMM, OP_IMM8, 1, -1, 1, 0},
    {"vpshufd", {0x62, 0xF1, 0x7D, 0x48, 0x70}, 5, OP_ZMM, OP_ZMM, OP_IMM8, 1, -1, 1, 0},

    /* AVX-512 - Scale (EVEX encoded) */
    {"vscalefps", {0x62, 0xF2, 0x75, 0x48, 0x2C}, 5, OP_ZMM, OP_ZMM, OP_ZMM, 1, -1, 0, 0},
    {"vscalefps", {0x62, 0xF2, 0x75, 0x48, 0x2C}, 5, OP_ZMM, OP_ZMM, OP_MEM512, 1, -1, 0, 0},

    /* AVX-512 - Reciprocal/Sqrt (EVEX encoded) */
    {"vrcp14ps", {0x62, 0xF2, 0x7D, 0x48, 0x4C}, 5, OP_ZMM, OP_ZMM, OP_NONE, 1, -1, 0, 0},
    {"vrcp14ps", {0x62, 0xF2, 0x7D, 0x48, 0x4C}, 5, OP_ZMM, OP_MEM512, OP_NONE, 1, -1, 0, 0},
    {"vrsqrt14ps", {0x62, 0xF2, 0x7D, 0x48, 0x4E}, 5, OP_ZMM, OP_ZMM, OP_NONE, 1, -1, 0, 0},
    {"vrsqrt14ps", {0x62, 0xF2, 0x7D, 0x48, 0x4E}, 5, OP_ZMM, OP_MEM512, OP_NONE, 1, -1, 0, 0},

    /* AVX-512 - Non-temporal stores (EVEX encoded) */
    {"vmovntdq", {0x62, 0xF1, 0x7D, 0x48, 0xE7}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},
    {"vmovntpd", {0x62, 0xF1, 0xFD, 0x48, 0x2B}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},
    {"vmovntps", {0x62, 0xF1, 0x7C, 0x48, 0x2B}, 5, OP_MEM512, OP_ZMM, OP_NONE, 1, 0, 0, 0},

    {NULL, {0}, 0, 0, 0, 0, 0, 0, 0, 0}
};

/* ============================================================================
 * PARSER STATE
 * ============================================================================ */
#define MAX_LINE_LENGTH 1024
#define MAX_LABELS 10000
#define MAX_FIXUPS 10000
#define MAX_SECTION_SIZE (1024 * 1024)  /* 1MB per section */
#define MAX_TOKENS 20
#define MAX_PUBLIC_SYMBOLS 256
#define MAX_EXTERN_SYMBOLS 256

typedef struct {
    char name[256];
    uint32_t offset;
    int section;  /* 0 = text, 1 = data, 2 = rdata, 3 = bss */
    int is_equ;   /* 1 = EQU constant, don't export to COFF */
    uint32_t string_offset; /* String table offset for long names */
} Label;

typedef struct {
    uint32_t offset;
    char label[256];
    int size;     /* 1, 2, 4, or 8 bytes */
    int section;
    int is_relative;
    uint32_t instruction_start;
} Fixup;

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} Section;

typedef struct {
    Section text;
    Section data;
    Section rdata;
    Section bss;
    Label labels[MAX_LABELS];
    int label_count;
    Fixup fixups[MAX_FIXUPS];
    int fixup_count;
    int current_section;
    uint32_t entry_point;
    int has_entry;
    /* NASM-style symbol support */
    char public_symbols[MAX_PUBLIC_SYMBOLS][256];
    int public_count;
    char extern_symbols[MAX_EXTERN_SYMBOLS][256];
    int extern_count;
    int default_rel;  /* Default to RIP-relative addressing */
} AssemblerState;

static AssemblerState g_state;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */
static void init_section(Section *sec) {
    sec->capacity = 4096;
    sec->data = (uint8_t *)malloc(sec->capacity);
    sec->size = 0;
}

static void section_append(Section *sec, uint8_t byte) {
    if (sec->size >= sec->capacity) {
        sec->capacity *= 2;
        sec->data = (uint8_t *)realloc(sec->data, sec->capacity);
    }
    sec->data[sec->size++] = byte;
}

static void section_append_bytes(Section *sec, const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        section_append(sec, bytes[i]);
    }
}

static uint32_t section_current_offset(Section *sec) {
    return (uint32_t)sec->size;
}

static Section* get_current_section(void) {
    switch (g_state.current_section) {
        case 0: return &g_state.text;
        case 1: return &g_state.data;
        case 2: return &g_state.rdata;
        case 3: return &g_state.bss;
        default: return &g_state.text;
    }
}

static void emit_byte(uint8_t byte) {
    section_append(get_current_section(), byte);
}

static void emit_bytes(const uint8_t *bytes, size_t len) {
    section_append_bytes(get_current_section(), bytes, len);
}

static void emit_word(uint16_t word) {
    emit_byte(word & 0xFF);
    emit_byte((word >> 8) & 0xFF);
}

static void emit_dword(uint32_t dword) {
    emit_byte(dword & 0xFF);
    emit_byte((dword >> 8) & 0xFF);
    emit_byte((dword >> 16) & 0xFF);
    emit_byte((dword >> 24) & 0xFF);
}

static void emit_qword(uint64_t qword) {
    emit_dword((uint32_t)(qword & 0xFFFFFFFF));
    emit_dword((uint32_t)(qword >> 32));
}

static uint32_t current_offset(void) {
    return section_current_offset(get_current_section());
}

/* ============================================================================
 * TOKENIZER
 * ============================================================================ */
static char *skip_whitespace(char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static char *skip_comment(char *p) {
    if (*p == ';') {
        while (*p && *p != '\n') p++;
    }
    return p;
}

static int is_label_char(char c) {
    return isalnum((unsigned char)c) || c == '_' || c == '.' || c == '@' || c == '?' || c == '$';
}

static char *parse_token(char *p, char *token, size_t token_size) {
    p = skip_whitespace(p);
    if (!*p) {
        token[0] = '\0';
        return p;
    }

    size_t i = 0;

    /* Check for quoted string */
    if (*p == '"' || *p == '\'') {
        char quote = *p++;
        while (*p && *p != quote && i < token_size - 1) {
            if (*p == '\\' && *(p+1)) {
                p++;
                switch (*p) {
                    case 'n': token[i++] = '\n'; break;
                    case 't': token[i++] = '\t'; break;
                    case 'r': token[i++] = '\r'; break;
                    case '0': token[i++] = '\0'; break;
                    case '\\': token[i++] = '\\'; break;
                    case '"': token[i++] = '"'; break;
                    case '\'': token[i++] = '\''; break;
                    default: token[i++] = *p; break;
                }
                p++;
            } else {
                token[i++] = *p++;
            }
        }
        if (*p == quote) p++;
        token[i] = '\0';
        return p;
    }

    /* Check for number (hex, binary, decimal) */
    if (*p == '0' && (*(p+1) == 'x' || *(p+1) == 'X')) {
        token[i++] = *p++;
        token[i++] = *p++;
        while (isxdigit((unsigned char)*p) && i < token_size - 1) {
            token[i++] = *p++;
        }
        token[i] = '\0';
        return p;
    }

    if (*p == '0' && (*(p+1) == 'b' || *(p+1) == 'B')) {
        token[i++] = *p++;
        token[i++] = *p++;
        while ((*p == '0' || *p == '1') && i < token_size - 1) {
            token[i++] = *p++;
        }
        token[i] = '\0';
        return p;
    }

    /* Parse identifier or operator */
    if (isalpha((unsigned char)*p) || *p == '_' || *p == '.' || *p == '@') {
        while (is_label_char(*p) && i < token_size - 1) {
            token[i++] = *p++;
        }
    } else if (isdigit((unsigned char)*p)) {
        while (isdigit((unsigned char)*p) && i < token_size - 1) {
            token[i++] = *p++;
        }
    } else {
        /* Single character token (operator, etc.) */
        token[i++] = *p++;
    }

    token[i] = '\0';
    return p;
}

/* ============================================================================
 * REGISTER LOOKUP
 * ============================================================================ */
static const RegInfo* find_register(const char *name) {
    for (int i = 0; g_registers[i].name != NULL; i++) {
        if (_stricmp(g_registers[i].name, name) == 0) {
            return &g_registers[i];
        }
    }
    return NULL;
}

/* ============================================================================
 * EXPRESSION EVALUATION
 * ============================================================================ */
static int64_t parse_number(const char *str) {
    int64_t value = 0;
    if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
        sscanf(str + 2, "%llx", (unsigned long long *)&value);
    } else if (strncmp(str, "0b", 2) == 0 || strncmp(str, "0B", 2) == 0) {
        for (const char *p = str + 2; *p; p++) {
            value = (value << 1) | (*p - '0');
        }
    } else {
        sscanf(str, "%lld", (long long *)&value);
    }
    return value;
}

static int find_label(const char *name) {
    for (int i = 0; i < g_state.label_count; i++) {
        if (_stricmp(g_state.labels[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static void add_label(const char *name) {
    if (g_state.label_count >= MAX_LABELS) {
        fprintf(stderr, "Error: Too many labels\n");
        return;
    }

    /* Check if label already exists */
    for (int i = 0; i < g_state.label_count; i++) {
        if (_stricmp(g_state.labels[i].name, name) == 0) {
            /* Update existing label */
            g_state.labels[i].offset = current_offset();
            g_state.labels[i].section = g_state.current_section;
            return;
        }
    }

    Label *l = &g_state.labels[g_state.label_count++];
    strncpy(l->name, name, 255);
    l->name[255] = '\0';
    l->offset = current_offset();
    l->section = g_state.current_section;
    l->is_equ = 0;  /* Regular label, not EQU constant */
}

static int64_t evaluate_expression(char *expr, int *is_label_ref, char *label_name) {
    *is_label_ref = 0;
    label_name[0] = '\0';

    expr = skip_whitespace(expr);

    /* Check if it's a label reference */
    char token[256];
    char *p = parse_token(expr, token, sizeof(token));

    /* Check for offset operator */
    if (strcmp(token, "offset") == 0) {
        expr = skip_whitespace(p);
        p = parse_token(expr, token, sizeof(token));
    }

    /* Check if it's a register-based expression */
    if (find_register(token) != NULL) {
        /* Memory operand - return 0 for now, will be handled separately */
        return 0;
    }

    /* Check if it's a label */
    int label_idx = find_label(token);
    if (label_idx >= 0) {
        *is_label_ref = 1;
        strncpy(label_name, token, 255);
        label_name[255] = '\0';
        return g_state.labels[label_idx].offset;
    }

    /* Check if it's an external symbol */
    for (int i = 0; i < g_state.extern_count; i++) {
        if (_stricmp(g_state.extern_symbols[i], token) == 0) {
            *is_label_ref = 1;
            strncpy(label_name, token, 255);
            label_name[255] = '\0';
            return 0; /* External symbols have value 0 at assembly time */
        }
    }

    /* Try to parse as number */
    if (isdigit((unsigned char)token[0]) ||
        (token[0] == '0' && (token[1] == 'x' || token[1] == 'X' || token[1] == 'b' || token[1] == 'B'))) {
        return parse_number(token);
    }

    /* Simple expression evaluation (addition/subtraction) */
    int64_t result = 0;
    int sign = 1;
    char *ep = expr;

    while (*ep) {
        ep = skip_whitespace(ep);
        if (!*ep) break;

        char tok[256];
        char *next = parse_token(ep, tok, sizeof(tok));

        if (strcmp(tok, "+") == 0) {
            sign = 1;
        } else if (strcmp(tok, "-") == 0) {
            sign = -1;
        } else if (isdigit((unsigned char)tok[0]) ||
                   (tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X'))) {
            result += sign * parse_number(tok);
            sign = 1;
        } else {
            label_idx = find_label(tok);
            if (label_idx >= 0) {
                *is_label_ref = 1;
                strncpy(label_name, tok, 255);
                label_name[255] = '\0';
                result += sign * g_state.labels[label_idx].offset;
                sign = 1;
            } else {
                /* Check if it's an external symbol */
                for (int i = 0; i < g_state.extern_count; i++) {
                    if (_stricmp(g_state.extern_symbols[i], tok) == 0) {
                        *is_label_ref = 1;
                        strncpy(label_name, tok, 255);
                        label_name[255] = '\0';
                        result += sign * 0; /* External symbols have value 0 at assembly time */
                        sign = 1;
                        break;
                    }
                }
            }
        }

        ep = next;
    }

    return result;
}

/* ============================================================================
 * MEMORY OPERAND PARSING
 * ============================================================================ */
typedef struct {
    int has_base;
    Register base_reg;
    int has_index;
    Register index_reg;
    int scale;
    int64_t displacement;
    int has_displacement;
} MemoryOperand;

static int parse_memory_operand(char *operand, MemoryOperand *mem) {
    memset(mem, 0, sizeof(MemoryOperand));
    mem->scale = 1;

    char *p = skip_whitespace(operand);

    /* Check for immediate displacement at start */
    if (isdigit((unsigned char)*p) || *p == '-' || *p == '+') {
        char num[64];
        int i = 0;
        int neg = 0;
        if (*p == '-') { neg = 1; p++; }
        else if (*p == '+') { p++; }

        while (isdigit((unsigned char)*p) ||
               (i == 1 && p[-1] == '0' && (*p == 'x' || *p == 'X')) ||
               isxdigit((unsigned char)*p)) {
            num[i++] = *p++;
        }
        num[i] = '\0';

        if (i > 0) {
            mem->displacement = parse_number(num);
            if (neg) mem->displacement = -mem->displacement;
            mem->has_displacement = 1;
        }
    }

    /* Look for [base+index*scale+disp] format */
    char *bracket = strchr(p, '[');
    if (!bracket) {
        /* Check if it's just a displacement */
        if (mem->has_displacement) {
            return 1;
        }
        return 0;
    }

    p = bracket + 1;
    char *end_bracket = strchr(p, ']');
    if (!end_bracket) return 0;
    *end_bracket = '\0';

    /* Parse inside brackets */
    char token[256];
    while (*p) {
        p = skip_whitespace(p);
        if (!*p) break;

        char *next = parse_token(p, token, sizeof(token));

        const RegInfo *reg = find_register(token);
        if (reg) {
            if (!mem->has_base) {
                mem->base_reg = reg->reg;
                mem->has_base = 1;
            } else if (!mem->has_index) {
                mem->index_reg = reg->reg;
                mem->has_index = 1;
            }
        } else if (strcmp(token, "*") == 0) {
            /* Scale follows */
            p = skip_whitespace(next);
            next = parse_token(p, token, sizeof(token));
            mem->scale = (int)parse_number(token);
        } else if (strcmp(token, "+") == 0 || strcmp(token, "-") == 0) {
            /* Handle displacement */
            int sign = (token[0] == '-') ? -1 : 1;
            p = skip_whitespace(next);
            next = parse_token(p, token, sizeof(token));
            if (isdigit((unsigned char)token[0])) {
                mem->displacement = sign * parse_number(token);
                mem->has_displacement = 1;
            }
        } else if (isdigit((unsigned char)token[0])) {
            /* Displacement without sign */
            mem->displacement = parse_number(token);
            mem->has_displacement = 1;
        }

        p = next;
    }

    return 1;
}

/* ============================================================================
 * MODR/M AND SIB ENCODING
 * ============================================================================ */
static void encode_modrm_sib(uint8_t *modrm, uint8_t *sib, int *has_sib,
                              int mod, int reg, int rm,
                              int scale, int index, int base) {
    *modrm = (mod << 6) | ((reg & 7) << 3) | (rm & 7);
    *has_sib = 0;

    if (rm == 4 && mod != 3) {  /* ESP/RSP requires SIB */
        *has_sib = 1;
        int ss;
        switch (scale) {
            case 1: ss = 0; break;
            case 2: ss = 1; break;
            case 4: ss = 2; break;
            case 8: ss = 3; break;
            default: ss = 0; break;
        }
        *sib = (ss << 6) | ((index & 7) << 3) | (base & 7);
    }
}

/* ============================================================================
 * INSTRUCTION ENCODING
 * ============================================================================ */
static int get_operand_size(const char *operand) {
    const RegInfo *reg = find_register(operand);
    if (reg) {
        return reg->size;
    }

    /* Check if it's a memory reference */
    if (strchr(operand, '[')) {
        /* Determine size from prefix or context */
        return 0; /* Unknown, need more context */
    }

    /* Immediate */
    return 0;
}

static int match_operand_type(int type, const char *operand, int size_hint) {
    const RegInfo *reg = find_register(operand);

    switch (type) {
        case OP_NONE:
            return operand[0] == '\0';

        case OP_REG8:
            return reg && reg->size == 1;

        case OP_REG16:
            return reg && reg->size == 2;

        case OP_REG32:
            /* Must be a register, not an immediate or memory */
            return reg && reg->size == 4;

        case OP_REG64:
            /* Must be a register, not an immediate or memory */
            return reg && reg->size == 8;

        case OP_IMM8:
        case OP_IMM16:
        case OP_IMM32:
        case OP_IMM64:
            /* Check if it's an immediate value (not a register) */
            if (reg) return 0;  /* Register is not an immediate */
            if (operand[0] == '\0') return 0;
            /* Could be number or label */
            return 1;

        case OP_MEM8:
        case OP_MEM16:
        case OP_MEM32:
        case OP_MEM64:
            /* Memory operand - either [reg] form or a label reference */
            if (strchr(operand, '[') != NULL) return 1;
            /* Also accept label references (for LEA instruction) */
            if (operand[0] != '\0' && !find_register(operand)) return 1;
            return 0;

        case OP_REL8:
        case OP_REL16:
        case OP_REL32:
            /* Relative offset - could be label or number */
            return 1;

        case OP_XMM:
            /* XMM register (128-bit) */
            return reg && reg->size == 16;

        case OP_YMM:
            /* YMM register (256-bit) */
            return reg && reg->size == 32;

        case OP_ZMM:
            /* ZMM register (512-bit) */
            return reg && reg->size == 64;

        case OP_MEM128:
        case OP_MEM256:
        case OP_MEM512:
            /* Memory operand (size checked at runtime) */
            return strchr(operand, '[') != NULL;

        default:
            return 0;
    }
}

static const InstructionEncoding* find_instruction(const char *mnemonic,
                                                      const char *op1,
                                                      const char *op2,
                                                      const char *op3) {
    for (int i = 0; g_instructions[i].mnemonic != NULL; i++) {
        if (_stricmp(g_instructions[i].mnemonic, mnemonic) != 0) {
            continue;
        }

        /* Check operand matching */
        int match = 1;

        if (g_instructions[i].op1_type != OP_NONE) {
            if (!match_operand_type(g_instructions[i].op1_type, op1, 0)) {
                match = 0;
            }
        } else if (op1[0] != '\0') {
            match = 0;
        }

        if (g_instructions[i].op2_type != OP_NONE) {
            if (!match_operand_type(g_instructions[i].op2_type, op2, 0)) {
                match = 0;
            }
        } else if (op2[0] != '\0') {
            match = 0;
        }

        if (g_instructions[i].op3_type != OP_NONE) {
            if (!match_operand_type(g_instructions[i].op3_type, op3, 0)) {
                match = 0;
            }
        } else if (op3[0] != '\0') {
            match = 0;
        }

        if (match) {
            return &g_instructions[i];
        }
    }

    return NULL;
}

/* Helper to check if instruction uses VEX encoding */
static int is_vex_instruction(const InstructionEncoding *inst) {
    return inst->opcode_len > 0 && (inst->opcode[0] == 0xC5 || inst->opcode[0] == 0xC4);
}

/* Helper to check if instruction uses EVEX encoding (AVX-512) */
static int is_evex_instruction(const InstructionEncoding *inst) {
    return inst->opcode_len > 0 && inst->opcode[0] == 0x62;
}

/* Calculate VEX prefix bytes for AVX instructions
 * For 2-byte VEX (C5): opcode[0]=C5, opcode[1]=base_vex, rest are actual opcode
 * For 3-byte VEX (C4): opcode[0]=C4, opcode[1]=R/X/B/map, opcode[2]=W/v/L/pp, rest are opcode
 */
static void emit_vex_prefix(const InstructionEncoding *inst,
                            const RegInfo *dest_reg,
                            const RegInfo *src1_reg,
                            const RegInfo *src2_reg) {
    if (inst->opcode[0] == 0xC5) {
        /* 2-byte VEX: C5 xx [opcode...]
         * Byte 1: R vvvv L pp
         *   R = ~REX.R (1 if no extension)
         *   vvvv = ~src1 (inverted source register)
         *   L = 1 for 256-bit, 0 for 128-bit
         *   pp = 00 (none), 01 (66), 10 (F3), 11 (F2)
         */
        uint8_t vex_byte1 = inst->opcode[1];

        /* Update vvvv field if we have a source register */
        if (src1_reg) {
            uint8_t vvvv = (~src1_reg->id) & 0x0F;
            vex_byte1 = (vex_byte1 & 0x80) | (vvvv << 3) | (vex_byte1 & 0x07);
        }

        /* Update L bit for vector length */
        if (inst->op1_type == OP_YMM || inst->op2_type == OP_YMM) {
            vex_byte1 |= 0x04;  /* Set L bit for 256-bit */
        }

        emit_byte(0xC5);
        emit_byte(vex_byte1);

        /* Emit remaining opcode bytes */
        for (int i = 2; i < inst->opcode_len; i++) {
            emit_byte(inst->opcode[i]);
        }
    } else if (inst->opcode[0] == 0xC4) {
        /* 3-byte VEX: C4 xx xx [opcode...]
         * Byte 1: R X B m-mmmm
         * Byte 2: W vvvv L pp
         */
        uint8_t vex_byte1 = inst->opcode[1];
        uint8_t vex_byte2 = inst->opcode[2];

        /* Update vvvv field if we have a source register */
        if (src1_reg) {
            uint8_t vvvv = (~src1_reg->id) & 0x0F;
            vex_byte2 = (vex_byte2 & 0x80) | (vvvv << 3) | (vex_byte2 & 0x07);
        }

        /* Update L bit for vector length */
        if (inst->op1_type == OP_YMM || inst->op2_type == OP_YMM) {
            vex_byte2 |= 0x04;  /* Set L bit for 256-bit */
        }

        emit_byte(0xC4);
        emit_byte(vex_byte1);
        emit_byte(vex_byte2);

        /* Emit remaining opcode bytes */
        for (int i = 3; i < inst->opcode_len; i++) {
            emit_byte(inst->opcode[i]);
        }
    }
}

static void emit_instruction(const InstructionEncoding *inst,
                              const char *op1, const char *op2, const char *op3) {
    uint8_t rex = 0;
    int need_rex = 0;

    /* Calculate REX prefix */
    const RegInfo *reg1 = find_register(op1);
    const RegInfo *reg2 = find_register(op2);
    const RegInfo *reg3 = find_register(op3);

    /* Handle VEX-encoded instructions (AVX/AVX2) */
    if (is_vex_instruction(inst)) {
        /* For 3-operand AVX: dest=op1, src1=op2, src2=op3
         * For 2-operand AVX: dest=op1, src1=op2 (for moves), src2=NULL
         */
        emit_vex_prefix(inst, reg1, reg2, reg3);
        /* Skip normal prefix/opcode emission - handled by emit_vex_prefix */
    } else if (is_evex_instruction(inst)) {
        /* Handle EVEX-encoded instructions (AVX-512)
         * EVEX prefix is 4 bytes: 62 XX YY ZZ [opcode...]
         * For now, emit the static prefix bytes from the instruction table
         * Full EVEX encoding with register updates would require more complex logic
         */
        for (int i = 0; i < inst->opcode_len; i++) {
            emit_byte(inst->opcode[i]);
        }
    } else {
        /* Standard SSE/x86 instruction encoding */
        if (g_arch == ARCH_X64 || g_arch == ARCH_X32) {
            /* REX.W for 64-bit operands */
            if (inst->op1_type == OP_REG64 || inst->op2_type == OP_REG64) {
                rex |= 0x48;
                need_rex = 1;
            }

            /* REX.B for extended registers (R8-R15) */
            if (reg1 && reg1->needs_rex) {
                rex |= 0x41;
                need_rex = 1;
            }
            if (reg2 && reg2->needs_rex) {
                rex |= 0x44;
                need_rex = 1;
            }

            /* REX.R for reg field in ModR/M */
            if (inst->needs_modrm && reg2 && reg2->needs_rex) {
                rex |= 0x44;
                need_rex = 1;
            }
        }

        /* Emit REX prefix if needed */
        if (need_rex) {
            emit_byte(rex);
        }

        /* Emit instruction prefix (0x66, 0xF2, 0xF3) */
        if (inst->prefix) {
            emit_byte(inst->prefix);
        }

        /* Emit opcode */
        for (int i = 0; i < inst->opcode_len; i++) {
            emit_byte(inst->opcode[i]);
        }
    }

    /* Emit ModR/M if needed */
    if (inst->needs_modrm) {
        uint8_t modrm = 0;
        uint8_t sib = 0;
        int has_sib = 0;

        int reg_field = inst->reg_field;
        if (reg_field == -1 && reg2) {
            reg_field = reg2->id;
        } else if (reg_field == -1) {
            reg_field = 0;
        }

        /* Check for memory operand */
        MemoryOperand mem;
        const char *mem_op = NULL;
        if (strchr(op1, '[')) mem_op = op1;
        else if (strchr(op2, '[')) mem_op = op2;

        if (mem_op && parse_memory_operand((char *)mem_op, &mem)) {
            /* Memory addressing mode */
            int mod, rm;

            if (mem.has_base) {
                const RegInfo *base = find_register(op1);
                if (!base) base = find_register(op2);

                if (mem.has_displacement && mem.displacement == 0 &&
                    base && base->id != 5) {
                    mod = 0;
                } else if (mem.has_displacement && mem.displacement >= -128 &&
                           mem.displacement <= 127) {
                    mod = 1;
                } else {
                    mod = 2;
                }

                rm = base ? base->id : mem.base_reg;

                if (mem.has_index) {
                    /* SIB required */
                    rm = 4;
                    encode_modrm_sib(&modrm, &sib, &has_sib, mod, reg_field, rm,
                                     mem.scale, mem.index_reg, base ? base->id : mem.base_reg);
                } else if (base && base->id == 4) {
                    /* ESP/RSP requires SIB */
                    encode_modrm_sib(&modrm, &sib, &has_sib, mod, reg_field, 4,
                                     1, 4, 4);
                } else {
                    modrm = (mod << 6) | ((reg_field & 7) << 3) | (rm & 7);
                }

                emit_byte(modrm);
                if (has_sib) {
                    emit_byte(sib);
                }

                /* Emit displacement */
                if (mod == 1) {
                    emit_byte((uint8_t)(int8_t)mem.displacement);
                } else if (mod == 2 || (mod == 0 && base && base->id == 5)) {
                    emit_dword((uint32_t)mem.displacement);
                }
            } else {
                /* Displacement-only addressing */
                modrm = (0 << 6) | ((reg_field & 7) << 3) | 5;
                emit_byte(modrm);
                emit_dword((uint32_t)mem.displacement);
            }
        } else if (reg1 && reg2) {
            /* Register to register */
            modrm = (3 << 6) | ((reg_field & 7) << 3) | (reg1->id & 7);
            emit_byte(modrm);
        } else if (reg1) {
            /* Register only */
            modrm = (3 << 6) | ((reg_field & 7) << 3) | (reg1->id & 7);
            emit_byte(modrm);
        } else {
            /* Default ModR/M */
            modrm = (3 << 6) | ((reg_field & 7) << 3);
            emit_byte(modrm);
        }
    }

    /* Emit immediate */
    if (inst->immediate_size > 0) {
        int is_label = 0;
        char label_name[256];
        int64_t imm = evaluate_expression((char *)op1, &is_label, label_name);

        if (!is_label) {
            /* Check if op2 has the immediate */
            imm = evaluate_expression((char *)op2, &is_label, label_name);
        }

        if (is_label) {
            /* Add fixup */
            if (g_state.fixup_count < MAX_FIXUPS) {
                Fixup *f = &g_state.fixups[g_state.fixup_count++];
                f->offset = current_offset();
                f->section = g_state.current_section;
                strncpy(f->label, label_name, 255);
                f->label[255] = '\0';
                f->size = inst->immediate_size;
                f->is_relative = (inst->op1_type >= OP_REL8 && inst->op1_type <= OP_REL32) ||
                                (inst->op2_type >= OP_REL8 && inst->op2_type <= OP_REL32);
                f->instruction_start = current_offset() - inst->opcode_len - (need_rex ? 1 : 0) - (inst->prefix ? 1 : 0);
            }

            /* Emit placeholder */
            for (int i = 0; i < inst->immediate_size; i++) {
                emit_byte(0);
            }
        } else {
            switch (inst->immediate_size) {
                case 1: emit_byte((uint8_t)imm); break;
                case 2: emit_word((uint16_t)imm); break;
                case 4: emit_dword((uint32_t)imm); break;
                case 8: emit_qword((uint64_t)imm); break;
            }
        }
    }
}

/* ============================================================================
 * DIRECTIVE HANDLING
 * ============================================================================ */
static int handle_directive(char *line) {
    char token[256];
    char *p = line;

    p = parse_token(p, token, sizeof(token));
    
    /* Handle both Unix-style (.directive) and MASM-style (directive) */
    int is_dot_directive = (token[0] == '.');
    char *directive_name = is_dot_directive ? token + 1 : token;
    
    /* NASM-style directives (no dot prefix) */
    if (!is_dot_directive) {
        /* SECTION directive - NASM style */
        if (_stricmp(directive_name, "section") == 0 ||
            _stricmp(directive_name, "segment") == 0) {
            p = skip_whitespace(p);
            char sec_name[256];
            p = parse_token(p, sec_name, sizeof(sec_name));
            
            /* Map NASM section names to internal sections */
            if (strstr(sec_name, ".text") || strstr(sec_name, "code")) {
                g_state.current_section = 0;  /* .text */
            } else if (strstr(sec_name, ".data")) {
                g_state.current_section = 1;  /* .data */
            } else if (strstr(sec_name, ".rdata") || strstr(sec_name, ".rodata")) {
                g_state.current_section = 2;  /* .rdata */
            } else if (strstr(sec_name, ".bss")) {
                g_state.current_section = 3;  /* .bss */
            }
            return 1;
        }

        /* GLOBAL directive - NASM style (export symbol) */
        if (_stricmp(directive_name, "global") == 0 ||
            _stricmp(directive_name, "public") == 0) {
            p = skip_whitespace(p);
            char sym_name[256];
            p = parse_token(p, sym_name, sizeof(sym_name));
            /* Mark symbol as public/exported - just skip for now */
            return 1;
        }

        /* EXTERN directive - NASM style (import symbol) */
        if (_stricmp(directive_name, "extern") == 0 ||
            _stricmp(directive_name, "extrn") == 0) {
            p = skip_whitespace(p);
            char sym_name[256];
            p = parse_token(p, sym_name, sizeof(sym_name));
            /* Remove :PROC or :type suffix if present */
            char *colon = strchr(sym_name, ':');
            if (colon) *colon = '\0';
            /* Add to external symbols table */
            if (g_state.extern_count < MAX_EXTERN_SYMBOLS) {
                strncpy(g_state.extern_symbols[g_state.extern_count], sym_name, 255);
                g_state.extern_symbols[g_state.extern_count][255] = '\0';
                g_state.extern_count++;
            }
            return 1;
        }

        /* BITS directive - NASM style (set architecture) */
        if (_stricmp(directive_name, "bits") == 0) {
            p = skip_whitespace(p);
            char val[256];
            p = parse_token(p, val, sizeof(val));
            int bits = (int)parse_number(val);
            if (bits == 16) {
                g_arch = ARCH_X86;
                g_bits = 16;
            } else if (bits == 32) {
                g_arch = ARCH_X86;
                g_bits = 32;
            } else if (bits == 64) {
                g_arch = ARCH_X64;
                g_bits = 64;
            }
            return 1;
        }

        /* DEFAULT directive - NASM style (set default rel/abs) */
        if (_stricmp(directive_name, "default") == 0) {
            p = skip_whitespace(p);
            char val[256];
            p = parse_token(p, val, sizeof(val));
            /* Just skip for now */
            return 1;
        }

        /* Check for MASM-style directives without dot */
        if (_stricmp(directive_name, "equ") == 0) {
            /* EQU directive - define constant */
            p = skip_whitespace(p);
            char name[256];
            p = parse_token(p, name, sizeof(name));
            p = skip_whitespace(p);
            if (*p == ',') p++;
            p = skip_whitespace(p);
            char val[256];
            p = parse_token(p, val, sizeof(val));

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            /* Add as label with absolute value */
            if (g_state.label_count < MAX_LABELS) {
                Label *l = &g_state.labels[g_state.label_count++];
                strncpy(l->name, name, 255);
                l->name[255] = '\0';
                l->offset = (uint32_t)num;
                l->section = g_state.current_section;
                l->is_equ = 1;  /* Mark as EQU constant - don't export to COFF */
            }
            return 1;
        }

        if (_stricmp(directive_name, "option") == 0) {
            /* OPTION directive - assembler options (ignore for now) */
            return 1;
        }

        if (_stricmp(directive_name, "extern") == 0 || _stricmp(directive_name, "extrn") == 0) {
            /* EXTERN/EXTRN directive - import symbol */
            p = skip_whitespace(p);
            char sym_name[256];
            p = parse_token(p, sym_name, sizeof(sym_name));
            /* Remove :PROC or :type suffix if present */
            char *colon = strchr(sym_name, ':');
            if (colon) *colon = '\0';
            /* Add to external symbols table */
            if (g_state.extern_count < MAX_EXTERN_SYMBOLS) {
                strncpy(g_state.extern_symbols[g_state.extern_count], sym_name, 255);
                g_state.extern_symbols[g_state.extern_count][255] = '\0';
                g_state.extern_count++;
            }
            return 1;
        }

        if (_stricmp(directive_name, "public") == 0) {
            /* PUBLIC directive - export symbol */
            p = skip_whitespace(p);
            char sym_name[256];
            p = parse_token(p, sym_name, sizeof(sym_name));
            /* Mark as public symbol (TODO: add to symbol table) */
            return 1;
        }

        if (_stricmp(directive_name, "proc") == 0) {
            /* PROC directive - procedure start */
            p = skip_whitespace(p);
            char proc_name[256];
            p = parse_token(p, proc_name, sizeof(proc_name));
            add_label(proc_name);
            return 1;
        }

        if (_stricmp(directive_name, "endp") == 0) {
            /* ENDP directive - procedure end */
            return 1;
        }

        if (_stricmp(directive_name, "end") == 0) {
            /* END directive - end of source */
            return 1;
        }

        if (_stricmp(directive_name, "include") == 0) {
            /* INCLUDE directive - include file */
            p = skip_whitespace(p);
            char filename[256];
            p = parse_token(p, filename, sizeof(filename));
            /* TODO: Implement file inclusion */
            /* For now, just skip the include */
            return 1;
        }

        if (_stricmp(directive_name, "struct") == 0 || _stricmp(directive_name, "ends") == 0) {
            /* STRUCT/ENDS directive - structure definition */
            /* For now, just skip structure definitions */
            return 1;
        }

        if (_stricmp(directive_name, "externdef") == 0) {
            /* EXTERNDEF directive - external symbol definition */
            p = skip_whitespace(p);
            char sym_name[256];
            p = parse_token(p, sym_name, sizeof(sym_name));
            /* Remove :PROC or :type suffix if present */
            char *colon = strchr(sym_name, ':');
            if (colon) *colon = '\0';
            /* Add to external symbols table */
            if (g_state.extern_count < MAX_EXTERN_SYMBOLS) {
                strncpy(g_state.extern_symbols[g_state.extern_count], sym_name, 255);
                g_state.extern_symbols[g_state.extern_count][255] = '\0';
                g_state.extern_count++;
            }
            return 1;
        }

        if (_stricmp(directive_name, "align") == 0) {
            /* ALIGN directive */
            p = skip_whitespace(p);
            char val[256];
            p = parse_token(p, val, sizeof(val));
            int align = (int)parse_number(val);
            if (align > 0) {
                uint32_t offset = current_offset();
                uint32_t mask = align - 1;
                uint32_t new_offset = (offset + mask) & ~mask;
                while (offset < new_offset) {
                    emit_byte(0x90);  /* NOP padding */
                    offset++;
                }
            }
            return 1;
        }

        if (_stricmp(directive_name, "db") == 0) {
            /* DB directive - define byte */
            p = skip_whitespace(p);
            while (*p) {
                char val[256];
                p = parse_token(p, val, sizeof(val));
                if (val[0] == '\0' || val[0] == ',') continue;

                int is_label = 0;
                char label_name[256];
                int64_t num = evaluate_expression(val, &is_label, label_name);

                if (is_label) {
                    if (g_state.fixup_count < MAX_FIXUPS) {
                        Fixup *f = &g_state.fixups[g_state.fixup_count++];
                        f->offset = current_offset();
                        f->section = g_state.current_section;
                        strncpy(f->label, label_name, 255);
                        f->label[255] = '\0';
                        f->size = 1;
                        f->is_relative = 0;
                    }
                    emit_byte(0);
                } else {
                    emit_byte((uint8_t)num);
                }

                p = skip_whitespace(p);
                if (*p == ',') p++;
            }
            return 1;
        }

        if (_stricmp(directive_name, "dw") == 0 || _stricmp(directive_name, "word") == 0) {
            /* DW/WORD directive - define word */
            p = skip_whitespace(p);
            while (*p) {
                char val[256];
                p = parse_token(p, val, sizeof(val));
                if (val[0] == '\0' || val[0] == ',') continue;

                int is_label = 0;
                char label_name[256];
                int64_t num = evaluate_expression(val, &is_label, label_name);

                if (is_label) {
                    if (g_state.fixup_count < MAX_FIXUPS) {
                        Fixup *f = &g_state.fixups[g_state.fixup_count++];
                        f->offset = current_offset();
                        f->section = g_state.current_section;
                        strncpy(f->label, label_name, 255);
                        f->label[255] = '\0';
                        f->size = 2;
                        f->is_relative = 0;
                    }
                    emit_word(0);
                } else {
                    emit_word((uint16_t)num);
                }

                p = skip_whitespace(p);
                if (*p == ',') p++;
            }
            return 1;
        }

        if (_stricmp(directive_name, "dd") == 0 || _stricmp(directive_name, "dword") == 0) {
            /* DD/DWORD directive - define dword */
            p = skip_whitespace(p);
            while (*p) {
                char val[256];
                p = parse_token(p, val, sizeof(val));
                if (val[0] == '\0' || val[0] == ',') continue;

                int is_label = 0;
                char label_name[256];
                int64_t num = evaluate_expression(val, &is_label, label_name);

                if (is_label) {
                    if (g_state.fixup_count < MAX_FIXUPS) {
                        Fixup *f = &g_state.fixups[g_state.fixup_count++];
                        f->offset = current_offset();
                        f->section = g_state.current_section;
                        strncpy(f->label, label_name, 255);
                        f->label[255] = '\0';
                        f->size = 4;
                        f->is_relative = 0;
                    }
                    emit_dword(0);
                } else {
                    emit_dword((uint32_t)num);
                }

                p = skip_whitespace(p);
                if (*p == ',') p++;
            }
            return 1;
        }

        if (_stricmp(directive_name, "dq") == 0 || _stricmp(directive_name, "qword") == 0) {
            /* DQ/QWORD directive - define qword */
            p = skip_whitespace(p);
            while (*p) {
                char val[256];
                p = parse_token(p, val, sizeof(val));
                if (val[0] == '\0' || val[0] == ',') continue;

                int is_label = 0;
                char label_name[256];
                int64_t num = evaluate_expression(val, &is_label, label_name);

                if (is_label) {
                    if (g_state.fixup_count < MAX_FIXUPS) {
                        Fixup *f = &g_state.fixups[g_state.fixup_count++];
                        f->offset = current_offset();
                        f->section = g_state.current_section;
                        strncpy(f->label, label_name, 255);
                        f->label[255] = '\0';
                        f->size = 8;
                        f->is_relative = 0;
                    }
                    emit_qword(0);
                } else {
                    emit_qword((uint64_t)num);
                }

                p = skip_whitespace(p);
                if (*p == ',') p++;
            }
            return 1;
        }

        if (_stricmp(directive_name, "proc") == 0) {
            /* PROC directive - procedure definition */
            /* The label should already be added by the label handler */
            return 1;
        }

        if (_stricmp(directive_name, "endp") == 0) {
            /* ENDP directive - end procedure */
            return 1;
        }

        if (_stricmp(directive_name, "byte") == 0) {
            /* BYTE directive - define byte(s) */
            p = skip_whitespace(p);
            
            /* Handle string literals */
            if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    emit_byte((uint8_t)*p++);
                }
                if (*p == '"') p++;
                /* Check for null terminator */
                p = skip_whitespace(p);
                if (*p == ',') {
                    p++;
                    p = skip_whitespace(p);
                    if (*p == '0') {
                        emit_byte(0);
                    }
                }
                return 1;
            }
            
            /* Handle numeric values */
            while (*p) {
                char val[256];
                p = parse_token(p, val, sizeof(val));
                if (val[0] == '\0' || val[0] == ',') continue;

                int is_label = 0;
                char label_name[256];
                int64_t num = evaluate_expression(val, &is_label, label_name);

                if (is_label) {
                    if (g_state.fixup_count < MAX_FIXUPS) {
                        Fixup *f = &g_state.fixups[g_state.fixup_count++];
                        f->offset = current_offset();
                        f->section = g_state.current_section;
                        strncpy(f->label, label_name, 255);
                        f->label[255] = '\0';
                        f->size = 1;
                        f->is_relative = 0;
                    }
                    emit_byte(0);
                } else {
                    emit_byte((uint8_t)num);
                }

                p = skip_whitespace(p);
                if (*p == ',') p++;
            }
            return 1;
        }

        if (_stricmp(directive_name, "code") == 0 || _stricmp(directive_name, "text") == 0) {
            g_state.current_section = 0;
            return 1;
        }

        if (_stricmp(directive_name, "data") == 0) {
            g_state.current_section = 1;
            return 1;
        }

        if (_stricmp(directive_name, "const") == 0 || _stricmp(directive_name, "rdata") == 0) {
            g_state.current_section = 2;
            return 1;
        }

        /* Check for structure definitions (WNDCLASSEXA, POINT, MSG, etc.) */
        /* These are typically defined with STRUCT/ENDS but may appear as labels */
        if (_stricmp(directive_name, "wndclassexa") == 0 ||
            _stricmp(directive_name, "point") == 0 ||
            _stricmp(directive_name, "msg") == 0 ||
            _stricmp(directive_name, "copydatastruct") == 0 ||
            _stricmp(directive_name, "initcommoncontrolsex") == 0) {
            /* Structure definition - skip for now */
            return 1;
        }

        /* Not a MASM directive without dot */
        return 0;
    }

    /* Unix-style directives with dot */
    if (_stricmp(token, ".code") == 0 || _stricmp(token, ".text") == 0) {
        g_state.current_section = 0;
        return 1;
    }

    if (_stricmp(token, ".data") == 0) {
        g_state.current_section = 1;
        return 1;
    }

    if (_stricmp(token, ".rdata") == 0 || _stricmp(token, ".const") == 0) {
        g_state.current_section = 2;
        return 1;
    }

    if (_stricmp(token, ".bss") == 0) {
        g_state.current_section = 3;
        return 1;
    }

    if (_stricmp(token, ".386") == 0) {
        g_arch = ARCH_X86;
        g_bits = 32;
        return 1;
    }

    if (_stricmp(token, ".x64") == 0 || _stricmp(token, ".x86_64") == 0) {
        g_arch = ARCH_X64;
        g_bits = 64;
        return 1;
    }

    if (_stricmp(token, ".x32") == 0) {
        g_arch = ARCH_X32;
        g_bits = 32;  /* ILP32 */
        return 1;
    }

    if (_stricmp(token, ".byte") == 0) {
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 1;
                    f->is_relative = 0;
                }
                emit_byte(0);
            } else {
                emit_byte((uint8_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    if (_stricmp(token, ".word") == 0) {
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 2;
                    f->is_relative = 0;
                }
                emit_word(0);
            } else {
                emit_word((uint16_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    if (_stricmp(token, ".dword") == 0 || _stricmp(token, ".long") == 0) {
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 4;
                    f->is_relative = 0;
                }
                emit_dword(0);
            } else {
                emit_dword((uint32_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    if (_stricmp(token, ".qword") == 0 || _stricmp(token, ".quad") == 0) {
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 8;
                    f->is_relative = 0;
                }
                emit_qword(0);
            } else {
                emit_qword((uint64_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    if (_stricmp(token, ".ascii") == 0 || _stricmp(token, ".string") == 0) {
        p = skip_whitespace(p);
        char str[1024];
        p = parse_token(p, str, sizeof(str));
        for (int i = 0; str[i]; i++) {
            emit_byte((uint8_t)str[i]);
        }
        return 1;
    }

    if (_stricmp(token, ".asciiz") == 0 || _stricmp(token, ".asciz") == 0) {
        p = skip_whitespace(p);
        char str[1024];
        p = parse_token(p, str, sizeof(str));
        for (int i = 0; str[i]; i++) {
            emit_byte((uint8_t)str[i]);
        }
        emit_byte(0);
        return 1;
    }

    if (_stricmp(token, ".align") == 0) {
        p = skip_whitespace(p);
        char val[256];
        p = parse_token(p, val, sizeof(val));
        int align = (int)parse_number(val);
        if (align > 0) {
            uint32_t offset = current_offset();
            uint32_t mask = align - 1;
            uint32_t new_offset = (offset + mask) & ~mask;
            while (offset < new_offset) {
                emit_byte(0x90);  /* NOP padding */
                offset++;
            }
        }
        return 1;
    }

    if (_stricmp(token, ".entry") == 0) {
        p = skip_whitespace(p);
        char entry[256];
        p = parse_token(p, entry, sizeof(entry));
        int idx = find_label(entry);
        if (idx >= 0) {
            g_state.entry_point = g_state.labels[idx].offset;
            g_state.has_entry = 1;
        }
        return 1;
    }

    if (_stricmp(token, ".org") == 0) {
        p = skip_whitespace(p);
        char val[256];
        p = parse_token(p, val, sizeof(val));
        uint32_t org = (uint32_t)parse_number(val);
        while (current_offset() < org) {
            emit_byte(0);
        }
        return 1;
    }

    if (_stricmp(token, ".equ") == 0 || _stricmp(token, ".set") == 0) {
        p = skip_whitespace(p);
        char name[256];
        p = parse_token(p, name, sizeof(name));
        p = skip_whitespace(p);
        if (*p == ',') p++;
        p = skip_whitespace(p);
        char val[256];
        p = parse_token(p, val, sizeof(val));

        int is_label = 0;
        char label_name[256];
        int64_t num = evaluate_expression(val, &is_label, label_name);

        /* Add as label with absolute value */
        if (g_state.label_count < MAX_LABELS) {
            Label *l = &g_state.labels[g_state.label_count++];
            strncpy(l->name, name, 255);
            l->name[255] = '\0';
            l->offset = (uint32_t)num;
            l->section = g_state.current_section;
            l->is_equ = 1;  /* Mark as EQU constant - don't export to COFF */
        }
        return 1;
    }

    if (_stricmp(token, ".include") == 0) {
        /* TODO: Handle includes */
        return 1;
    }

    if (_stricmp(token, ".macro") == 0) {
        /* TODO: Handle macros */
        return 1;
    }

    if (_stricmp(token, ".proc") == 0 || _stricmp(token, ".endp") == 0 ||
        _stricmp(token, ".local") == 0 || _stricmp(token, ".end") == 0) {
        /* Procedure directives - mostly ignored for now */
        return 1;
    }

    /* MASM directives */
    if (_stricmp(token, "public") == 0) {
        /* PUBLIC directive - export symbol */
        return 1;
    }

    if (_stricmp(token, "extrn") == 0 || _stricmp(token, "extern") == 0) {
        /* EXTRN/EXTERN directive - import symbol */
        return 1;
    }

    if (_stricmp(token, "proc") == 0) {
        /* PROC directive - procedure start */
        p = skip_whitespace(p);
        char proc_name[256];
        p = parse_token(p, proc_name, sizeof(proc_name));
        add_label(proc_name);
        return 1;
    }

    if (_stricmp(token, "endp") == 0) {
        /* ENDP directive - procedure end */
        return 1;
    }

    if (_stricmp(token, "end") == 0) {
        /* END directive - end of source */
        return 1;
    }

    if (_stricmp(token, "frame") == 0) {
        /* FRAME directive - for unwind info */
        return 1;
    }

    if (_stricmp(token, ".pushreg") == 0) {
        /* .pushreg directive - unwind info */
        return 1;
    }

    if (_stricmp(token, ".allocstack") == 0) {
        /* .allocstack directive - unwind info */
        return 1;
    }

    if (_stricmp(token, ".endprolog") == 0) {
        /* .endprolog directive - unwind info */
        return 1;
    }

    if (_stricmp(token, ".savereg") == 0) {
        /* .savereg directive - unwind info */
        return 1;
    }

    if (_stricmp(token, ".savexmm128") == 0) {
        /* .savexmm128 directive - unwind info */
        return 1;
    }

    if (_stricmp(token, "align") == 0 || _stricmp(token, ".align") == 0) {
        /* ALIGN directive */
        p = skip_whitespace(p);
        char val[256];
        p = parse_token(p, val, sizeof(val));
        int align = (int)parse_number(val);
        if (align > 0) {
            uint32_t offset = current_offset();
            uint32_t mask = align - 1;
            uint32_t new_offset = (offset + mask) & ~mask;
            while (offset < new_offset) {
                emit_byte(0x90);  /* NOP padding */
                offset++;
            }
        }
        return 1;
    }

    if (_stricmp(token, "db") == 0 || _stricmp(token, ".byte") == 0) {
        /* DB directive - define byte */
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 1;
                    f->is_relative = 0;
                }
                emit_byte(0);
            } else {
                emit_byte((uint8_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    if (_stricmp(token, "dw") == 0 || _stricmp(token, ".word") == 0) {
        /* DW directive - define word */
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 2;
                    f->is_relative = 0;
                }
                emit_word(0);
            } else {
                emit_word((uint16_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    if (_stricmp(token, "dd") == 0 || _stricmp(token, ".dword") == 0 || _stricmp(token, ".long") == 0) {
        /* DD directive - define dword */
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 4;
                    f->is_relative = 0;
                }
                emit_dword(0);
            } else {
                emit_dword((uint32_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    if (_stricmp(token, "dq") == 0 || _stricmp(token, ".qword") == 0 || _stricmp(token, ".quad") == 0) {
        /* DQ directive - define qword */
        p = skip_whitespace(p);
        while (*p) {
            char val[256];
            p = parse_token(p, val, sizeof(val));
            if (val[0] == '\0' || val[0] == ',') continue;

            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);

            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 8;
                    f->is_relative = 0;
                }
                emit_qword(0);
            } else {
                emit_qword((uint64_t)num);
            }

            p = skip_whitespace(p);
            if (*p == ',') p++;
        }
        return 1;
    }

    return 0;
}

/* ============================================================================
 * LABEL HANDLING
 * ============================================================================ */
/* Forward declarations */
static const InstructionEncoding* find_instruction(const char *mnemonic,
                                                      const char *op1,
                                                      const char *op2,
                                                      const char *op3);

/* Simple check if a mnemonic exists in the instruction table */
static int mnemonic_exists(const char *mnemonic) {
    for (int i = 0; g_instructions[i].mnemonic != NULL; i++) {
        if (_stricmp(g_instructions[i].mnemonic, mnemonic) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_label_definition(char *line, char *label_out) {
    char *p = skip_whitespace(line);
    int i = 0;

    while (is_label_char(p[i]) && i < 255) {
        label_out[i] = p[i];
        i++;
    }

    if (i == 0) return 0;

    label_out[i] = '\0';

    /* Check if followed by colon OR EQU directive OR data directive OR PROC */
    char *after = skip_whitespace(p + i);
    if (*after == ':') {
        return 1;
    }
    
    /* Check for EQU directive (MASM-style constant definition) */
    if (_strnicmp(after, "EQU", 3) == 0 && !is_label_char(after[3])) {
        return 1;
    }
    
    /* Check for PROC directive (MASM-style procedure definition) */
    if (_strnicmp(after, "PROC", 4) == 0 && !is_label_char(after[4])) {
        return 1;
    }
    
    /* Check for FRAME keyword after PROC */
    if (_strnicmp(after, "PROC", 4) == 0) {
        char *after_proc = skip_whitespace(after + 4);
        if (_strnicmp(after_proc, "FRAME", 5) == 0) {
            return 1;
        }
    }
    
    /* Check for ENDP directive (marks end of procedure) */
    if (_strnicmp(after, "ENDP", 4) == 0 && !is_label_char(after[4])) {
        return 1;
    }
    
    /* Check for data directives (MASM allows label without colon before data) */
    if (_strnicmp(after, "BYTE", 4) == 0 && !is_label_char(after[4])) return 1;
    if (_strnicmp(after, "WORD", 4) == 0 && !is_label_char(after[4])) return 1;
    if (_strnicmp(after, "DWORD", 5) == 0 && !is_label_char(after[5])) return 1;
    if (_strnicmp(after, "QWORD", 5) == 0 && !is_label_char(after[5])) return 1;
    if (_strnicmp(after, "DB", 2) == 0 && !is_label_char(after[2])) return 1;
    if (_strnicmp(after, "DW", 2) == 0 && !is_label_char(after[2])) return 1;
    if (_strnicmp(after, "DD", 2) == 0 && !is_label_char(after[2])) return 1;
    if (_strnicmp(after, "DQ", 2) == 0 && !is_label_char(after[2])) return 1;
    
    /* Check if the token after the label is a known instruction */
    /* If so, this is NOT a label - it's an instruction */
    char next_token[256];
    char *token_start = after;
    int j = 0;
    while (is_label_char(token_start[j]) && j < 255) {
        next_token[j] = token_start[j];
        j++;
    }
    next_token[j] = '\0';
    
    if (j > 0 && mnemonic_exists(next_token)) {
        return 0;  /* This is an instruction, not a label */
    }
    
    /* Check for MASM directives that follow labels */
    if (_strnicmp(after, ".", 1) == 0) return 1;  /* Dot directives like .setframe */
    if (_strnicmp(after, "OPTION", 6) == 0 && !is_label_char(after[6])) return 1;
    if (_strnicmp(after, "ALIGN", 5) == 0 && !is_label_char(after[5])) return 1;
    if (_strnicmp(after, "PUBLIC", 6) == 0 && !is_label_char(after[6])) return 1;
    if (_strnicmp(after, "EXTERNDEF", 9) == 0 && !is_label_char(after[9])) return 1;
    if (_strnicmp(after, "INCLUDE", 7) == 0 && !is_label_char(after[7])) return 1;

    return 0;
}

/* ============================================================================
 * Handle EQU constant definition
 * ============================================================================ */
static int handle_equ_definition(char *line) {
    char *p = skip_whitespace(line);
    char name[256];
    
    /* Parse the constant name */
    int i = 0;
    while (is_label_char(p[i]) && i < 255) {
        name[i] = p[i];
        i++;
    }
    name[i] = '\0';
    
    p = skip_whitespace(p + i);
    
    /* Skip EQU keyword */
    if (_strnicmp(p, "EQU", 3) != 0) return 0;
    p += 3;
    p = skip_whitespace(p);
    
    /* Parse the value */
    char val[256];
    p = parse_token(p, val, sizeof(val));
    
    int is_label = 0;
    char label_name[256];
    int64_t num = evaluate_expression(val, &is_label, label_name);
    
    /* Add as label with absolute value */
    if (g_state.label_count < MAX_LABELS) {
        Label *l = &g_state.labels[g_state.label_count++];
        strncpy(l->name, name, 255);
        l->name[255] = '\0';
        l->offset = (uint32_t)num;
        l->section = g_state.current_section;
        l->is_equ = 1;  /* Mark as EQU constant - don't export to COFF */
    }
    
    return 1;
}

/* ============================================================================
 * Handle data definition with optional label
 * ============================================================================ */
static int handle_data_definition(char *line) {
    char *p = skip_whitespace(line);
    char name[256];
    int has_label = 0;
    
    /* Check for label before data directive */
    int i = 0;
    while (is_label_char(p[i]) && i < 255) {
        name[i] = p[i];
        i++;
    }
    
    if (i > 0) {
        char *after = skip_whitespace(p + i);
        
        /* Check if followed by data directive */
        if (_strnicmp(after, "BYTE", 4) == 0 && !is_label_char(after[4])) {
            name[i] = '\0';
            add_label(name);
            p = after + 4;
            has_label = 1;
        } else if (_strnicmp(after, "WORD", 4) == 0 && !is_label_char(after[4])) {
            name[i] = '\0';
            add_label(name);
            p = after + 4;
            has_label = 1;
        } else if (_strnicmp(after, "DWORD", 5) == 0 && !is_label_char(after[5])) {
            name[i] = '\0';
            add_label(name);
            p = after + 5;
            has_label = 1;
        } else if (_strnicmp(after, "QWORD", 5) == 0 && !is_label_char(after[5])) {
            name[i] = '\0';
            add_label(name);
            p = after + 5;
            has_label = 1;
        } else if (_strnicmp(after, "DB", 2) == 0 && !is_label_char(after[2])) {
            name[i] = '\0';
            add_label(name);
            p = after + 2;
            has_label = 1;
        } else if (_strnicmp(after, "DW", 2) == 0 && !is_label_char(after[2])) {
            name[i] = '\0';
            add_label(name);
            p = after + 2;
            has_label = 1;
        } else if (_strnicmp(after, "DD", 2) == 0 && !is_label_char(after[2])) {
            name[i] = '\0';
            add_label(name);
            p = after + 2;
            has_label = 1;
        } else if (_strnicmp(after, "DQ", 2) == 0 && !is_label_char(after[2])) {
            name[i] = '\0';
            add_label(name);
            p = after + 2;
            has_label = 1;
        }
    }
    
    if (!has_label) return 0;
    
    /* Parse data values */
    p = skip_whitespace(p);
    
    /* Handle string literals */
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            emit_byte((uint8_t)*p++);
        }
        if (*p == '"') p++;
        /* Emit null terminator if followed by comma and 0 */
        p = skip_whitespace(p);
        if (*p == ',') {
            p++;
            p = skip_whitespace(p);
            if (*p == '0') {
                emit_byte(0);
            }
        }
        return 1;
    }
    
    /* Handle numeric values */
    while (*p) {
        char val[256];
        p = parse_token(p, val, sizeof(val));
        if (val[0] == '\0' || val[0] == ',') continue;
        
        /* Skip OFFSET keyword */
        if (_stricmp(val, "OFFSET") == 0 || _stricmp(val, "OFF") == 0) {
            p = skip_whitespace(p);
            p = parse_token(p, val, sizeof(val));
            /* Add fixup for the label */
            if (g_state.fixup_count < MAX_FIXUPS) {
                Fixup *f = &g_state.fixups[g_state.fixup_count++];
                f->offset = current_offset();
                f->section = g_state.current_section;
                strncpy(f->label, val, 255);
                f->label[255] = '\0';
                f->size = 8; /* QWORD for OFFSET */
                f->is_relative = 0;
            }
            emit_qword(0);
        } else {
            int is_label = 0;
            char label_name[256];
            int64_t num = evaluate_expression(val, &is_label, label_name);
            
            if (is_label) {
                if (g_state.fixup_count < MAX_FIXUPS) {
                    Fixup *f = &g_state.fixups[g_state.fixup_count++];
                    f->offset = current_offset();
                    f->section = g_state.current_section;
                    strncpy(f->label, label_name, 255);
                    f->label[255] = '\0';
                    f->size = 1;
                    f->is_relative = 0;
                }
                emit_byte(0);
            } else {
                emit_byte((uint8_t)num);
            }
        }
        
        p = skip_whitespace(p);
        if (*p == ',') p++;
    }
    
    return 1;
}

/* ============================================================================
 * INSTRUCTION PARSING
 * ============================================================================ */
static void parse_instruction(char *line) {
    char mnemonic[256];
    char operands[3][256];
    int operand_count = 0;

    memset(operands, 0, sizeof(operands));

    char *p = skip_whitespace(line);

    /* Skip label if present */
    char label_name[256];
    if (is_label_definition(p, label_name)) {
        /* Check if this is an EQU definition - if so, let handle_equ_definition handle it */
        char *after_label = skip_whitespace(p + strlen(label_name));
        if (_strnicmp(after_label, "EQU", 3) == 0 && !is_label_char(after_label[3])) {
            /* EQU definition - handle_equ_definition will create the label */
            if (handle_equ_definition(p)) {
                return;
            }
        }
        
        add_label(label_name);
        p = skip_whitespace(p + strlen(label_name));
        if (*p == ':') p++;
        p = skip_whitespace(p);
        
        /* Check for PROC directive after label */
        if (_strnicmp(p, "PROC", 4) == 0) {
            /* Skip PROC and any attributes (FRAME, etc.) */
            p += 4;
            p = skip_whitespace(p);
            while (*p && !isspace((unsigned char)*p) && *p != ';') {
                p++;
            }
            p = skip_whitespace(p);
        }
        
        /* Return if nothing else on line */
        if (!*p || *p == ';') return;
    }

    /* Skip empty lines */
    if (!*p || *p == ';') return;

    /* Check for EQU constant definition (MASM-style) */
    if (handle_equ_definition(p)) {
        return;
    }

    /* Check for data definition with optional label (MASM-style) */
    if (handle_data_definition(p)) {
        return;
    }

    /* Check for directive (both Unix-style with dot and MASM-style without dot) */
    if (handle_directive(p)) {
        return;
    }

    /* Parse mnemonic */
    char *mnem_end = parse_token(p, mnemonic, sizeof(mnemonic));
    if (mnemonic[0] == '\0') return;

    /* Check if it's actually a directive */
    if (handle_directive(p)) {
        return;
    }

    p = skip_whitespace(mnem_end);

    /* Parse operands */
    int in_string = 0;
    char string_char = 0;
    int op_idx = 0;
    int char_idx = 0;

    while (*p && operand_count < 3) {
        if (!in_string && (*p == '"' || *p == '\'')) {
            in_string = 1;
            string_char = *p;
            operands[operand_count][char_idx++] = *p++;
        } else if (in_string && *p == string_char) {
            in_string = 0;
            operands[operand_count][char_idx++] = *p++;
        } else if (!in_string && *p == ',') {
            operands[operand_count][char_idx] = '\0';
            operand_count++;
            char_idx = 0;
            p++;
        } else if (!in_string && *p == ';') {
            break;
        } else {
            operands[operand_count][char_idx++] = *p++;
        }
    }

    if (char_idx > 0) {
        operands[operand_count][char_idx] = '\0';
        operand_count++;
    }

    /* Trim whitespace from operands */
    for (int i = 0; i < operand_count; i++) {
        char *start = operands[i];
        while (isspace((unsigned char)*start)) start++;
        char *end = start + strlen(start) - 1;
        while (end > start && isspace((unsigned char)*end)) *end-- = '\0';
        memmove(operands[i], start, strlen(start) + 1);
    }

    /* Find and emit instruction */
    const InstructionEncoding *inst = find_instruction(mnemonic,
                                                        operands[0],
                                                        operands[1],
                                                        operands[2]);

    if (inst) {
        emit_instruction(inst, operands[0], operands[1], operands[2]);
    } else {
        fprintf(stderr, "Error: Unknown instruction '%s'\n", mnemonic);
    }
}

/* ============================================================================
 * FIXUP RESOLUTION
 * ============================================================================ */
static void resolve_fixups(void) {
    for (int i = 0; i < g_state.fixup_count; i++) {
        Fixup *f = &g_state.fixups[i];
        int label_idx = find_label(f->label);

        /* Check if this is an external symbol */
        int is_extern = 0;
        for (int j = 0; j < g_state.extern_count; j++) {
            if (_stricmp(g_state.extern_symbols[j], f->label) == 0) {
                is_extern = 1;
                break;
            }
        }

        if (label_idx < 0 && !is_extern) {
            fprintf(stderr, "Error: Undefined label '%s'\n", f->label);
            continue;
        }

        /* For external symbols, we don't resolve the fixup here - it will be handled by the linker */
        if (is_extern && label_idx < 0) {
            /* External symbol - relocation will be generated in write_coff_object() */
            /* Don't patch the code, but keep the fixup for relocation generation */
            continue;
        }

        if (label_idx < 0) {
            continue;
        }

        Label *l = &g_state.labels[label_idx];
        Section *sec = NULL;

        switch (f->section) {
            case 0: sec = &g_state.text; break;
            case 1: sec = &g_state.data; break;
            case 2: sec = &g_state.rdata; break;
            case 3: sec = &g_state.bss; break;
        }

        if (!sec) continue;

        uint32_t target_addr = l->offset;
        uint32_t fixup_addr = f->offset;

        if (f->is_relative) {
            /* Calculate relative offset */
            int32_t rel = (int32_t)(target_addr - (f->instruction_start + 5));

            /* Patch the displacement */
            if (f->size == 1) {
                sec->data[fixup_addr] = (uint8_t)(int8_t)rel;
            } else if (f->size == 4) {
                sec->data[fixup_addr] = rel & 0xFF;
                sec->data[fixup_addr + 1] = (rel >> 8) & 0xFF;
                sec->data[fixup_addr + 2] = (rel >> 16) & 0xFF;
                sec->data[fixup_addr + 3] = (rel >> 24) & 0xFF;
            }
        } else {
            /* Absolute address */
            if (f->size == 1) {
                sec->data[fixup_addr] = target_addr & 0xFF;
            } else if (f->size == 2) {
                sec->data[fixup_addr] = target_addr & 0xFF;
                sec->data[fixup_addr + 1] = (target_addr >> 8) & 0xFF;
            } else if (f->size == 4) {
                sec->data[fixup_addr] = target_addr & 0xFF;
                sec->data[fixup_addr + 1] = (target_addr >> 8) & 0xFF;
                sec->data[fixup_addr + 2] = (target_addr >> 16) & 0xFF;
                sec->data[fixup_addr + 3] = (target_addr >> 24) & 0xFF;
            } else if (f->size == 8) {
                for (int j = 0; j < 8; j++) {
                    sec->data[fixup_addr + j] = (target_addr >> (j * 8)) & 0xFF;
                }
            }
        }
    }
}

/* ============================================================================
 * PE FILE GENERATION
 * ============================================================================ */
#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386  0x014C
#define IMAGE_NT_SIGNATURE       0x00004550
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020

#define IMAGE_SCN_CNT_CODE       0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE    0x20000000
#define IMAGE_SCN_MEM_READ       0x40000000
#define IMAGE_SCN_MEM_WRITE      0x80000000

#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3

#pragma pack(pop)

/* ============================================================================
 * COFF OBJECT FILE WRITER
 * ============================================================================ */

/* COFF structures */
#pragma pack(push, 1)

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_FILE_HEADER;

typedef struct {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} COFF_SECTION_HEADER;

typedef struct {
    union {
        uint8_t ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } Name;
    } N;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} COFF_RELOCATION;

#pragma pack(pop)

#define COFF_MACHINE_AMD64 0x8664
#define COFF_MACHINE_I386  0x014C

#define COFF_SECTION_CODE       0x00000020
#define COFF_SECTION_DATA       0x00000040
#define COFF_SECTION_BSS        0x00000080
#define COFF_SECTION_ALIGN_1     0x00100000
#define COFF_SECTION_ALIGN_2     0x00200000
#define COFF_SECTION_ALIGN_4     0x00300000
#define COFF_SECTION_ALIGN_8     0x00400000
#define COFF_SECTION_ALIGN_16    0x00500000
#define COFF_SECTION_ALIGN_32    0x00600000
#define COFF_SECTION_ALIGN_64    0x00700000
#define COFF_SECTION_ALIGN_128   0x00800000
#define COFF_SECTION_ALIGN_256   0x00900000
#define COFF_SECTION_ALIGN_512   0x00A00000
#define COFF_SECTION_ALIGN_1024  0x00B00000
#define COFF_SECTION_ALIGN_2048  0x00C00000
#define COFF_SECTION_ALIGN_4096  0x00D00000
#define COFF_SECTION_ALIGN_8192  0x00E00000
#define COFF_SECTION_MEM_EXECUTE 0x20000000
#define COFF_SECTION_MEM_READ    0x40000000
#define COFF_SECTION_MEM_WRITE   0x80000000

#define COFF_SYMBOL_EXTERNAL  2
#define COFF_SYMBOL_STATIC     3
#define COFF_SYMBOL_LABEL      6

#define COFF_REL_ADDR32   0x0002  /* IMAGE_REL_AMD64_ADDR32 */
#define COFF_REL_ADDR64   0x0001  /* IMAGE_REL_AMD64_ADDR64 */
#define COFF_REL_REL32    0x0004  /* IMAGE_REL_AMD64_REL32 */

/* IMAGE constants for compatibility */
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386   0x014C
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA  0x00000080
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000
#define IMAGE_SYM_TYPE_NULL   0
#define IMAGE_SYM_CLASS_EXTERNAL 2
#define IMAGE_SYM_CLASS_STATIC  3
#define IMAGE_REL_AMD64_ADDR64  0x0001
#define IMAGE_REL_AMD64_ADDR32  0x0002
#define IMAGE_REL_AMD64_REL32   0x0004

static void write_coff_object(const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create object file '%s'\n", filename);
        return;
    }

    /* Count sections */
    int num_sections = 0;
    if (g_state.text.size > 0) num_sections++;
    if (g_state.data.size > 0) num_sections++;
    if (g_state.rdata.size > 0) num_sections++;
    if (g_state.bss.size > 0) num_sections++;
    if (num_sections == 0) num_sections = 1; /* At least one section */

    /* Calculate symbol count */
    int num_symbols = 0;
    
    /* File symbol (auxiliary) */
    num_symbols += 2;
    
    /* Section symbols */
    int section_symbol_idx[4] = {0, 0, 0, 0};
    int sym_idx = 2;
    
    if (g_state.text.size > 0) {
        section_symbol_idx[0] = sym_idx;
        sym_idx += 2; /* Section + auxiliary */
        num_symbols += 2;
    }
    if (g_state.data.size > 0) {
        section_symbol_idx[1] = sym_idx;
        sym_idx += 2;
        num_symbols += 2;
    }
    if (g_state.rdata.size > 0) {
        section_symbol_idx[2] = sym_idx;
        sym_idx += 2;
        num_symbols += 2;
    }
    if (g_state.bss.size > 0) {
        section_symbol_idx[3] = sym_idx;
        sym_idx += 2;
        num_symbols += 2;
    }
    
    /* Label symbols (excluding EQU constants) */
    int label_start_idx = sym_idx;
    int non_equ_label_count = 0;
    for (int i = 0; i < g_state.label_count; i++) {
        if (!g_state.labels[i].is_equ) non_equ_label_count++;
    }
    num_symbols += non_equ_label_count;
    
    /* External symbols (from EXTERNDEF) */
    num_symbols += g_state.extern_count;

    /* Calculate header size */
    size_t header_size = sizeof(COFF_FILE_HEADER);
    size_t section_table_offset = header_size;
    size_t section_table_size = num_sections * sizeof(COFF_SECTION_HEADER);
    
    /* Calculate raw data offsets */
    size_t text_offset = section_table_offset + section_table_size;
    size_t data_offset = text_offset + ((g_state.text.size + 15) & ~15);
    size_t rdata_offset = data_offset + ((g_state.data.size + 15) & ~15);
    size_t bss_offset = rdata_offset + ((g_state.rdata.size + 15) & ~15);
    
    /* Calculate relocation table offsets */
    size_t reloc_offset = bss_offset;
    size_t text_relocs = 0;
    size_t data_relocs = 0;
    size_t rdata_relocs = 0;
    
    /* Count relocations - include both internal labels and external symbols */
    for (int i = 0; i < g_state.fixup_count; i++) {
        Fixup *f = &g_state.fixups[i];
        int label_idx = find_label(f->label);
        int extern_idx = -1;
        for (int j = 0; j < g_state.extern_count; j++) {
            if (_stricmp(g_state.extern_symbols[j], f->label) == 0) {
                extern_idx = j;
                break;
            }
        }
        /* Only count if this fixup references a known label or external symbol */
        if (label_idx < 0 && extern_idx < 0) continue;
        
        if (f->section == 0) text_relocs++;
        else if (f->section == 1) data_relocs++;
        else if (f->section == 2) rdata_relocs++;
    }
    
    size_t text_reloc_offset = reloc_offset;
    size_t data_reloc_offset = text_reloc_offset + text_relocs * sizeof(COFF_RELOCATION);
    size_t rdata_reloc_offset = data_reloc_offset + data_relocs * sizeof(COFF_RELOCATION);
    
    /* Symbol table offset */
    size_t symbol_table_offset = rdata_reloc_offset + rdata_relocs * sizeof(COFF_RELOCATION);
    
    /* String table offset */
    size_t string_table_offset = symbol_table_offset + num_symbols * sizeof(COFF_SYMBOL);

    /* Write COFF header */
    COFF_FILE_HEADER coff_header = {0};
    coff_header.Machine = (g_bits == 64) ? COFF_MACHINE_AMD64 : COFF_MACHINE_I386;
    coff_header.NumberOfSections = num_sections;
    coff_header.TimeDateStamp = (uint32_t)time(NULL);
    coff_header.PointerToSymbolTable = (uint32_t)symbol_table_offset;
    coff_header.NumberOfSymbols = num_symbols;
    coff_header.SizeOfOptionalHeader = 0;
    coff_header.Characteristics = 0;
    fwrite(&coff_header, sizeof(coff_header), 1, fp);

    /* Write section headers */
    int sec_num = 1;
    
    if (g_state.text.size > 0) {
        COFF_SECTION_HEADER sec = {0};
        memcpy(sec.Name, ".text", 5);
        sec.VirtualSize = (uint32_t)g_state.text.size;
        sec.VirtualAddress = 0;
        sec.SizeOfRawData = (uint32_t)((g_state.text.size + 15) & ~15);
        sec.PointerToRawData = (uint32_t)text_offset;
        if (text_relocs > 0) {
            sec.PointerToRelocations = (uint32_t)text_reloc_offset;
            sec.NumberOfRelocations = (uint16_t)text_relocs;
        }
        sec.Characteristics = COFF_SECTION_CODE | COFF_SECTION_ALIGN_16 | 
                              COFF_SECTION_MEM_EXECUTE | COFF_SECTION_MEM_READ;
        fwrite(&sec, sizeof(sec), 1, fp);
        sec_num++;
    }
    
    if (g_state.data.size > 0) {
        COFF_SECTION_HEADER sec = {0};
        memcpy(sec.Name, ".data", 5);
        sec.VirtualSize = (uint32_t)g_state.data.size;
        sec.VirtualAddress = 0;
        sec.SizeOfRawData = (uint32_t)((g_state.data.size + 15) & ~15);
        sec.PointerToRawData = (uint32_t)data_offset;
        if (data_relocs > 0) {
            sec.PointerToRelocations = (uint32_t)data_reloc_offset;
            sec.NumberOfRelocations = (uint16_t)data_relocs;
        }
        sec.Characteristics = COFF_SECTION_DATA | COFF_SECTION_ALIGN_16 | 
                              COFF_SECTION_MEM_READ | COFF_SECTION_MEM_WRITE;
        fwrite(&sec, sizeof(sec), 1, fp);
        sec_num++;
    }
    
    if (g_state.rdata.size > 0) {
        COFF_SECTION_HEADER sec = {0};
        memcpy(sec.Name, ".rdata", 6);
        sec.VirtualSize = (uint32_t)g_state.rdata.size;
        sec.VirtualAddress = 0;
        sec.SizeOfRawData = (uint32_t)((g_state.rdata.size + 15) & ~15);
        sec.PointerToRawData = (uint32_t)rdata_offset;
        if (rdata_relocs > 0) {
            sec.PointerToRelocations = (uint32_t)rdata_reloc_offset;
            sec.NumberOfRelocations = (uint16_t)rdata_relocs;
        }
        sec.Characteristics = COFF_SECTION_DATA | COFF_SECTION_ALIGN_16 | 
                              COFF_SECTION_MEM_READ;
        fwrite(&sec, sizeof(sec), 1, fp);
        sec_num++;
    }
    
    if (g_state.bss.size > 0) {
        COFF_SECTION_HEADER sec = {0};
        memcpy(sec.Name, ".bss", 4);
        sec.VirtualSize = (uint32_t)g_state.bss.size;
        sec.VirtualAddress = 0;
        sec.SizeOfRawData = 0;
        sec.PointerToRawData = 0;
        sec.Characteristics = COFF_SECTION_BSS | COFF_SECTION_ALIGN_16 | 
                              COFF_SECTION_MEM_READ | COFF_SECTION_MEM_WRITE;
        fwrite(&sec, sizeof(sec), 1, fp);
    }

    /* Write section data */
    if (g_state.text.size > 0) {
        fwrite(g_state.text.data, g_state.text.size, 1, fp);
        /* Pad to alignment */
        size_t pad = ((g_state.text.size + 15) & ~15) - g_state.text.size;
        for (size_t i = 0; i < pad; i++) fputc(0, fp);
    }
    
    if (g_state.data.size > 0) {
        fwrite(g_state.data.data, g_state.data.size, 1, fp);
        size_t pad = ((g_state.data.size + 15) & ~15) - g_state.data.size;
        for (size_t i = 0; i < pad; i++) fputc(0, fp);
    }
    
    if (g_state.rdata.size > 0) {
        fwrite(g_state.rdata.data, g_state.rdata.size, 1, fp);
        size_t pad = ((g_state.rdata.size + 15) & ~15) - g_state.rdata.size;
        for (size_t i = 0; i < pad; i++) fputc(0, fp);
    }

    /* Write relocations - grouped by section */
    /* Text section relocations */
    for (int i = 0; i < g_state.fixup_count; i++) {
        Fixup *f = &g_state.fixups[i];
        if (f->section != 0) continue; /* Only text section */
        
        int label_idx = find_label(f->label);
        int extern_idx = -1;
        for (int j = 0; j < g_state.extern_count; j++) {
            if (_stricmp(g_state.extern_symbols[j], f->label) == 0) {
                extern_idx = j;
                break;
            }
        }
        if (label_idx < 0 && extern_idx < 0) continue;
        
        COFF_RELOCATION reloc = {0};
        reloc.VirtualAddress = f->offset;
        
        if (extern_idx >= 0) {
            reloc.SymbolTableIndex = label_start_idx + g_state.label_count + extern_idx;
            reloc.Type = f->is_relative ? COFF_REL_REL32 : ((g_bits == 64) ? COFF_REL_ADDR64 : COFF_REL_ADDR32);
        } else {
            reloc.SymbolTableIndex = label_start_idx + label_idx;
            reloc.Type = (g_bits == 64) ? COFF_REL_REL32 : COFF_REL_ADDR32;
        }
        fwrite(&reloc, sizeof(reloc), 1, fp);
    }
    
    /* Data section relocations */
    for (int i = 0; i < g_state.fixup_count; i++) {
        Fixup *f = &g_state.fixups[i];
        if (f->section != 1) continue; /* Only data section */
        
        int label_idx = find_label(f->label);
        int extern_idx = -1;
        for (int j = 0; j < g_state.extern_count; j++) {
            if (_stricmp(g_state.extern_symbols[j], f->label) == 0) {
                extern_idx = j;
                break;
            }
        }
        if (label_idx < 0 && extern_idx < 0) continue;
        
        COFF_RELOCATION reloc = {0};
        reloc.VirtualAddress = f->offset;
        
        if (extern_idx >= 0) {
            reloc.SymbolTableIndex = label_start_idx + g_state.label_count + extern_idx;
            reloc.Type = f->is_relative ? COFF_REL_REL32 : ((g_bits == 64) ? COFF_REL_ADDR64 : COFF_REL_ADDR32);
        } else {
            reloc.SymbolTableIndex = label_start_idx + label_idx;
            reloc.Type = (g_bits == 64) ? COFF_REL_REL32 : COFF_REL_ADDR32;
        }
        fwrite(&reloc, sizeof(reloc), 1, fp);
    }
    
    /* RData section relocations */
    for (int i = 0; i < g_state.fixup_count; i++) {
        Fixup *f = &g_state.fixups[i];
        if (f->section != 2) continue; /* Only rdata section */
        
        int label_idx = find_label(f->label);
        int extern_idx = -1;
        for (int j = 0; j < g_state.extern_count; j++) {
            if (_stricmp(g_state.extern_symbols[j], f->label) == 0) {
                extern_idx = j;
                break;
            }
        }
        if (label_idx < 0 && extern_idx < 0) continue;
        
        COFF_RELOCATION reloc = {0};
        reloc.VirtualAddress = f->offset;
        
        if (extern_idx >= 0) {
            reloc.SymbolTableIndex = label_start_idx + g_state.label_count + extern_idx;
            reloc.Type = f->is_relative ? COFF_REL_REL32 : ((g_bits == 64) ? COFF_REL_ADDR64 : COFF_REL_ADDR32);
        } else {
            reloc.SymbolTableIndex = label_start_idx + label_idx;
            reloc.Type = (g_bits == 64) ? COFF_REL_REL32 : COFF_REL_ADDR32;
        }
        fwrite(&reloc, sizeof(reloc), 1, fp);
    }

    /* Write symbol table */
    /* File symbol */
    COFF_SYMBOL file_sym = {0};
    memcpy(file_sym.N.ShortName, ".file", 5);
    file_sym.Value = 0;
    file_sym.SectionNumber = -2; /* FILE section */
    file_sym.Type = 0;
    file_sym.StorageClass = COFF_SYMBOL_STATIC;
    file_sym.NumberOfAuxSymbols = 1;
    fwrite(&file_sym, sizeof(file_sym), 1, fp);
    
    /* File auxiliary record */
    uint8_t file_aux[18] = {0};
    memcpy(file_aux, "rawrxd.asm", 10);
    fwrite(file_aux, 18, 1, fp);
    
    /* Section symbols */
    sec_num = 1;
    if (g_state.text.size > 0) {
        COFF_SYMBOL sec_sym = {0};
        memcpy(sec_sym.N.ShortName, ".text", 5);
        sec_sym.Value = 0;
        sec_sym.SectionNumber = sec_num;
        sec_sym.Type = 0;
        sec_sym.StorageClass = COFF_SYMBOL_STATIC;
        sec_sym.NumberOfAuxSymbols = 1;
        fwrite(&sec_sym, sizeof(sec_sym), 1, fp);
        /* Auxiliary section record */
        uint8_t sec_aux[18] = {0};
        fwrite(sec_aux, 18, 1, fp);
        sec_num++;
    }
    
    if (g_state.data.size > 0) {
        COFF_SYMBOL sec_sym = {0};
        memcpy(sec_sym.N.ShortName, ".data", 5);
        sec_sym.Value = 0;
        sec_sym.SectionNumber = sec_num;
        sec_sym.Type = 0;
        sec_sym.StorageClass = COFF_SYMBOL_STATIC;
        sec_sym.NumberOfAuxSymbols = 1;
        fwrite(&sec_sym, sizeof(sec_sym), 1, fp);
        uint8_t sec_aux[18] = {0};
        fwrite(sec_aux, 18, 1, fp);
        sec_num++;
    }
    
    if (g_state.rdata.size > 0) {
        COFF_SYMBOL sec_sym = {0};
        memcpy(sec_sym.N.ShortName, ".rdata", 6);
        sec_sym.Value = 0;
        sec_sym.SectionNumber = sec_num;
        sec_sym.Type = 0;
        sec_sym.StorageClass = COFF_SYMBOL_STATIC;
        sec_sym.NumberOfAuxSymbols = 1;
        fwrite(&sec_sym, sizeof(sec_sym), 1, fp);
        uint8_t sec_aux[18] = {0};
        fwrite(sec_aux, 18, 1, fp);
        sec_num++;
    }
    
    if (g_state.bss.size > 0) {
        COFF_SYMBOL sec_sym = {0};
        memcpy(sec_sym.N.ShortName, ".bss", 4);
        sec_sym.Value = 0;
        sec_sym.SectionNumber = sec_num;
        sec_sym.Type = 0;
        sec_sym.StorageClass = COFF_SYMBOL_STATIC;
        sec_sym.NumberOfAuxSymbols = 1;
        fwrite(&sec_sym, sizeof(sec_sym), 1, fp);
        uint8_t sec_aux[18] = {0};
        fwrite(sec_aux, 18, 1, fp);
    }

    /* Count symbols that need string table and assign offsets (names > 8 chars) */
    int need_string_table = 0;
    uint32_t string_table_size = 4; /* Size field */
    
    /* Assign string table offsets to labels first */
    for (int i = 0; i < g_state.label_count; i++) {
        /* Skip EQU constants */
        if (g_state.labels[i].is_equ) continue;
        size_t name_len = strlen(g_state.labels[i].name);
        if (name_len > 8) {
            need_string_table = 1;
            g_state.labels[i].string_offset = string_table_size;
            string_table_size += name_len + 1;
        } else {
            g_state.labels[i].string_offset = 0;
        }
    }
    
    /* Count external symbols */
    for (int i = 0; i < g_state.extern_count; i++) {
        if (strlen(g_state.extern_symbols[i]) > 8) {
            need_string_table = 1;
            string_table_size += strlen(g_state.extern_symbols[i]) + 1;
        }
    }
    
    /* Write label symbols (skip EQU constants) */
    for (int i = 0; i < g_state.label_count; i++) {
        Label *l = &g_state.labels[i];
        
        /* Skip EQU constants - they're compile-time only */
        if (l->is_equ) continue;
        
        COFF_SYMBOL sym = {0};
        
        size_t name_len = strlen(l->name);
        if (name_len <= 8) {
            memcpy(sym.N.ShortName, l->name, name_len);
        } else {
            sym.N.Name.Zeroes = 0;
            sym.N.Name.Offset = l->string_offset;
        }
        
        sym.Value = l->offset;
        
        /* Determine section number */
        if (l->section == 0) sym.SectionNumber = 1;
        else if (l->section == 1) sym.SectionNumber = 2;
        else if (l->section == 2) sym.SectionNumber = 3;
        else if (l->section == 3) sym.SectionNumber = 4;
        else sym.SectionNumber = 0;
        
        sym.Type = 0; /* Not a function */
        sym.StorageClass = COFF_SYMBOL_EXTERNAL;
        sym.NumberOfAuxSymbols = 0;
        
        fwrite(&sym, sizeof(sym), 1, fp);
    }
    
    /* Write external symbols (from EXTERNDEF) */
    /* Continue string offsets from where labels left off */
    uint32_t current_string_offset = string_table_size;
    
    for (int i = 0; i < g_state.extern_count; i++) {
        COFF_SYMBOL sym = {0};
        
        size_t name_len = strlen(g_state.extern_symbols[i]);
        if (name_len <= 8) {
            memcpy(sym.N.ShortName, g_state.extern_symbols[i], name_len);
        } else {
            sym.N.Name.Zeroes = 0;
            sym.N.Name.Offset = current_string_offset;
            current_string_offset += name_len + 1;
        }
        
        sym.Value = 0;
        sym.SectionNumber = 0; /* External symbol - no section */
        sym.Type = 0;
        sym.StorageClass = COFF_SYMBOL_EXTERNAL;
        sym.NumberOfAuxSymbols = 0;
        
        fwrite(&sym, sizeof(sym), 1, fp);
    }

    /* Write string table */
    fwrite(&string_table_size, 4, 1, fp);
    
    /* Write long names to string table */
    FILE *debug_fp = fopen("d:\\temp\\assembler_debug.txt", "w");
    fprintf(debug_fp, "DEBUG: Writing string table, label_count=%d\n", g_state.label_count);
    for (int i = 0; i < g_state.label_count; i++) {
        /* Skip EQU constants */
        fprintf(debug_fp, "DEBUG: Label[%d]: name='%s' is_equ=%d\n", i, g_state.labels[i].name, g_state.labels[i].is_equ);
        if (g_state.labels[i].is_equ) {
            fprintf(debug_fp, "DEBUG: Skipping EQU label '%s'\n", g_state.labels[i].name);
            continue;
        }
        size_t name_len = strlen(g_state.labels[i].name);
        if (name_len > 8) {
            fprintf(debug_fp, "DEBUG: Writing label '%s' to string table\n", g_state.labels[i].name);
            fwrite(g_state.labels[i].name, name_len + 1, 1, fp);
        }
    }
    fclose(debug_fp);
    for (int i = 0; i < g_state.extern_count; i++) {
        size_t name_len = strlen(g_state.extern_symbols[i]);
        if (name_len > 8) {
            fwrite(g_state.extern_symbols[i], name_len + 1, 1, fp);
        }
    }

    fclose(fp);
}

static void write_pe_file(const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", filename);
        return;
    }

    /* Calculate sizes */
    uint32_t text_size = (g_state.text.size + 511) & ~511;
    uint32_t data_size = (g_state.data.size + 511) & ~511;
    uint32_t rdata_size = (g_state.rdata.size + 511) & ~511;

    /* Calculate header size */
    uint32_t num_sections = 0;
    if (text_size > 0) num_sections++;
    if (data_size > 0) num_sections++;
    if (rdata_size > 0) num_sections++;
    if (num_sections == 0) num_sections = 1;

    uint32_t header_size = sizeof(IMAGE_DOS_HEADER) + 64 + /* DOS stub */
                           4 + /* PE signature */
                           sizeof(IMAGE_FILE_HEADER) +
                           sizeof(IMAGE_OPTIONAL_HEADER64) +
                           num_sections * sizeof(IMAGE_SECTION_HEADER);
    header_size = (header_size + 511) & ~511;

    /* Section virtual addresses */
    uint32_t image_base = 0x140000000ULL;
    uint32_t section_alignment = 0x1000;
    uint32_t file_alignment = 512;

    uint32_t text_rva = section_alignment;
    uint32_t data_rva = (text_rva + text_size + section_alignment - 1) & ~(section_alignment - 1);
    uint32_t rdata_rva = (data_rva + data_size + section_alignment - 1) & ~(section_alignment - 1);

    uint32_t text_file_offset = header_size;
    uint32_t data_file_offset = text_file_offset + text_size;
    uint32_t rdata_file_offset = data_file_offset + data_size;

    /* Calculate entry point */
    uint32_t entry_rva = text_rva + g_state.entry_point;
    if (!g_state.has_entry && g_state.text.size > 0) {
        entry_rva = text_rva;
    }

    /* Write DOS header */
    IMAGE_DOS_HEADER dos_header = {0};
    dos_header.e_magic = 0x5A4D; /* "MZ" */
    dos_header.e_cblp = 144;
    dos_header.e_cp = 3;
    dos_header.e_cparhdr = 4;
    dos_header.e_maxalloc = 0xFFFF;
    dos_header.e_sp = 0xB8;
    dos_header.e_lfarlc = 64;
    dos_header.e_lfanew = sizeof(IMAGE_DOS_HEADER) + 64;
    fwrite(&dos_header, sizeof(dos_header), 1, fp);

    /* Write DOS stub */
    uint8_t dos_stub[64] = {
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
        'T', 'h', 'i', 's', ' ', 'p', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'c', 'a', 'n', 'n', 'o',
        't', ' ', 'b', 'e', ' ', 'r', 'u', 'n', ' ', 'i', 'n', ' ', 'D', 'O', 'S', ' ', 'm',
        'o', 'd', 'e', '.', '\r', '\r', '\n', '$', 0, 0, 0, 0, 0, 0, 0, 0
    };
    fwrite(dos_stub, 64, 1, fp);

    /* Write PE signature */
    uint32_t pe_sig = IMAGE_NT_SIGNATURE;
    fwrite(&pe_sig, 4, 1, fp);

    /* Write COFF header */
    IMAGE_FILE_HEADER coff_header = {0};
    coff_header.Machine = IMAGE_FILE_MACHINE_AMD64;
    coff_header.NumberOfSections = num_sections;
    coff_header.TimeDateStamp = (uint32_t)time(NULL);
    coff_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    coff_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    fwrite(&coff_header, sizeof(coff_header), 1, fp);

    /* Write optional header */
    IMAGE_OPTIONAL_HEADER64 opt_header = {0};
    opt_header.Magic = 0x20B; /* PE32+ (64-bit) */
    opt_header.MajorLinkerVersion = 1;
    opt_header.MinorLinkerVersion = 0;
    opt_header.SizeOfCode = text_size;
    opt_header.SizeOfInitializedData = data_size + rdata_size;
    opt_header.SizeOfUninitializedData = 0;
    opt_header.AddressOfEntryPoint = entry_rva;
    opt_header.BaseOfCode = text_rva;
    opt_header.ImageBase = image_base;
    opt_header.SectionAlignment = section_alignment;
    opt_header.FileAlignment = file_alignment;
    opt_header.MajorOperatingSystemVersion = 6;
    opt_header.MinorOperatingSystemVersion = 0;
    opt_header.MajorSubsystemVersion = 6;
    opt_header.MinorSubsystemVersion = 0;
    opt_header.SizeOfImage = (rdata_rva + rdata_size + section_alignment - 1) & ~(section_alignment - 1);
    opt_header.SizeOfHeaders = header_size;
    opt_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt_header.DllCharacteristics = 0x8160;
    opt_header.SizeOfStackReserve = 0x100000;
    opt_header.SizeOfStackCommit = 0x1000;
    opt_header.SizeOfHeapReserve = 0x100000;
    opt_header.SizeOfHeapCommit = 0x1000;
    opt_header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    fwrite(&opt_header, sizeof(opt_header), 1, fp);

    /* Write section headers */
    int section_idx = 0;

    if (text_size > 0) {
        IMAGE_SECTION_HEADER text_header = {0};
        memcpy(text_header.Name, ".text", 5);
        text_header.VirtualSize = (uint32_t)g_state.text.size;
        text_header.VirtualAddress = text_rva;
        text_header.SizeOfRawData = text_size;
        text_header.PointerToRawData = text_file_offset;
        text_header.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        fwrite(&text_header, sizeof(text_header), 1, fp);
        section_idx++;
    }

    if (data_size > 0) {
        IMAGE_SECTION_HEADER data_header = {0};
        memcpy(data_header.Name, ".data", 5);
        data_header.VirtualSize = (uint32_t)g_state.data.size;
        data_header.VirtualAddress = data_rva;
        data_header.SizeOfRawData = data_size;
        data_header.PointerToRawData = data_file_offset;
        data_header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        fwrite(&data_header, sizeof(data_header), 1, fp);
        section_idx++;
    }

    if (rdata_size > 0) {
        IMAGE_SECTION_HEADER rdata_header = {0};
        memcpy(rdata_header.Name, ".rdata", 6);
        rdata_header.VirtualSize = (uint32_t)g_state.rdata.size;
        rdata_header.VirtualAddress = rdata_rva;
        rdata_header.SizeOfRawData = rdata_size;
        rdata_header.PointerToRawData = rdata_file_offset;
        rdata_header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        fwrite(&rdata_header, sizeof(rdata_header), 1, fp);
        section_idx++;
    }

    /* Pad to header_size */
    long current_pos = ftell(fp);
    while (current_pos < (long)header_size) {
        fputc(0, fp);
        current_pos++;
    }

    /* Write section data */
    if (text_size > 0) {
        fwrite(g_state.text.data, g_state.text.size, 1, fp);
        for (uint32_t i = g_state.text.size; i < text_size; i++) {
            fputc(0, fp);
        }
    }

    if (data_size > 0) {
        fwrite(g_state.data.data, g_state.data.size, 1, fp);
        for (uint32_t i = g_state.data.size; i < data_size; i++) {
            fputc(0, fp);
        }
    }

    if (rdata_size > 0) {
        fwrite(g_state.rdata.data, g_state.rdata.size, 1, fp);
        for (uint32_t i = g_state.rdata.size; i < rdata_size; i++) {
            fputc(0, fp);
        }
    }

    fclose(fp);
}

/* ============================================================================
 * COFF OBJECT FILE OUTPUT (uses structures defined above)
 * ============================================================================ */

static void write_coff_file(const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", filename);
        return;
    }

    /* Count sections */
    int num_sections = 0;
    int text_section = -1, data_section = -1, rdata_section = -1, bss_section = -1;

    if (g_state.text.size > 0) {
        text_section = num_sections++;
    }
    if (g_state.data.size > 0) {
        data_section = num_sections++;
    }
    if (g_state.rdata.size > 0) {
        rdata_section = num_sections++;
    }
    if (g_state.bss.size > 0) {
        bss_section = num_sections++;
    }

    if (num_sections == 0) {
        /* Need at least one section */
        text_section = num_sections++;
    }

    /* Calculate symbol count */
    int num_symbols = 0;
    int entry_symbol = -1;

    /* Section symbols */
    num_symbols += num_sections;

    /* Label symbols */
    for (int i = 0; i < g_state.label_count; i++) {
        /* Skip EQU constants - they're compile-time only */
        if (g_state.labels[i].is_equ) continue;
        num_symbols++;
    }

    /* Calculate offsets */
    uint32_t header_size = sizeof(COFF_FILE_HEADER);
    uint32_t section_headers_size = num_sections * sizeof(COFF_SECTION_HEADER);
    uint32_t string_table_offset = 4; /* String table starts with its size */

    /* Calculate section data offsets */
    uint32_t current_offset = header_size + section_headers_size;

    uint32_t text_data_offset = current_offset;
    uint32_t text_size = (g_state.text.size > 0) ? g_state.text.size : 1;
    if (text_section >= 0) current_offset += text_size;

    uint32_t data_data_offset = current_offset;
    uint32_t data_size = (g_state.data.size > 0) ? g_state.data.size : 1;
    if (data_section >= 0) current_offset += data_size;

    uint32_t rdata_data_offset = current_offset;
    uint32_t rdata_size = (g_state.rdata.size > 0) ? g_state.rdata.size : 1;
    if (rdata_section >= 0) current_offset += rdata_size;

    uint32_t bss_size = (g_state.bss.size > 0) ? g_state.bss.size : 0;

    /* Relocation offsets */
    uint32_t reloc_offset = current_offset;
    uint32_t num_relocs = 0;

    /* Count relocations */
    for (int i = 0; i < g_state.fixup_count; i++) {
        if (!g_state.fixups[i].is_relative) {
            num_relocs++;
        }
    }

    uint32_t reloc_table_size = num_relocs * sizeof(COFF_RELOCATION);
    current_offset += reloc_table_size;

    /* Symbol table offset */
    uint32_t symbol_table_offset = current_offset;
    uint32_t symbol_table_size = num_symbols * sizeof(COFF_SYMBOL);
    current_offset += symbol_table_size;

    /* String table */
    uint32_t string_table_size = 4; /* Start with size field */
    uint32_t current_str_offset = 4; /* Start after size field */

    /* Calculate string table size and assign offsets */
    for (int i = 0; i < g_state.label_count; i++) {
        /* Skip EQU constants */
        if (g_state.labels[i].is_equ) continue;
        size_t len = strlen(g_state.labels[i].name);
        if (len > 8) {
            g_state.labels[i].string_offset = current_str_offset;
            current_str_offset += (uint32_t)(len + 1);
            string_table_size += (uint32_t)(len + 1);
        } else {
            g_state.labels[i].string_offset = 0;
        }
    }

    /* Write COFF header */
    COFF_FILE_HEADER coff_header = {0};
    coff_header.Machine = (g_arch == ARCH_X64) ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    coff_header.NumberOfSections = (uint16_t)num_sections;
    coff_header.TimeDateStamp = (uint32_t)time(NULL);
    coff_header.PointerToSymbolTable = symbol_table_offset;
    coff_header.NumberOfSymbols = (uint32_t)num_symbols;
    coff_header.SizeOfOptionalHeader = 0;
    coff_header.Characteristics = 0;

    fwrite(&coff_header, sizeof(coff_header), 1, fp);

    /* Write section headers */
    uint32_t section_index = 0;

    /* .text section */
    if (text_section >= 0) {
        COFF_SECTION_HEADER sh = {0};
        memcpy(sh.Name, ".text\0\0\0", 8);
        sh.VirtualSize = text_size;
        sh.VirtualAddress = 0;
        sh.SizeOfRawData = text_size;
        sh.PointerToRawData = text_data_offset;
        sh.PointerToRelocations = (num_relocs > 0) ? reloc_offset : 0;
        sh.PointerToLinenumbers = 0;
        sh.NumberOfRelocations = 0;
        sh.NumberOfLinenumbers = 0;
        sh.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

        /* Count relocations for this section */
        for (int i = 0; i < g_state.fixup_count; i++) {
            if (g_state.fixups[i].section == 0 && !g_state.fixups[i].is_relative) {
                sh.NumberOfRelocations++;
            }
        }

        fwrite(&sh, sizeof(sh), 1, fp);
        section_index++;
    }

    /* .data section */
    if (data_section >= 0) {
        COFF_SECTION_HEADER sh = {0};
        memcpy(sh.Name, ".data\0\0\0", 8);
        sh.VirtualSize = data_size;
        sh.VirtualAddress = 0;
        sh.SizeOfRawData = data_size;
        sh.PointerToRawData = data_data_offset;
        sh.PointerToRelocations = 0;
        sh.PointerToLinenumbers = 0;
        sh.NumberOfRelocations = 0;
        sh.NumberOfLinenumbers = 0;
        sh.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        fwrite(&sh, sizeof(sh), 1, fp);
        section_index++;
    }

    /* .rdata section */
    if (rdata_section >= 0) {
        COFF_SECTION_HEADER sh = {0};
        memcpy(sh.Name, ".rdata\0\0", 8);
        sh.VirtualSize = rdata_size;
        sh.VirtualAddress = 0;
        sh.SizeOfRawData = rdata_size;
        sh.PointerToRawData = rdata_data_offset;
        sh.PointerToRelocations = 0;
        sh.PointerToLinenumbers = 0;
        sh.NumberOfRelocations = 0;
        sh.NumberOfLinenumbers = 0;
        sh.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        fwrite(&sh, sizeof(sh), 1, fp);
        section_index++;
    }

    /* .bss section */
    if (bss_section >= 0) {
        COFF_SECTION_HEADER sh = {0};
        memcpy(sh.Name, ".bss\0\0\0\0", 8);
        sh.VirtualSize = bss_size;
        sh.VirtualAddress = 0;
        sh.SizeOfRawData = bss_size;
        sh.PointerToRawData = 0;
        sh.PointerToRelocations = 0;
        sh.PointerToLinenumbers = 0;
        sh.NumberOfRelocations = 0;
        sh.NumberOfLinenumbers = 0;
        sh.Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        fwrite(&sh, sizeof(sh), 1, fp);
        section_index++;
    }

    /* Write section data */
    if (text_section >= 0) {
        if (g_state.text.size > 0) {
            fwrite(g_state.text.data, g_state.text.size, 1, fp);
            /* Pad to alignment */
            uint32_t pad = text_size - g_state.text.size;
            for (uint32_t i = 0; i < pad; i++) {
                fputc(0, fp);
            }
        } else {
            fputc(0x90, fp); /* NOP */
        }
    }

    if (data_section >= 0) {
        if (g_state.data.size > 0) {
            fwrite(g_state.data.data, g_state.data.size, 1, fp);
            uint32_t pad = data_size - g_state.data.size;
            for (uint32_t i = 0; i < pad; i++) {
                fputc(0, fp);
            }
        } else {
            fputc(0, fp);
        }
    }

    if (rdata_section >= 0) {
        if (g_state.rdata.size > 0) {
            fwrite(g_state.rdata.data, g_state.rdata.size, 1, fp);
            uint32_t pad = rdata_size - g_state.rdata.size;
            for (uint32_t i = 0; i < pad; i++) {
                fputc(0, fp);
            }
        } else {
            fputc(0, fp);
        }
    }

    /* Write relocations */
    uint32_t reloc_index = 0;
    uint32_t string_offset = 4;

    for (int i = 0; i < g_state.fixup_count; i++) {
        if (!g_state.fixups[i].is_relative) {
            COFF_RELOCATION reloc = {0};
            reloc.VirtualAddress = g_state.fixups[i].offset;
            reloc.SymbolTableIndex = num_sections; /* Will be updated */
            reloc.Type = IMAGE_REL_AMD64_ADDR64;

            /* Find symbol index */
            for (int j = 0; j < g_state.label_count; j++) {
                if (strcmp(g_state.fixups[i].label, g_state.labels[j].name) == 0) {
                    reloc.SymbolTableIndex = num_sections + j;
                    break;
                }
            }

            fwrite(&reloc, sizeof(reloc), 1, fp);
            reloc_index++;
        }
    }

    /* Write symbol table */
    /* Section symbols */
    section_index = 0;

    if (text_section >= 0) {
        COFF_SYMBOL sym = {0};
        memcpy(sym.N.ShortName, ".text\0\0\0", 8);
        sym.Value = 0;
        sym.SectionNumber = (int16_t)(section_index + 1);
        sym.Type = 0;
        sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
        sym.NumberOfAuxSymbols = 0;
        fwrite(&sym, sizeof(sym), 1, fp);
        section_index++;
    }

    if (data_section >= 0) {
        COFF_SYMBOL sym = {0};
        memcpy(sym.N.ShortName, ".data\0\0\0", 8);
        sym.Value = 0;
        sym.SectionNumber = (int16_t)(section_index + 1);
        sym.Type = 0;
        sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
        sym.NumberOfAuxSymbols = 0;
        fwrite(&sym, sizeof(sym), 1, fp);
        section_index++;
    }

    if (rdata_section >= 0) {
        COFF_SYMBOL sym = {0};
        memcpy(sym.N.ShortName, ".rdata\0\0", 8);
        sym.Value = 0;
        sym.SectionNumber = (int16_t)(section_index + 1);
        sym.Type = 0;
        sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
        sym.NumberOfAuxSymbols = 0;
        fwrite(&sym, sizeof(sym), 1, fp);
        section_index++;
    }

    if (bss_section >= 0) {
        COFF_SYMBOL sym = {0};
        memcpy(sym.N.ShortName, ".bss\0\0\0\0", 8);
        sym.Value = 0;
        sym.SectionNumber = (int16_t)(section_index + 1);
        sym.Type = 0;
        sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
        sym.NumberOfAuxSymbols = 0;
        fwrite(&sym, sizeof(sym), 1, fp);
        section_index++;
    }

    /* Label symbols */
    for (int i = 0; i < g_state.label_count; i++) {
        /* Skip EQU constants - they're compile-time only */
        if (g_state.labels[i].is_equ) continue;
        
        COFF_SYMBOL sym = {0};
        size_t name_len = strlen(g_state.labels[i].name);

        if (name_len <= 8) {
            memcpy(sym.N.ShortName, g_state.labels[i].name, name_len);
        } else {
            sym.N.Name.Zeroes = 0;
            sym.N.Name.Offset = g_state.labels[i].string_offset;
        }

        sym.Value = g_state.labels[i].offset;

        /* Determine section */
        int16_t sec_num = 1;
        switch (g_state.labels[i].section) {
            case 0: sec_num = (text_section >= 0) ? (int16_t)(text_section + 1) : 1; break;
            case 1: sec_num = (data_section >= 0) ? (int16_t)(data_section + 1) : 1; break;
            case 2: sec_num = (rdata_section >= 0) ? (int16_t)(rdata_section + 1) : 1; break;
            case 3: sec_num = (bss_section >= 0) ? (int16_t)(bss_section + 1) : 1; break;
        }

        sym.SectionNumber = sec_num;
        sym.Type = IMAGE_SYM_TYPE_NULL;
        sym.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
        sym.NumberOfAuxSymbols = 0;

        fwrite(&sym, sizeof(sym), 1, fp);
    }

    /* Write string table */
    fwrite(&string_table_size, 4, 1, fp);

    for (int i = 0; i < g_state.label_count; i++) {
        /* Skip EQU constants */
        if (g_state.labels[i].is_equ) continue;
        size_t len = strlen(g_state.labels[i].name);
        if (len > 8) {
            fwrite(g_state.labels[i].name, len + 1, 1, fp);
        }
    }

    fclose(fp);
}

/* ============================================================================
 * MAIN
 * ============================================================================ */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input.asm> <output.exe>\n", argv[0]);
        fprintf(stderr, "       %s /c <input.asm> <output.obj>\n", argv[0]);
        fprintf(stderr, "\nNative MASM-compatible assembler for x86/x64/x32\n");
        fprintf(stderr, "No external dependencies - completely self-contained\n");
        return 1;
    }

    const char *input_file = argv[1];
    const char *output_file = argv[2];
    int obj_mode = 0;

    if (strcmp(input_file, "/c") == 0 || strcmp(input_file, "-c") == 0) {
        obj_mode = 1;
        if (argc < 4) {
            fprintf(stderr, "Error: Object mode requires input and output files\n");
            return 1;
        }
        input_file = argv[2];
        output_file = argv[3];
    }

    /* Initialize state */
    memset(&g_state, 0, sizeof(g_state));
    init_section(&g_state.text);
    init_section(&g_state.data);
    init_section(&g_state.rdata);
    init_section(&g_state.bss);

    /* Open input file */
    FILE *fp = fopen(input_file, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 1;
    }

    printf("Pass 1: Parsing and encoding...\n");

    /* Parse file */
    char line[MAX_LINE_LENGTH];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        /* Skip empty lines and comments */
        char *p = skip_whitespace(line);
        if (!*p || *p == ';') continue;

        /* Parse instruction or directive */
        parse_instruction(line);
    }

    fclose(fp);

    printf("Pass 2: Resolving fixups...\n");

    /* Resolve fixups */
    resolve_fixups();

    printf("  Labels defined: %d\n", g_state.label_count);
    printf("  Fixups resolved: %d\n", g_state.fixup_count);
    printf("  Text section: %zu bytes\n", g_state.text.size);
    printf("  Data section: %zu bytes\n", g_state.data.size);
    printf("  RData section: %zu bytes\n", g_state.rdata.size);

    /* Write output */
    if (obj_mode) {
        write_coff_object(output_file);  /* Produce COFF object file for linking */
    } else {
        write_coff_file(output_file);  /* Produce PE executable directly */
    }

    printf("\nSuccess! Assembly complete.\n");
    printf("Output: %s\n", output_file);

    /* Cleanup */
    free(g_state.text.data);
    free(g_state.data.data);
    free(g_state.rdata.data);
    free(g_state.bss.data);

    return 0;
}
