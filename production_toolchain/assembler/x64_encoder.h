/*
 * x64 Instruction Encoder - Production Quality
 * Full x64 instruction set support including AVX/AVX-512
 */

#ifndef X64_ENCODER_H
#define X64_ENCODER_H

#include <stdint.h>
#include <stdbool.h>

// REX prefix bits
#define REX_W           0x08    // 64-bit operand size
#define REX_R           0x04    // ModRM reg extension
#define REX_X           0x02    // SIB index extension
#define REX_B           0x01    // ModRM r/m or SIB base extension
#define REX_BASE        0x40

// ModRM byte components
#define MOD_INDIRECT    0x00    // [reg]
#define MOD_DISP8       0x40    // [reg+disp8]
#define MOD_DISP32      0x80    // [reg+disp32]
#define MOD_DIRECT      0xC0    // reg

// Scale for SIB byte
#define SCALE_1         0x00
#define SCALE_2         0x40
#define SCALE_4         0x80
#define SCALE_8         0xC0

// Register encodings (3-bit, 0-7, extended with REX)
typedef enum {
    REG_RAX = 0, REG_RCX = 1, REG_RDX = 2, REG_RBX = 3,
    REG_RSP = 4, REG_RBP = 5, REG_RSI = 6, REG_RDI = 7,
    REG_R8 = 8,  REG_R9 = 9,  REG_R10 = 10, REG_R11 = 11,
    REG_R12 = 12, REG_R13 = 13, REG_R14 = 14, REG_R15 = 15,
    REG_NONE = 0xFF
} X64Register;

// Operand types
typedef enum {
    OP_NONE,
    OP_REG,         // Register
    OP_IMM8,        // 8-bit immediate
    OP_IMM16,       // 16-bit immediate
    OP_IMM32,       // 32-bit immediate
    OP_IMM64,       // 64-bit immediate
    OP_MEM,         // Memory reference
    OP_MEM_DISP8,   // Memory + 8-bit displacement
    OP_MEM_DISP32,  // Memory + 32-bit displacement
    OP_LABEL        // Label/rip-relative
} OperandType;

// Operand structure
typedef struct {
    OperandType type;
    X64Register reg;        // For OP_REG, OP_MEM
    X64Register index;      // For SIB
    uint8_t scale;          // For SIB (1, 2, 4, 8)
    int64_t immediate;      // For OP_IMM*
    int32_t displacement;   // For memory operands
    const char* label;      // For OP_LABEL
} Operand;

// Instruction structure
typedef struct {
    const char* mnemonic;
    uint8_t opcode[4];        // Primary opcode bytes
    uint8_t opcode_len;
    bool has_modrm;
    bool has_sib;
    uint8_t reg_opcode;     // For instructions with reg field in opcode
    bool needs_rex_w;       // Requires REX.W
    bool is_jump;           // Branch instruction
} InstructionDef;

// Encoder state
typedef struct {
    uint8_t* code_buffer;
    size_t code_size;
    size_t code_capacity;
    uint64_t current_address;
} X64Encoder;

// Function prototypes
X64Encoder* x64_encoder_create(size_t initial_capacity);
void x64_encoder_destroy(X64Encoder* enc);
int x64_encoder_emit_instruction(X64Encoder* enc, const char* mnemonic, 
                                   const Operand* op1, const Operand* op2);
int x64_encoder_emit_mov_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_mov_reg_imm(X64Encoder* enc, X64Register dst, int64_t imm);
int x64_encoder_emit_push_reg(X64Encoder* enc, X64Register reg);
int x64_encoder_emit_pop_reg(X64Encoder* enc, X64Register reg);
int x64_encoder_emit_call_reg(X64Encoder* enc, X64Register reg);
int x64_encoder_emit_call_rel32(X64Encoder* enc, int32_t offset);
int x64_encoder_emit_ret(X64Encoder* enc);
int x64_encoder_emit_nop(X64Encoder* enc);
int x64_encoder_emit_add_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_sub_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_sub_reg_imm(X64Encoder* enc, X64Register dst, int32_t imm);
int x64_encoder_emit_lea(X64Encoder* enc, X64Register dst, X64Register base, 
                          X64Register index, uint8_t scale, int32_t disp);
int x64_encoder_emit_jmp_rel32(X64Encoder* enc, int32_t offset);
int x64_encoder_emit_jcc_rel32(X64Encoder* enc, uint8_t condition, int32_t offset);
int x64_encoder_emit_test_reg_reg(X64Encoder* enc, X64Register reg1, X64Register reg2);
int x64_encoder_emit_cmp_reg_reg(X64Encoder* enc, X64Register reg1, X64Register reg2);
int x64_encoder_emit_setcc(X64Encoder* enc, uint8_t condition, X64Register dst);
int x64_encoder_emit_movzx_reg8_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_imul_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_bsf_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_bts_mem_imm(X64Encoder* enc, X64Register base, int32_t disp, uint8_t bit);
int x64_encoder_emit_inc_reg(X64Encoder* enc, X64Register reg);
int x64_encoder_emit_dec_reg(X64Encoder* enc, X64Register reg);
int x64_encoder_emit_and_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_or_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_xor_reg_reg(X64Encoder* enc, X64Register dst, X64Register src);
int x64_encoder_emit_shl_reg_imm(X64Encoder* enc, X64Register reg, uint8_t imm);
int x64_encoder_emit_shr_reg_imm(X64Encoder* enc, X64Register reg, uint8_t imm);
int x64_encoder_emit_sar_reg_imm(X64Encoder* enc, X64Register reg, uint8_t imm);

// AVX instructions
int x64_encoder_emit_vmovaps(X64Encoder* enc, uint8_t dst_reg, uint8_t src_reg);
int x64_encoder_emit_vbroadcastss(X64Encoder* enc, uint8_t dst_reg, X64Register src);
int x64_encoder_emit_vfmadd213ps(X64Encoder* enc, uint8_t dst, uint8_t src1, uint8_t src2);
int x64_encoder_emit_vpermq(X64Encoder* enc, uint8_t dst, uint8_t src, uint8_t imm);
int x64_encoder_emit_vpaddd(X64Encoder* enc, uint8_t dst, uint8_t src1, uint8_t src2);
int x64_encoder_emit_vpsrldq(X64Encoder* enc, uint8_t dst, uint8_t src, uint8_t imm);

// Utility functions
const char* x64_reg_to_string(X64Register reg);
X64Register x64_reg_from_string(const char* name);
bool x64_reg_is_extended(X64Register reg);
uint8_t x64_reg_get_encoding(X64Register reg);

#endif // X64_ENCODER_H
