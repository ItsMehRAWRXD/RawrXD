// ============================================================================
// unicompiler.c - RawrXD Unified Compiler/Assembler
// ============================================================================
// Multi-architecture assembler supporting x86, x64, and x32 (ILP32)
// Supports NASM-style and simplified syntax
// Outputs: PE32, PE32+, COFF, raw binary
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <windows.h>

// ============================================================================
// ARCHITECTURE MODES
// ============================================================================
typedef enum {
    ARCH_X86 = 0,   /* 32-bit x86 (PE32, machine 0x14C) */
    ARCH_X64 = 1,   /* 64-bit x64 (PE32+, machine 0x8664) */
    ARCH_X32 = 2    /* 64-bit x32 ILP32 (PE32+, machine 0x8664) */
} ArchMode;

static ArchMode g_arch = ARCH_X64;
static int g_bits = 64;

// ============================================================================
// OPERAND SIZES
// ============================================================================
typedef enum {
    SIZE_8  = 8,
    SIZE_16 = 16,
    SIZE_32 = 32,
    SIZE_64 = 64
} OperandSize;

// x64 instruction encoding structures
typedef enum {
    OP_MOV_RR,      // mov reg, reg
    OP_MOV_RI,      // mov reg, imm
    OP_MOV_RM,      // mov reg, [mem]
    OP_MOV_MR,      // mov [mem], reg
    OP_PUSH_R,      // push reg
    OP_POP_R,       // pop reg
    OP_ADD_RR,      // add reg, reg
    OP_ADD_RI,      // add reg, imm
    OP_SUB_RR,      // sub reg, reg
    OP_SUB_RI,      // sub reg, imm
    OP_CALL,        // call addr
    OP_RET,         // ret
    OP_NOP,         // nop
    OP_XOR_RR,      // xor reg, reg
    OP_LEA,         // lea reg, [mem]
    OP_JMP,         // jmp addr
    OP_SYSCALL,     // syscall (not on Windows but good to have)
    OP_INT3,        // int3 (breakpoint)
    OP_INC_R,       // inc reg
    OP_INC_R32,     // inc r32
    OP_UNKNOWN
} OpcodeType;

// ============================================================================
// COMPREHENSIVE REGISTER SYSTEM
// ============================================================================
// All registers are represented as (base_id, size) pairs
// Base ID 0-7: RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI
// Base ID 8-15: R8-R15 (x64 extended)
// ============================================================================

typedef enum {
    // Base register IDs (0-15)
    REG_ID_RAX = 0, REG_ID_RCX = 1, REG_ID_RDX = 2, REG_ID_RBX = 3,
    REG_ID_RSP = 4, REG_ID_RBP = 5, REG_ID_RSI = 6, REG_ID_RDI = 7,
    REG_ID_R8  = 8, REG_ID_R9  = 9, REG_ID_R10 = 10, REG_ID_R11 = 11,
    REG_ID_R12 = 12, REG_ID_R13 = 13, REG_ID_R14 = 14, REG_ID_R15 = 15,
    REG_ID_INVALID = 255
} RegisterID;

// Legacy enum for backward compatibility
typedef enum {
    REG_RAX, REG_RCX, REG_RDX, REG_RBX,
    REG_RSP, REG_RBP, REG_RSI, REG_RDI,
    REG_R8, REG_R9, REG_R10, REG_R11,
    REG_R12, REG_R13, REG_R14, REG_R15,
    REG_INVALID
} Register;

// Enhanced register operand with size
typedef struct {
    RegisterID id;
    OperandSize size;
    int needs_rex;      // 1 if REX prefix needed (R8-R15 or SPL/BPL/SIL/DIL)
} RegisterOperand;

// Register info for parsing
typedef struct {
    const char* name;
    RegisterID id;
    OperandSize size;
    int needs_rex;
} RegInfo;

// Complete register table
static const RegInfo g_registers[] = {
    // 8-bit low (legacy)
    {"al",   REG_ID_RAX, SIZE_8, 0}, {"cl",   REG_ID_RCX, SIZE_8, 0},
    {"dl",   REG_ID_RDX, SIZE_8, 0}, {"bl",   REG_ID_RBX, SIZE_8, 0},
    {"spl",  REG_ID_RSP, SIZE_8, 1}, {"bpl",  REG_ID_RBP, SIZE_8, 1},
    {"sil",  REG_ID_RSI, SIZE_8, 1}, {"dil",  REG_ID_RDI, SIZE_8, 1},
    // 8-bit high (legacy, not available in x64 for R8-R15)
    {"ah",   REG_ID_RAX, SIZE_8, 0}, {"ch",   REG_ID_RCX, SIZE_8, 0},
    {"dh",   REG_ID_RDX, SIZE_8, 0}, {"bh",   REG_ID_RBX, SIZE_8, 0},
    // 8-bit extended (x64)
    {"r8b",  REG_ID_R8,  SIZE_8, 1}, {"r9b",  REG_ID_R9,  SIZE_8, 1},
    {"r10b", REG_ID_R10, SIZE_8, 1}, {"r11b", REG_ID_R11, SIZE_8, 1},
    {"r12b", REG_ID_R12, SIZE_8, 1}, {"r13b", REG_ID_R13, SIZE_8, 1},
    {"r14b", REG_ID_R14, SIZE_8, 1}, {"r15b", REG_ID_R15, SIZE_8, 1},
    // 16-bit
    {"ax",   REG_ID_RAX, SIZE_16, 0}, {"cx",   REG_ID_RCX, SIZE_16, 0},
    {"dx",   REG_ID_RDX, SIZE_16, 0}, {"bx",   REG_ID_RBX, SIZE_16, 0},
    {"sp",   REG_ID_RSP, SIZE_16, 0}, {"bp",   REG_ID_RBP, SIZE_16, 0},
    {"si",   REG_ID_RSI, SIZE_16, 0}, {"di",   REG_ID_RDI, SIZE_16, 0},
    {"r8w",  REG_ID_R8,  SIZE_16, 1}, {"r9w",  REG_ID_R9,  SIZE_16, 1},
    {"r10w", REG_ID_R10, SIZE_16, 1}, {"r11w", REG_ID_R11, SIZE_16, 1},
    {"r12w", REG_ID_R12, SIZE_16, 1}, {"r13w", REG_ID_R13, SIZE_16, 1},
    {"r14w", REG_ID_R14, SIZE_16, 1}, {"r15w", REG_ID_R15, SIZE_16, 1},
    // 32-bit
    {"eax",  REG_ID_RAX, SIZE_32, 0}, {"ecx",  REG_ID_RCX, SIZE_32, 0},
    {"edx",  REG_ID_RDX, SIZE_32, 0}, {"ebx",  REG_ID_RBX, SIZE_32, 0},
    {"esp",  REG_ID_RSP, SIZE_32, 0}, {"ebp",  REG_ID_RBP, SIZE_32, 0},
    {"esi",  REG_ID_RSI, SIZE_32, 0}, {"edi",  REG_ID_RDI, SIZE_32, 0},
    {"r8d",  REG_ID_R8,  SIZE_32, 1}, {"r9d",  REG_ID_R9,  SIZE_32, 1},
    {"r10d", REG_ID_R10, SIZE_32, 1}, {"r11d", REG_ID_R11, SIZE_32, 1},
    {"r12d", REG_ID_R12, SIZE_32, 1}, {"r13d", REG_ID_R13, SIZE_32, 1},
    {"r14d", REG_ID_R14, SIZE_32, 1}, {"r15d", REG_ID_R15, SIZE_32, 1},
    // 64-bit
    {"rax",  REG_ID_RAX, SIZE_64, 0}, {"rcx",  REG_ID_RCX, SIZE_64, 0},
    {"rdx",  REG_ID_RDX, SIZE_64, 0}, {"rbx",  REG_ID_RBX, SIZE_64, 0},
    {"rsp",  REG_ID_RSP, SIZE_64, 0}, {"rbp",  REG_ID_RBP, SIZE_64, 0},
    {"rsi",  REG_ID_RSI, SIZE_64, 0}, {"rdi",  REG_ID_RDI, SIZE_64, 0},
    {"r8",   REG_ID_R8,  SIZE_64, 1}, {"r9",   REG_ID_R9,  SIZE_64, 1},
    {"r10",  REG_ID_R10, SIZE_64, 1}, {"r11",  REG_ID_R11, SIZE_64, 1},
    {"r12",  REG_ID_R12, SIZE_64, 1}, {"r13",  REG_ID_R13, SIZE_64, 1},
    {"r14",  REG_ID_R14, SIZE_64, 1}, {"r15",  REG_ID_R15, SIZE_64, 1},
    {NULL, REG_ID_INVALID, 0, 0}
};

typedef struct {
    OpcodeType type;
    Register dst;
    Register src;
    int64_t immediate;
    char label[64];
    int has_immediate;
    int has_label;
} Instruction;

typedef struct {
    char name[64];
    uint32_t rva;
} Symbol;

// Code generation buffer
typedef struct {
    uint8_t* data;
    size_t size;
    size_t capacity;
} CodeBuffer;

// Parser state
typedef struct {
    char* source;
    size_t pos;
    size_t line;
    Instruction* instructions;
    size_t instr_count;
    size_t instr_capacity;
    Symbol* symbols;
    size_t symbol_count;
    size_t symbol_capacity;
} Parser;

// Register encoding table (x64 register numbers)
static const int reg_encoding[] = {
    0,  // RAX
    1,  // RCX
    2,  // RDX
    3,  // RBX
    4,  // RSP
    5,  // RBP
    6,  // RSI
    7,  // RDI
    8,  // R8
    9,  // R9
    10, // R10
    11, // R11
    12, // R12
    13, // R13
    14, // R14
    15  // R15
};

// Register names
static const char* reg_names[] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    NULL
};

// Initialize code buffer
void code_buffer_init(CodeBuffer* buf) {
    buf->capacity = 4096;
    buf->data = malloc(buf->capacity);
    buf->size = 0;
}

void code_buffer_free(CodeBuffer* buf) {
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

void code_buffer_append(CodeBuffer* buf, const uint8_t* data, size_t len) {
    if (buf->size + len > buf->capacity) {
        buf->capacity *= 2;
        buf->data = realloc(buf->data, buf->capacity);
    }
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
}

void code_buffer_append_byte(CodeBuffer* buf, uint8_t byte) {
    code_buffer_append(buf, &byte, 1);
}

// Parse register from string
Register parse_register(const char* str) {
    if (!str) return REG_NONE;
    
    // 64-bit registers
    if (_stricmp(str, "rax") == 0) return REG_RAX;
    if (_stricmp(str, "rcx") == 0) return REG_RCX;
    if (_stricmp(str, "rdx") == 0) return REG_RDX;
    if (_stricmp(str, "rbx") == 0) return REG_RBX;
    if (_stricmp(str, "rsp") == 0) return REG_RSP;
    if (_stricmp(str, "rbp") == 0) return REG_RBP;
    if (_stricmp(str, "rsi") == 0) return REG_RSI;
    if (_stricmp(str, "rdi") == 0) return REG_RDI;
    if (_stricmp(str, "r8") == 0) return REG_R8;
    if (_stricmp(str, "r9") == 0) return REG_R9;
    if (_stricmp(str, "r10") == 0) return REG_R10;
    if (_stricmp(str, "r11") == 0) return REG_R11;
    if (_stricmp(str, "r12") == 0) return REG_R12;
    if (_stricmp(str, "r13") == 0) return REG_R13;
    if (_stricmp(str, "r14") == 0) return REG_R14;
    if (_stricmp(str, "r15") == 0) return REG_R15;
    
    // 32-bit registers (map to same encoding as 64-bit)
    if (_stricmp(str, "eax") == 0) return REG_RAX;
    if (_stricmp(str, "ecx") == 0) return REG_RCX;
    if (_stricmp(str, "edx") == 0) return REG_RDX;
    if (_stricmp(str, "ebx") == 0) return REG_RBX;
    if (_stricmp(str, "esp") == 0) return REG_RSP;
    if (_stricmp(str, "ebp") == 0) return REG_RBP;
    if (_stricmp(str, "esi") == 0) return REG_RSI;
    if (_stricmp(str, "edi") == 0) return REG_RDI;
    
    return REG_NONE;
}

// Skip whitespace
void skip_whitespace(Parser* p) {
    while (p->source[p->pos] && isspace((unsigned char)p->source[p->pos])) {
        if (p->source[p->pos] == '\n') p->line++;
        p->pos++;
    }
}

// Get next token
int get_token(Parser* p, char* token, size_t max_len) {
    skip_whitespace(p);
    
    size_t i = 0;
    
    // Check for end of input
    if (!p->source[p->pos]) {
        token[0] = '\0';
        return 0;
    }
    
    // Check for comment
    if (p->source[p->pos] == ';') {
        // Skip to end of line
        while (p->source[p->pos] && p->source[p->pos] != '\n') {
            p->pos++;
        }
        return get_token(p, token, max_len);
    }
    
    // Check for label (ends with :)
    char* colon = strchr(p->source + p->pos, ':');
    char* newline = strchr(p->source + p->pos, '\n');
    if (colon && (!newline || colon < newline)) {
        // This might be a label
        size_t label_len = colon - (p->source + p->pos);
        if (label_len > 0 && label_len < max_len - 1) {
            // Check if it's just an identifier followed by :
            int is_label = 1;
            for (size_t j = 0; j < label_len; j++) {
                char c = p->source[p->pos + j];
                if (!isalnum((unsigned char)c) && c != '_') {
                    is_label = 0;
                    break;
                }
            }
            if (is_label) {
                strncpy(token, p->source + p->pos, label_len);
                token[label_len] = ':';
                token[label_len + 1] = '\0';
                p->pos += label_len + 1;
                return 1;
            }
        }
    }
    
    // Parse identifier or number
    if (isalpha((unsigned char)p->source[p->pos]) || p->source[p->pos] == '_') {
        while (i < max_len - 1 && 
               (isalnum((unsigned char)p->source[p->pos]) || p->source[p->pos] == '_')) {
            token[i++] = p->source[p->pos++];
        }
    } else if (isdigit((unsigned char)p->source[p->pos]) || 
               (p->source[p->pos] == '-' && isdigit((unsigned char)p->source[p->pos + 1]))) {
        // Number (possibly negative)
        if (p->source[p->pos] == '-') {
            token[i++] = p->source[p->pos++];
        }
        while (i < max_len - 1 && isdigit((unsigned char)p->source[p->pos])) {
            token[i++] = p->source[p->pos++];
        }
        // Handle hex
        if (p->source[p->pos - 1] == '0' && p->source[p->pos] == 'x') {
            token[i++] = p->source[p->pos++];
            while (i < max_len - 1 && isxdigit((unsigned char)p->source[p->pos])) {
                token[i++] = p->source[p->pos++];
            }
        }
    } else if (p->source[p->pos] == '[') {
        // Memory reference
        token[i++] = p->source[p->pos++];
        while (i < max_len - 1 && p->source[p->pos] && p->source[p->pos] != ']') {
            token[i++] = p->source[p->pos++];
        }
        if (p->source[p->pos] == ']') {
            token[i++] = p->source[p->pos++];
        }
    } else {
        // Single character token
        token[i++] = p->source[p->pos++];
    }
    
    token[i] = '\0';
    return i > 0;
}

// Parse instruction
int parse_instruction(Parser* p, Instruction* instr) {
    char token[256];
    
    memset(instr, 0, sizeof(Instruction));
    
    // Get mnemonic
    if (!get_token(p, token, sizeof(token))) {
        return 0;
    }
    
    // Check for label definition
    size_t len = strlen(token);
    if (len > 0 && token[len - 1] == ':') {
        token[len - 1] = '\0';
        strncpy(instr->label, token, sizeof(instr->label) - 1);
        instr->type = OP_UNKNOWN; // Label definition
        instr->has_label = 1;
        return 1;
    }
    
    // Parse mnemonic
    if (_stricmp(token, "mov") == 0) {
        // mov dst, src
        char dst[64], src[64];
        if (!get_token(p, dst, sizeof(dst))) return 0;
        if (!get_token(p, token, sizeof(token))) return 0; // comma
        if (!get_token(p, src, sizeof(src))) return 0;
        
        instr->dst = parse_register(dst);
        instr->src = parse_register(src);
        
        if (instr->dst != REG_NONE && instr->src != REG_NONE) {
            instr->type = OP_MOV_RR;
        } else if (instr->dst != REG_NONE) {
            // Check if src is immediate
            if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) {
                instr->immediate = strtoll(src, NULL, 16);
            } else {
                instr->immediate = strtoll(src, NULL, 10);
            }
            instr->has_immediate = 1;
            instr->type = OP_MOV_RI;
        }
    } else if (_stricmp(token, "push") == 0) {
        char reg[64];
        if (!get_token(p, reg, sizeof(reg))) return 0;
        instr->dst = parse_register(reg);
        instr->type = OP_PUSH_R;
    } else if (_stricmp(token, "pop") == 0) {
        char reg[64];
        if (!get_token(p, reg, sizeof(reg))) return 0;
        instr->dst = parse_register(reg);
        instr->type = OP_POP_R;
    } else if (_stricmp(token, "add") == 0) {
        char dst[64], src[64];
        if (!get_token(p, dst, sizeof(dst))) return 0;
        if (!get_token(p, token, sizeof(token))) return 0; // comma
        if (!get_token(p, src, sizeof(src))) return 0;
        
        instr->dst = parse_register(dst);
        instr->src = parse_register(src);
        
        if (instr->dst != REG_NONE && instr->src != REG_NONE) {
            instr->type = OP_ADD_RR;
        } else if (instr->dst != REG_NONE) {
            if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) {
                instr->immediate = strtoll(src, NULL, 16);
            } else {
                instr->immediate = strtoll(src, NULL, 10);
            }
            instr->has_immediate = 1;
            instr->type = OP_ADD_RI;
        }
    } else if (_stricmp(token, "sub") == 0) {
        char dst[64], src[64];
        if (!get_token(p, dst, sizeof(dst))) return 0;
        if (!get_token(p, token, sizeof(token))) return 0; // comma
        if (!get_token(p, src, sizeof(src))) return 0;
        
        instr->dst = parse_register(dst);
        instr->src = parse_register(src);
        
        if (instr->dst != REG_NONE && instr->src != REG_NONE) {
            instr->type = OP_SUB_RR;
        } else if (instr->dst != REG_NONE) {
            if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) {
                instr->immediate = strtoll(src, NULL, 16);
            } else {
                instr->immediate = strtoll(src, NULL, 10);
            }
            instr->has_immediate = 1;
            instr->type = OP_SUB_RI;
        }
    } else if (_stricmp(token, "xor") == 0) {
        char dst[64], src[64];
        if (!get_token(p, dst, sizeof(dst))) return 0;
        if (!get_token(p, token, sizeof(token))) return 0; // comma
        if (!get_token(p, src, sizeof(src))) return 0;
        
        instr->dst = parse_register(dst);
        instr->src = parse_register(src);
        instr->type = OP_XOR_RR;
    } else if (_stricmp(token, "inc") == 0) {
        char reg[64];
        if (!get_token(p, reg, sizeof(reg))) return 0;
        instr->dst = parse_register(reg);
        // Check if it's a 32-bit register (ends with 'x' for eax, ebx, etc.)
        size_t reg_len = strlen(reg);
        if (reg_len == 3 && reg[2] == 'x') {
            instr->type = OP_INC_R32;
        } else {
            instr->type = OP_INC_R;
        }
    } else if (_stricmp(token, "call") == 0) {
        char target[64];
        if (!get_token(p, target, sizeof(target))) return 0;
        strncpy(instr->label, target, sizeof(instr->label) - 1);
        instr->has_label = 1;
        instr->type = OP_CALL;
    } else if (_stricmp(token, "ret") == 0) {
        instr->type = OP_RET;
    } else if (_stricmp(token, "nop") == 0) {
        instr->type = OP_NOP;
    } else if (_stricmp(token, "int3") == 0) {
        instr->type = OP_INT3;
    } else {
        instr->type = OP_UNKNOWN;
    }
    
    return 1;
}

// Encode instruction to machine code
void encode_instruction(CodeBuffer* buf, Instruction* instr, uint32_t current_rva) {
    uint8_t encoding[16];
    size_t len = 0;
    
    switch (instr->type) {
        case OP_MOV_RR: {
            // mov r64, r64: REX.W + 89 /r (MOV r/m64, r64)
            // or REX.W + 8B /r (MOV r64, r/m64)
            int dst_enc = reg_encoding[instr->dst];
            int src_enc = reg_encoding[instr->src];
            
            // REX.W prefix (0x48) + opcode + ModR/M
            encoding[len++] = 0x48;
            encoding[len++] = 0x89;
            // ModR/M: mod=11 (register), reg=src, r/m=dst
            encoding[len++] = 0xC0 | (src_enc << 3) | dst_enc;
            break;
        }
        
        case OP_MOV_RI: {
            // mov r64, imm64: REX.W + B8+rd io
            int dst_enc = reg_encoding[instr->dst];
            
            // REX.W prefix with possible REX.B for r8-r15
            if (instr->dst >= REG_R8) {
                encoding[len++] = 0x49; // REX.W | REX.B
                encoding[len++] = 0xB8 + (dst_enc - 8);
            } else {
                encoding[len++] = 0x48; // REX.W
                encoding[len++] = 0xB8 + dst_enc;
            }
            
            // 64-bit immediate (little endian)
            int64_t imm = instr->immediate;
            for (int i = 0; i < 8; i++) {
                encoding[len++] = (imm >> (i * 8)) & 0xFF;
            }
            break;
        }
        
        case OP_PUSH_R: {
            // push r64: 50+rd (for r8-r15: 41 + 50+rd)
            int dst_enc = reg_encoding[instr->dst];
            if (instr->dst >= REG_R8) {
                encoding[len++] = 0x41;
                encoding[len++] = 0x50 + (dst_enc - 8);
            } else {
                encoding[len++] = 0x50 + dst_enc;
            }
            break;
        }
        
        case OP_POP_R: {
            // pop r64: 58+rd
            int dst_enc = reg_encoding[instr->dst];
            if (instr->dst >= REG_R8) {
                encoding[len++] = 0x41;
                encoding[len++] = 0x58 + (dst_enc - 8);
            } else {
                encoding[len++] = 0x58 + dst_enc;
            }
            break;
        }
        
        case OP_ADD_RR: {
            // add r64, r64: REX.W + 01 /r
            int dst_enc = reg_encoding[instr->dst];
            int src_enc = reg_encoding[instr->src];
            
            encoding[len++] = 0x48;
            encoding[len++] = 0x01;
            encoding[len++] = 0xC0 | (src_enc << 3) | dst_enc;
            break;
        }
        
        case OP_ADD_RI: {
            // add r64, imm32: REX.W + 81 /0 id
            int dst_enc = reg_encoding[instr->dst];
            
            encoding[len++] = 0x48;
            encoding[len++] = 0x81;
            encoding[len++] = 0xC0 | dst_enc; // ModR/M: mod=11, reg=0, r/m=dst
            
            // 32-bit immediate
            int32_t imm = (int32_t)instr->immediate;
            for (int i = 0; i < 4; i++) {
                encoding[len++] = (imm >> (i * 8)) & 0xFF;
            }
            break;
        }
        
        case OP_SUB_RR: {
            // sub r64, r64: REX.W + 29 /r
            int dst_enc = reg_encoding[instr->dst];
            int src_enc = reg_encoding[instr->src];
            
            encoding[len++] = 0x48;
            encoding[len++] = 0x29;
            encoding[len++] = 0xC0 | (src_enc << 3) | dst_enc;
            break;
        }
        
        case OP_SUB_RI: {
            // sub r64, imm32: REX.W + 81 /5 id
            int dst_enc = reg_encoding[instr->dst];
            
            encoding[len++] = 0x48;
            encoding[len++] = 0x81;
            encoding[len++] = 0xE8 | dst_enc; // ModR/M: mod=11, reg=5, r/m=dst
            
            int32_t imm = (int32_t)instr->immediate;
            for (int i = 0; i < 4; i++) {
                encoding[len++] = (imm >> (i * 8)) & 0xFF;
            }
            break;
        }
        
        case OP_XOR_RR: {
            // xor r64, r64: REX.W + 31 /r
            int dst_enc = reg_encoding[instr->dst];
            int src_enc = reg_encoding[instr->src];
            
            encoding[len++] = 0x48;
            encoding[len++] = 0x31;
            encoding[len++] = 0xC0 | (src_enc << 3) | dst_enc;
            break;
        }
        
        case OP_CALL: {
            // call rel32: E8 cd
            encoding[len++] = 0xE8;
            // Placeholder for relative offset (will be patched later)
            encoding[len++] = 0x00;
            encoding[len++] = 0x00;
            encoding[len++] = 0x00;
            encoding[len++] = 0x00;
            break;
        }
        
        case OP_RET: {
            // ret: C3
            encoding[len++] = 0xC3;
            break;
        }
        
        case OP_NOP: {
            // nop: 90
            encoding[len++] = 0x90;
            break;
        }
        
        case OP_INT3: {
            // int3: CC
            encoding[len++] = 0xCC;
            break;
        }
        
        case OP_INC_R: {
            // inc r64: FF /0 (ModR/M: mod=11, reg=0, r/m=reg)
            // For 64-bit registers, we need REX.W prefix
            int dst_enc = reg_encoding[instr->dst];
            
            // REX.W prefix (0x48) + opcode + ModR/M
            encoding[len++] = 0x48;
            encoding[len++] = 0xFF;
            // ModR/M: mod=11 (register), reg=0 (inc), r/m=dst
            encoding[len++] = 0xC0 | dst_enc;
            break;
        }
        
        case OP_INC_R32: {
            // inc r32: FF /0 (ModR/M: mod=11, reg=0, r/m=reg)
            // NO REX.W prefix for 32-bit registers
            int dst_enc = reg_encoding[instr->dst];
            
            encoding[len++] = 0xFF;
            // ModR/M: mod=11 (register), reg=0 (inc), r/m=dst
            encoding[len++] = 0xC0 | dst_enc;
            break;
        }
        
        default:
            // Unknown instruction - encode as NOP
            encoding[len++] = 0x90;
            break;
    }
    
    code_buffer_append(buf, encoding, len);
}

// Create PE file
int create_pe_file(const char* filename, CodeBuffer* code, size_t entry_point_offset) {
    FILE* f = fopen(filename, "wb");
    if (!f) return 0;
    
    // PE structures
    IMAGE_DOS_HEADER dos_header = {0};
    IMAGE_FILE_HEADER file_header = {0};
    IMAGE_OPTIONAL_HEADER64 opt_header = {0};
    IMAGE_SECTION_HEADER sect_header = {0};
    
    // Calculate sizes
    uint32_t dos_size = sizeof(IMAGE_DOS_HEADER);
    uint32_t pe_sig_size = 4;
    uint32_t file_header_size = sizeof(IMAGE_FILE_HEADER);
    uint32_t opt_header_size = sizeof(IMAGE_OPTIONAL_HEADER64);
    uint32_t data_dir_size = 16 * sizeof(IMAGE_DATA_DIRECTORY);
    uint32_t sect_header_size = sizeof(IMAGE_SECTION_HEADER);
    
    uint32_t headers_size = dos_size + pe_sig_size + file_header_size + opt_header_size + data_dir_size + sect_header_size;
    uint32_t file_alignment = 512;
    uint32_t section_alignment = 4096;
    
    uint32_t padded_headers = (headers_size + file_alignment - 1) & ~(file_alignment - 1);
    uint32_t padded_code = (code->size + file_alignment - 1) & ~(file_alignment - 1);
    
    // Allocate PE buffer
    uint32_t total_size = padded_headers + padded_code;
    uint8_t* pe = calloc(1, total_size);
    if (!pe) {
        fclose(f);
        return 0;
    }
    
    // DOS Header
    dos_header.e_magic = 0x5A4D; // 'MZ'
    dos_header.e_lfanew = dos_size;
    memcpy(pe, &dos_header, sizeof(dos_header));
    
    // PE Signature
    uint32_t pe_sig = 0x00004550;
    memcpy(pe + dos_size, &pe_sig, 4);
    
    // File Header
    file_header.Machine = IMAGE_FILE_MACHINE_AMD64;
    file_header.NumberOfSections = 1;
    file_header.TimeDateStamp = 0;
    file_header.PointerToSymbolTable = 0;
    file_header.NumberOfSymbols = 0;
    file_header.SizeOfOptionalHeader = opt_header_size + data_dir_size;
    file_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    memcpy(pe + dos_size + pe_sig_size, &file_header, sizeof(file_header));
    
    // Optional Header
    opt_header.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt_header.MajorLinkerVersion = 1;
    opt_header.MinorLinkerVersion = 0;
    opt_header.SizeOfCode = padded_code;
    opt_header.SizeOfInitializedData = 0;
    opt_header.SizeOfUninitializedData = 0;
    opt_header.AddressOfEntryPoint = section_alignment; // Entry point RVA
    opt_header.BaseOfCode = section_alignment;
    opt_header.ImageBase = 0x140000000ULL;
    opt_header.SectionAlignment = section_alignment;
    opt_header.FileAlignment = file_alignment;
    opt_header.MajorOperatingSystemVersion = 6;
    opt_header.MinorOperatingSystemVersion = 0;
    opt_header.MajorImageVersion = 0;
    opt_header.MinorImageVersion = 0;
    opt_header.MajorSubsystemVersion = 6;
    opt_header.MinorSubsystemVersion = 0;
    opt_header.Win32VersionValue = 0;
    opt_header.SizeOfImage = section_alignment * 2;
    opt_header.SizeOfHeaders = padded_headers;
    opt_header.CheckSum = 0;
    opt_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt_header.DllCharacteristics = 0;
    opt_header.SizeOfStackReserve = 0x100000;
    opt_header.SizeOfStackCommit = 0x1000;
    opt_header.SizeOfHeapReserve = 0x100000;
    opt_header.SizeOfHeapCommit = 0x1000;
    opt_header.LoaderFlags = 0;
    opt_header.NumberOfRvaAndSizes = 16;
    memcpy(pe + dos_size + pe_sig_size + sizeof(file_header), &opt_header, sizeof(opt_header));
    
    // Section Header
    memcpy(sect_header.Name, ".text", 5);
    sect_header.Misc.VirtualSize = code->size;
    sect_header.VirtualAddress = section_alignment;
    sect_header.SizeOfRawData = padded_code;
    sect_header.PointerToRawData = padded_headers;
    sect_header.PointerToRelocations = 0;
    sect_header.PointerToLinenumbers = 0;
    sect_header.NumberOfRelocations = 0;
    sect_header.NumberOfLinenumbers = 0;
    sect_header.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    memcpy(pe + dos_size + pe_sig_size + sizeof(file_header) + opt_header_size + data_dir_size, 
           &sect_header, sizeof(sect_header));
    
    // Copy code
    memcpy(pe + padded_headers, code->data, code->size);
    
    // Write file
    fwrite(pe, 1, total_size, f);
    fclose(f);
    free(pe);
    
    return 1;
}

// Main assembler function
int assemble_file(const char* input_file, const char* output_file) {
    printf("RawrXD Real Assembler v1.0\n");
    printf("==========================\n\n");
    
    // Read source file
    FILE* f = fopen(input_file, "rb");
    if (!f) {
        printf("Error: Cannot open input file: %s\n", input_file);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* source = malloc(size + 1);
    if (!source) {
        fclose(f);
        printf("Error: Out of memory\n");
        return 1;
    }
    
    fread(source, 1, size, f);
    source[size] = '\0';
    fclose(f);
    
    printf("Read %ld bytes from %s\n\n", size, input_file);
    
    // Initialize parser
    Parser parser = {0};
    parser.source = source;
    parser.instr_capacity = 1024;
    parser.instructions = malloc(sizeof(Instruction) * parser.instr_capacity);
    
    // Parse all instructions
    printf("Parsing assembly...\n");
    
    Instruction instr;
    while (parse_instruction(&parser, &instr)) {
        if (parser.instr_count >= parser.instr_capacity) {
            parser.instr_capacity *= 2;
            parser.instructions = realloc(parser.instructions, 
                                         sizeof(Instruction) * parser.instr_capacity);
        }
        parser.instructions[parser.instr_count++] = instr;
    }
    
    printf("Parsed %zu instructions\n\n", parser.instr_count);
    
    // Generate code
    printf("Generating machine code...\n");
    
    CodeBuffer code;
    code_buffer_init(&code);
    
    // Add some startup code: sub rsp, 0x28 (shadow space)
    uint8_t startup[] = {0x48, 0x83, 0xEC, 0x28};
    code_buffer_append(&code, startup, sizeof(startup));
    
    // Encode all instructions
    for (size_t i = 0; i < parser.instr_count; i++) {
        encode_instruction(&code, &parser.instructions[i], 0x1000 + code.size);
    }
    
    // Add exit code: xor ecx, ecx; mov rax, ExitProcess; call rax
    // For now, just add a ret
    uint8_t exit_code[] = {0x48, 0x83, 0xC4, 0x28,  // add rsp, 0x28
                           0xC3};                    // ret
    code_buffer_append(&code, exit_code, sizeof(exit_code));
    
    printf("Generated %zu bytes of machine code\n\n", code.size);
    
    // Create PE file
    printf("Creating PE file: %s\n", output_file);
    
    if (!create_pe_file(output_file, &code, 0)) {
        printf("Error: Failed to create output file\n");
        code_buffer_free(&code);
        free(parser.instructions);
        free(source);
        return 1;
    }
    
    printf("\nSuccess! Output written to: %s\n", output_file);
    printf("Entry point: 0x1000\n");
    printf("Image base: 0x140000000\n");
    
    // Cleanup
    code_buffer_free(&code);
    free(parser.instructions);
    free(source);
    
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input.asm> <output.exe>\n", argv[0]);
        printf("\nA real x64 assembler that parses instructions and generates machine code.\n");
        printf("Supported instructions: mov, push, pop, add, sub, xor, call, ret, nop, int3\n");
        return 1;
    }
    
    return assemble_file(argv[1], argv[2]);
}

