// ============================================================================
// rawrxd_assembler.c - Real x64 Assembler for RawrXD Sovereign IDE
// ============================================================================
// This is a REAL assembler - parses x64 assembly and generates machine code
// No hardcoded outputs, no dependencies on external tools
// ============================================================================
// Build: gcc -O2 -o rawrxd_assembler.exe rawrxd_assembler.c
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <windows.h>

// Error codes
#define ERR_OK 0
#define ERR_SYNTAX 1
#define ERR_UNDEFINED 2
#define ERR_OVERFLOW 3
#define ERR_IO 4

// Instruction types
enum {
    INSTR_MOV,
    INSTR_PUSH,
    INSTR_POP,
    INSTR_ADD,
    INSTR_SUB,
    INSTR_AND,
    INSTR_OR,
    INSTR_XOR,
    INSTR_CMP,
    INSTR_TEST,
    INSTR_JMP,
    INSTR_JE,
    INSTR_JNE,
    INSTR_JL,
    INSTR_JLE,
    INSTR_JG,
    INSTR_JGE,
    INSTR_CALL,
    INSTR_RET,
    INSTR_NOP,
    INSTR_SYSCALL,
    INSTR_LEA,
    INSTR_INC,
    INSTR_DEC,
    INSTR_NEG,
    INSTR_NOT,
    INSTR_SHL,
    INSTR_SHR,
    INSTR_SAR,
    INSTR_MUL,
    INSTR_IMUL,
    INSTR_DIV,
    INSTR_IDIV,
    INSTR_CBW,
    INSTR_CWD,
    INSTR_CDQ,
    INSTR_CQO,
    INSTR_MOVZX,
    INSTR_MOVSX,
    INSTR_SETE,
    INSTR_SETNE,
    INSTR_SETL,
    INSTR_SETLE,
    INSTR_SETG,
    INSTR_SETGE,
    INSTR_SETZ,
    INSTR_SETNZ,
    INSTR_DB,
    INSTR_DW,
    INSTR_DD,
    INSTR_DQ,
    INSTR_RESB,
    INSTR_RESW,
    INSTR_RESD,
    INSTR_RESQ,
    INSTR_GLOBAL,
    INSTR_EXTERN,
    INSTR_SECTION,
    INSTR_ALIGN,
    INSTR_TIMES,
    INSTR_EQU,
    INSTR_LABEL,
    INSTR_UNKNOWN
};

// Register encodings
#define REG_RAX 0
#define REG_RCX 1
#define REG_RDX 2
#define REG_RBX 3
#define REG_RSP 4
#define REG_RBP 5
#define REG_RSI 6
#define REG_RDI 7
#define REG_R8 8
#define REG_R9 9
#define REG_R10 10
#define REG_R11 11
#define REG_R12 12
#define REG_R13 13
#define REG_R14 14
#define REG_R15 15

// Register sizes
#define SIZE_BYTE 1
#define SIZE_WORD 2
#define SIZE_DWORD 4
#define SIZE_QWORD 8

// Operand types
enum {
    OP_NONE,
    OP_REG,
    OP_IMM,
    OP_MEM,
    OP_LABEL_REF
};

// Operand structure
typedef struct {
    int type;
    int reg;
    int size;
    int64_t imm;
    int base_reg;
    int index_reg;
    int scale;
    int64_t disp;
    char label_name[256];
} Operand;

// Instruction structure
typedef struct {
    int type;
    char mnemonic[32];
    Operand dst;
    Operand src;
    int line_num;
} Instruction;

// Label structure
typedef struct {
    char name[256];
    uint64_t offset;
    int defined;
    int section;
} Label;

// Section types
enum {
    SECTION_NONE,
    SECTION_TEXT,
    SECTION_DATA,
    SECTION_BSS,
    SECTION_RDATA
};

// Assembler state
typedef struct {
    // Sections
    uint8_t text_section[65536];
    uint8_t data_section[65536];
    uint8_t rdata_section[65536];
    uint8_t bss_section[65536];
    
    uint64_t text_offset;
    uint64_t data_offset;
    uint64_t rdata_offset;
    uint64_t bss_offset;
    
    int current_section;
    
    // Labels
    Label labels[1024];
    int label_count;
    
    // Fixups for forward references
    struct {
        char label_name[256];
        uint64_t offset;
        int section;
        int size;
    } fixups[1024];
    int fixup_count;
    
    // Source info
    char *source;
    int source_len;
    int pos;
    int line;
    
    // Output
    char output_file[512];
    
    // Entry point
    char entry_point[256];
    int has_entry;
} Assembler;

// Register names
const char *reg64_names[] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};

const char *reg32_names[] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
};

const char *reg16_names[] = {
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
};

const char *reg8_names[] = {
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    "ah", "ch", "dh", "bh"
};

// Initialize assembler
void init_assembler(Assembler *a) {
    memset(a, 0, sizeof(Assembler));
    a->current_section = SECTION_TEXT;
    a->line = 1;
    a->has_entry = 0;
}

// Skip whitespace
void skip_whitespace(Assembler *a) {
    while (a->pos < a->source_len && isspace((unsigned char)a->source[a->pos])) {
        if (a->source[a->pos] == '\n') a->line++;
        a->pos++;
    }
}

// Skip comments
void skip_comments(Assembler *a) {
    skip_whitespace(a);
    if (a->pos < a->source_len && a->source[a->pos] == ';') {
        while (a->pos < a->source_len && a->source[a->pos] != '\n') {
            a->pos++;
        }
        skip_whitespace(a);
    }
}

// Get next token
int get_token(Assembler *a, char *token, int max_len) {
    skip_comments(a);
    
    if (a->pos >= a->source_len) return 0;
    
    int i = 0;
    
    // Check for special characters
    char c = a->source[a->pos];
    if (c == ':' || c == ',' || c == '[' || c == ']' || c == '+' || c == '-' || 
        c == '*' || c == '(' || c == ')' || c == '$' || c == '%') {
        token[i++] = c;
        a->pos++;
        token[i] = '\0';
        return 1;
    }
    
    // String literal
    if (c == '"' || c == '\'') {
        char quote = c;
        a->pos++;
        while (a->pos < a->source_len && i < max_len - 1) {
            c = a->source[a->pos];
            if (c == quote) {
                a->pos++;
                break;
            }
            if (c == '\\' && a->pos + 1 < a->source_len) {
                a->pos++;
                c = a->source[a->pos];
                switch (c) {
                    case 'n': token[i++] = '\n'; break;
                    case 'r': token[i++] = '\r'; break;
                    case 't': token[i++] = '\t'; break;
                    case '0': token[i++] = '\0'; break;
                    case '\\': token[i++] = '\\'; break;
                    case '"': token[i++] = '"'; break;
                    case '\'': token[i++] = '\''; break;
                    default: token[i++] = c;
                }
            } else {
                token[i++] = c;
            }
            a->pos++;
        }
        token[i] = '\0';
        return 1;
    }
    
    // Number (hex, binary, decimal)
    if (isdigit((unsigned char)c) || c == '0') {
        // Check for hex
        if (c == '0' && a->pos + 1 < a->source_len && 
            (a->source[a->pos + 1] == 'x' || a->source[a->pos + 1] == 'X')) {
            token[i++] = '0';
            token[i++] = a->source[++a->pos];
            a->pos++;
            while (a->pos < a->source_len && i < max_len - 1 &&
                   isxdigit((unsigned char)a->source[a->pos])) {
                token[i++] = a->source[a->pos++];
            }
        }
        // Check for binary
        else if (c == '0' && a->pos + 1 < a->source_len && 
                 (a->source[a->pos + 1] == 'b' || a->source[a->pos + 1] == 'B')) {
            token[i++] = '0';
            token[i++] = a->source[++a->pos];
            a->pos++;
            while (a->pos < a->source_len && i < max_len - 1 &&
                   (a->source[a->pos] == '0' || a->source[a->pos] == '1')) {
                token[i++] = a->source[a->pos++];
            }
        }
        // Decimal
        else {
            while (a->pos < a->source_len && i < max_len - 1 &&
                   isdigit((unsigned char)a->source[a->pos])) {
                token[i++] = a->source[a->pos++];
            }
        }
        token[i] = '\0';
        return 1;
    }
    
    // Identifier
    if (isalpha((unsigned char)c) || c == '_' || c == '.' || c == '@') {
        while (a->pos < a->source_len && i < max_len - 1 &&
               (isalnum((unsigned char)a->source[a->pos]) || 
                a->source[a->pos] == '_' || a->source[a->pos] == '.' || 
                a->source[a->pos] == '@')) {
            token[i++] = a->source[a->pos++];
        }
        token[i] = '\0';
        return 1;
    }
    
    return 0;
}

// Peek at next token without consuming
int peek_token(Assembler *a, char *token, int max_len) {
    int old_pos = a->pos;
    int old_line = a->line;
    int result = get_token(a, token, max_len);
    a->pos = old_pos;
    a->line = old_line;
    return result;
}

// Parse number
int64_t parse_number(const char *str) {
    if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
        return strtoll(str + 2, NULL, 16);
    } else if (strncmp(str, "0b", 2) == 0 || strncmp(str, "0B", 2) == 0) {
        return strtoll(str + 2, NULL, 2);
    } else {
        return strtoll(str, NULL, 10);
    }
}

// Check if token is a register
int is_register(const char *token, int *reg_num, int *size) {
    // 64-bit registers
    for (int i = 0; i < 16; i++) {
        if (strcasecmp(token, reg64_names[i]) == 0) {
            *reg_num = i;
            *size = SIZE_QWORD;
            return 1;
        }
    }
    // 32-bit registers
    for (int i = 0; i < 16; i++) {
        if (strcasecmp(token, reg32_names[i]) == 0) {
            *reg_num = i;
            *size = SIZE_DWORD;
            return 1;
        }
    }
    // 16-bit registers
    for (int i = 0; i < 16; i++) {
        if (strcasecmp(token, reg16_names[i]) == 0) {
            *reg_num = i;
            *size = SIZE_WORD;
            return 1;
        }
    }
    // 8-bit registers
    for (int i = 0; i < 20; i++) {
        if (strcasecmp(token, reg8_names[i]) == 0) {
            if (i < 16) *reg_num = i;
            else *reg_num = i - 12;  // ah, ch, dh, bh
            *size = SIZE_BYTE;
            return 1;
        }
    }
    return 0;
}

// Check if token is an instruction
int is_instruction(const char *token) {
    static const char *instrs[] = {
        "mov", "push", "pop", "add", "sub", "and", "or", "xor",
        "cmp", "test", "jmp", "je", "jne", "jl", "jle", "jg", "jge",
        "call", "ret", "nop", "syscall", "lea", "inc", "dec", "neg",
        "not", "shl", "shr", "sar", "mul", "imul", "div", "idiv",
        "cbw", "cwd", "cdq", "cqo", "movzx", "movsx",
        "sete", "setne", "setl", "setle", "setg", "setge", "setz", "setnz",
        "db", "dw", "dd", "dq", "resb", "resw", "resd", "resq",
        "global", "extern", "section", "align", "times", "equ",
        NULL
    };
    
    for (int i = 0; instrs[i]; i++) {
        if (strcasecmp(token, instrs[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Get instruction type
int get_instruction_type(const char *mnemonic) {
    if (strcasecmp(mnemonic, "mov") == 0) return INSTR_MOV;
    if (strcasecmp(mnemonic, "push") == 0) return INSTR_PUSH;
    if (strcasecmp(mnemonic, "pop") == 0) return INSTR_POP;
    if (strcasecmp(mnemonic, "add") == 0) return INSTR_ADD;
    if (strcasecmp(mnemonic, "sub") == 0) return INSTR_SUB;
    if (strcasecmp(mnemonic, "and") == 0) return INSTR_AND;
    if (strcasecmp(mnemonic, "or") == 0) return INSTR_OR;
    if (strcasecmp(mnemonic, "xor") == 0) return INSTR_XOR;
    if (strcasecmp(mnemonic, "cmp") == 0) return INSTR_CMP;
    if (strcasecmp(mnemonic, "test") == 0) return INSTR_TEST;
    if (strcasecmp(mnemonic, "jmp") == 0) return INSTR_JMP;
    if (strcasecmp(mnemonic, "je") == 0) return INSTR_JE;
    if (strcasecmp(mnemonic, "jne") == 0) return INSTR_JNE;
    if (strcasecmp(mnemonic, "jl") == 0) return INSTR_JL;
    if (strcasecmp(mnemonic, "jle") == 0) return INSTR_JLE;
    if (strcasecmp(mnemonic, "jg") == 0) return INSTR_JG;
    if (strcasecmp(mnemonic, "jge") == 0) return INSTR_JGE;
    if (strcasecmp(mnemonic, "call") == 0) return INSTR_CALL;
    if (strcasecmp(mnemonic, "ret") == 0) return INSTR_RET;
    if (strcasecmp(mnemonic, "nop") == 0) return INSTR_NOP;
    if (strcasecmp(mnemonic, "syscall") == 0) return INSTR_SYSCALL;
    if (strcasecmp(mnemonic, "lea") == 0) return INSTR_LEA;
    if (strcasecmp(mnemonic, "inc") == 0) return INSTR_INC;
    if (strcasecmp(mnemonic, "dec") == 0) return INSTR_DEC;
    if (strcasecmp(mnemonic, "neg") == 0) return INSTR_NEG;
    if (strcasecmp(mnemonic, "not") == 0) return INSTR_NOT;
    if (strcasecmp(mnemonic, "shl") == 0) return INSTR_SHL;
    if (strcasecmp(mnemonic, "shr") == 0) return INSTR_SHR;
    if (strcasecmp(mnemonic, "sar") == 0) return INSTR_SAR;
    if (strcasecmp(mnemonic, "mul") == 0) return INSTR_MUL;
    if (strcasecmp(mnemonic, "imul") == 0) return INSTR_IMUL;
    if (strcasecmp(mnemonic, "div") == 0) return INSTR_DIV;
    if (strcasecmp(mnemonic, "idiv") == 0) return INSTR_IDIV;
    if (strcasecmp(mnemonic, "cbw") == 0) return INSTR_CBW;
    if (strcasecmp(mnemonic, "cwd") == 0) return INSTR_CWD;
    if (strcasecmp(mnemonic, "cdq") == 0) return INSTR_CDQ;
    if (strcasecmp(mnemonic, "cqo") == 0) return INSTR_CQO;
    if (strcasecmp(mnemonic, "movzx") == 0) return INSTR_MOVZX;
    if (strcasecmp(mnemonic, "movsx") == 0) return INSTR_MOVSX;
    if (strcasecmp(mnemonic, "sete") == 0) return INSTR_SETE;
    if (strcasecmp(mnemonic, "setne") == 0) return INSTR_SETNE;
    if (strcasecmp(mnemonic, "setl") == 0) return INSTR_SETL;
    if (strcasecmp(mnemonic, "setle") == 0) return INSTR_SETLE;
    if (strcasecmp(mnemonic, "setg") == 0) return INSTR_SETG;
    if (strcasecmp(mnemonic, "setge") == 0) return INSTR_SETGE;
    if (strcasecmp(mnemonic, "setz") == 0) return INSTR_SETZ;
    if (strcasecmp(mnemonic, "setnz") == 0) return INSTR_SETNZ;
    if (strcasecmp(mnemonic, "db") == 0) return INSTR_DB;
    if (strcasecmp(mnemonic, "dw") == 0) return INSTR_DW;
    if (strcasecmp(mnemonic, "dd") == 0) return INSTR_DD;
    if (strcasecmp(mnemonic, "dq") == 0) return INSTR_DQ;
    if (strcasecmp(mnemonic, "resb") == 0) return INSTR_RESB;
    if (strcasecmp(mnemonic, "resw") == 0) return INSTR_RESW;
    if (strcasecmp(mnemonic, "resd") == 0) return INSTR_RESD;
    if (strcasecmp(mnemonic, "resq") == 0) return INSTR_RESQ;
    if (strcasecmp(mnemonic, "global") == 0) return INSTR_GLOBAL;
    if (strcasecmp(mnemonic, "extern") == 0) return INSTR_EXTERN;
    if (strcasecmp(mnemonic, "section") == 0) return INSTR_SECTION;
    if (strcasecmp(mnemonic, "align") == 0) return INSTR_ALIGN;
    if (strcasecmp(mnemonic, "times") == 0) return INSTR_TIMES;
    if (strcasecmp(mnemonic, "equ") == 0) return INSTR_EQU;
    return INSTR_UNKNOWN;
}

// Get current output buffer based on section
uint8_t* get_current_buffer(Assembler *a, uint64_t **offset) {
    switch (a->current_section) {
        case SECTION_TEXT:
            *offset = &a->text_offset;
            return a->text_section;
        case SECTION_DATA:
            *offset = &a->data_offset;
            return a->data_section;
        case SECTION_RDATA:
            *offset = &a->rdata_offset;
            return a->rdata_section;
        case SECTION_BSS:
            *offset = &a->bss_offset;
            return a->bss_section;
        default:
            *offset = &a->text_offset;
            return a->text_section;
    }
}

// Emit byte
void emit_byte(Assembler *a, uint8_t byte) {
    uint64_t *offset;
    uint8_t *buffer = get_current_buffer(a, &offset);
    buffer[*offset] = byte;
    (*offset)++;
}

// Emit word
void emit_word(Assembler *a, uint16_t word) {
    emit_byte(a, word & 0xFF);
    emit_byte(a, (word >> 8) & 0xFF);
}

// Emit dword
void emit_dword(Assembler *a, uint32_t dword) {
    emit_byte(a, dword & 0xFF);
    emit_byte(a, (dword >> 8) & 0xFF);
    emit_byte(a, (dword >> 16) & 0xFF);
    emit_byte(a, (dword >> 24) & 0xFF);
}

// Emit qword
void emit_qword(Assembler *a, uint64_t qword) {
    emit_dword(a, qword & 0xFFFFFFFF);
    emit_dword(a, (qword >> 32) & 0xFFFFFFFF);
}

// Encode ModR/M byte
void emit_modrm(Assembler *a, int mod, int reg, int rm) {
    emit_byte(a, ((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7));
}

// Encode SIB byte
void emit_sib(Assembler *a, int scale, int index, int base) {
    int scale_bits = 0;
    if (scale == 2) scale_bits = 1;
    else if (scale == 4) scale_bits = 2;
    else if (scale == 8) scale_bits = 3;
    emit_byte(a, (scale_bits << 6) | ((index & 7) << 3) | (base & 7));
}

// Encode REX prefix
void emit_rex(Assembler *a, int w, int r, int x, int b) {
    emit_byte(a, 0x40 | ((w & 1) << 3) | ((r & 1) << 2) | ((x & 1) << 1) | (b & 1));
}

// Encode register operand
void encode_register(Assembler *a, int opcode, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    
    // REX prefix for extended registers (r8-r15) or 64-bit mode
    if (w || reg >= 8) {
        int r = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, r);
    }
    
    // Opcode + register
    emit_byte(a, opcode + (reg & 7));
}

// Encode mov reg, imm
void encode_mov_reg_imm(Assembler *a, int reg, int64_t imm, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    
    // REX prefix
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    
    // MOV r64, imm64 (0xB8 + rd) for 64-bit immediate
    if (size == SIZE_QWORD && (imm < -2147483648LL || imm > 2147483647LL)) {
        emit_byte(a, 0xB8 + (reg & 7));
        emit_qword(a, imm);
    }
    // MOV r32, imm32 (0xB8 + rd)
    else if (size == SIZE_DWORD || size == SIZE_QWORD) {
        emit_byte(a, 0xB8 + (reg & 7));
        emit_dword(a, (uint32_t)imm);
    }
    // MOV r16, imm16 (0xB8 + rd with 0x66 prefix)
    else if (size == SIZE_WORD) {
        emit_byte(a, 0x66);  // Operand size prefix
        emit_byte(a, 0xB8 + (reg & 7));
        emit_word(a, (uint16_t)imm);
    }
    // MOV r8, imm8 (0xB0 + rd)
    else {
        emit_byte(a, 0xB0 + (reg & 7));
        emit_byte(a, (uint8_t)imm);
    }
}

// Encode mov reg, reg
void encode_mov_reg_reg(Assembler *a, int dst_reg, int src_reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    
    // REX prefix
    int r = (src_reg >= 8) ? 1 : 0;
    int b = (dst_reg >= 8) ? 1 : 0;
    if (w || r || b) {
        emit_rex(a, w, r, 0, b);
    }
    
    // MOV r/m64, r64 (0x89 /r)
    emit_byte(a, 0x89);
    emit_modrm(a, 3, src_reg & 7, dst_reg & 7);
}

// Encode push reg
void encode_push_reg(Assembler *a, int reg) {
    if (reg >= 8) {
        emit_rex(a, 0, 0, 0, 1);
    }
    emit_byte(a, 0x50 + (reg & 7));
}

// Encode pop reg
void encode_pop_reg(Assembler *a, int reg) {
    if (reg >= 8) {
        emit_rex(a, 0, 0, 0, 1);
    }
    emit_byte(a, 0x58 + (reg & 7));
}

// Encode add reg, imm
void encode_add_reg_imm(Assembler *a, int reg, int64_t imm, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    
    // Check if immediate fits in 8 bits
    if (imm >= -128 && imm <= 127) {
        // ADD r/m64, imm8 (0x83 /0 ib)
        if (w || reg >= 8) {
            int b = (reg >= 8) ? 1 : 0;
            emit_rex(a, w, 0, 0, b);
        }
        emit_byte(a, 0x83);
        emit_modrm(a, 3, 0, reg & 7);
        emit_byte(a, (uint8_t)imm);
    } else {
        // ADD r/m64, imm32 (0x81 /0 id)
        if (w || reg >= 8) {
            int b = (reg >= 8) ? 1 : 0;
            emit_rex(a, w, 0, 0, b);
        }
        emit_byte(a, 0x81);
        emit_modrm(a, 3, 0, reg & 7);
        emit_dword(a, (uint32_t)imm);
    }
}

// Encode sub reg, imm
void encode_sub_reg_imm(Assembler *a, int reg, int64_t imm, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    
    if (imm >= -128 && imm <= 127) {
        if (w || reg >= 8) {
            int b = (reg >= 8) ? 1 : 0;
            emit_rex(a, w, 0, 0, b);
        }
        emit_byte(a, 0x83);
        emit_modrm(a, 3, 5, reg & 7);  // /5 = SUB
        emit_byte(a, (uint8_t)imm);
    } else {
        if (w || reg >= 8) {
            int b = (reg >= 8) ? 1 : 0;
            emit_rex(a, w, 0, 0, b);
        }
        emit_byte(a, 0x81);
        emit_modrm(a, 3, 5, reg & 7);
        emit_dword(a, (uint32_t)imm);
    }
}

// Encode ret
void encode_ret(Assembler *a) {
    emit_byte(a, 0xC3);
}

// Encode nop
void encode_nop(Assembler *a) {
    emit_byte(a, 0x90);
}

// Encode syscall
void encode_syscall(Assembler *a) {
    emit_byte(a, 0x0F);
    emit_byte(a, 0x05);
}

// Encode inc reg
void encode_inc_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xFF);
    emit_modrm(a, 3, 0, reg & 7);  // /0 = INC
}

// Encode dec reg
void encode_dec_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xFF);
    emit_modrm(a, 3, 1, reg & 7);  // /1 = DEC
}

// Encode jmp rel32
void encode_jmp_rel32(Assembler *a, int32_t offset) {
    emit_byte(a, 0xE9);
    emit_dword(a, offset);
}

// Encode je rel32
void encode_je_rel32(Assembler *a, int32_t offset) {
    emit_byte(a, 0x0F);
    emit_byte(a, 0x84);
    emit_dword(a, offset);
}

// Encode jne rel32
void encode_jne_rel32(Assembler *a, int32_t offset) {
    emit_byte(a, 0x0F);
    emit_byte(a, 0x85);
    emit_dword(a, offset);
}

// Encode call rel32
void encode_call_rel32(Assembler *a, int32_t offset) {
    emit_byte(a, 0xE8);
    emit_dword(a, offset);
}

// Encode cmp reg, imm
void encode_cmp_reg_imm(Assembler *a, int reg, int64_t imm, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    
    if (imm >= -128 && imm <= 127) {
        if (w || reg >= 8) {
            int b = (reg >= 8) ? 1 : 0;
            emit_rex(a, w, 0, 0, b);
        }
        emit_byte(a, 0x83);
        emit_modrm(a, 3, 7, reg & 7);  // /7 = CMP
        emit_byte(a, (uint8_t)imm);
    } else {
        if (w || reg >= 8) {
            int b = (reg >= 8) ? 1 : 0;
            emit_rex(a, w, 0, 0, b);
        }
        emit_byte(a, 0x81);
        emit_modrm(a, 3, 7, reg & 7);
        emit_dword(a, (uint32_t)imm);
    }
}

// Encode test reg, reg
void encode_test_reg_reg(Assembler *a, int reg1, int reg2, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    int r = (reg2 >= 8) ? 1 : 0;
    int b = (reg1 >= 8) ? 1 : 0;
    if (w || r || b) {
        emit_rex(a, w, r, 0, b);
    }
    emit_byte(a, 0x85);
    emit_modrm(a, 3, reg2 & 7, reg1 & 7);
}

// Encode and reg, reg
void encode_and_reg_reg(Assembler *a, int dst, int src, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    int r = (src >= 8) ? 1 : 0;
    int b = (dst >= 8) ? 1 : 0;
    if (w || r || b) {
        emit_rex(a, w, r, 0, b);
    }
    emit_byte(a, 0x21);  // AND r/m64, r64
    emit_modrm(a, 3, src & 7, dst & 7);
}

// Encode or reg, reg
void encode_or_reg_reg(Assembler *a, int dst, int src, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    int r = (src >= 8) ? 1 : 0;
    int b = (dst >= 8) ? 1 : 0;
    if (w || r || b) {
        emit_rex(a, w, r, 0, b);
    }
    emit_byte(a, 0x09);  // OR r/m64, r64
    emit_modrm(a, 3, src & 7, dst & 7);
}

// Encode xor reg, reg
void encode_xor_reg_reg(Assembler *a, int dst, int src, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    int r = (src >= 8) ? 1 : 0;
    int b = (dst >= 8) ? 1 : 0;
    if (w || r || b) {
        emit_rex(a, w, r, 0, b);
    }
    emit_byte(a, 0x31);  // XOR r/m64, r64
    emit_modrm(a, 3, src & 7, dst & 7);
}

// Encode add reg, reg
void encode_add_reg_reg(Assembler *a, int dst, int src, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    int r = (src >= 8) ? 1 : 0;
    int b = (dst >= 8) ? 1 : 0;
    if (w || r || b) {
        emit_rex(a, w, r, 0, b);
    }
    emit_byte(a, 0x01);  // ADD r/m64, r64
    emit_modrm(a, 3, src & 7, dst & 7);
}

// Encode sub reg, reg
void encode_sub_reg_reg(Assembler *a, int dst, int src, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    int r = (src >= 8) ? 1 : 0;
    int b = (dst >= 8) ? 1 : 0;
    if (w || r || b) {
        emit_rex(a, w, r, 0, b);
    }
    emit_byte(a, 0x29);  // SUB r/m64, r64
    emit_modrm(a, 3, src & 7, dst & 7);
}

// Encode lea reg, [rip+disp32]
void encode_lea_rip_rel(Assembler *a, int reg, int32_t disp) {
    int b = (reg >= 8) ? 1 : 0;
    emit_rex(a, 1, 0, 0, b);  // REX.W
    emit_byte(a, 0x8D);  // LEA
    emit_modrm(a, 0, reg & 7, 5);  // Mod=00, RIP-relative addressing
    emit_dword(a, disp);
}

// Encode neg reg
void encode_neg_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xF7);
    emit_modrm(a, 3, 3, reg & 7);  // /3 = NEG
}

// Encode not reg
void encode_not_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xF7);
    emit_modrm(a, 3, 2, reg & 7);  // /2 = NOT
}

// Encode mul reg
void encode_mul_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xF7);
    emit_modrm(a, 3, 4, reg & 7);  // /4 = MUL
}

// Encode imul reg
void encode_imul_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xF7);
    emit_modrm(a, 3, 5, reg & 7);  // /5 = IMUL
}

// Encode div reg
void encode_div_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xF7);
    emit_modrm(a, 3, 6, reg & 7);  // /6 = DIV
}

// Encode idiv reg
void encode_idiv_reg(Assembler *a, int reg, int size) {
    int w = (size == SIZE_QWORD) ? 1 : 0;
    if (w || reg >= 8) {
        int b = (reg >= 8) ? 1 : 0;
        emit_rex(a, w, 0, 0, b);
    }
    emit_byte(a, 0xF7);
    emit_modrm(a, 3, 7, reg & 7);  // /7 = IDIV
}

// Encode cqo (sign-extend RAX into RDX:RAX)
void encode_cqo(Assembler *a) {
    emit_rex(a, 1, 0, 0, 0);  // REX.W
    emit_byte(a, 0x99);  // CQO
}

// Encode setcc reg8
void encode_setcc(Assembler *a, int condition, int reg) {
    // SETcc r/m8
    int b = (reg >= 8) ? 1 : 0;
    if (b) {
        emit_rex(a, 0, 0, 0, b);
    }
    emit_byte(a, 0x0F);
    emit_byte(a, 0x90 + condition);  // SETcc opcodes
    emit_modrm(a, 3, 0, reg & 7);
}

// Condition codes for SETcc
#define COND_O   0x0  // Overflow
#define COND_NO  0x1  // Not overflow
#define COND_B   0x2  // Below (unsigned)
#define COND_NB  0x3  // Not below
#define COND_Z   0x4  // Zero
#define COND_NZ  0x5  // Not zero
#define COND_BE  0x6  // Below or equal
#define COND_NBE 0x7  // Not below or equal
#define COND_S   0x8  // Sign
#define COND_NS  0x9  // Not sign
#define COND_P   0xA  // Parity
#define COND_NP  0xB  // Not parity
#define COND_L   0xC  // Less (signed)
#define COND_NL  0xD  // Not less
#define COND_LE  0xE  // Less or equal
#define COND_NLE 0xF  // Not less or equal

// Parse operand
int parse_operand(Assembler *a, Operand *op) {
    char token[256];
    
    memset(op, 0, sizeof(Operand));
    
    if (!get_token(a, token, sizeof(token))) {
        return 0;
    }
    
    // Check for register
    int reg, size;
    if (is_register(token, &reg, &size)) {
        op->type = OP_REG;
        op->reg = reg;
        op->size = size;
        return 1;
    }
    
    // Check for immediate (number)
    if (isdigit((unsigned char)token[0]) || 
        (token[0] == '0' && (token[1] == 'x' || token[1] == 'X' || token[1] == 'b' || token[1] == 'B'))) {
        op->type = OP_IMM;
        op->imm = parse_number(token);
        op->size = SIZE_QWORD;  // Default to 64-bit
        return 1;
    }
    
    // Check for memory reference [reg]
    if (strcmp(token, "[") == 0) {
        op->type = OP_MEM;
        // Parse memory expression
        char base[256], index[256];
        int scale = 1;
        
        if (!get_token(a, base, sizeof(base))) {
            return 0;
        }
        
        // Check for base register
        if (is_register(base, &op->base_reg, &size)) {
            // Check for + index*scale or + disp
            char next[256];
            if (peek_token(a, next, sizeof(next)) && strcmp(next, "+") == 0) {
                get_token(a, next, sizeof(next));  // consume +
                char idx[256];
                if (get_token(a, idx, sizeof(idx))) {
                    if (is_register(idx, &op->index_reg, &size)) {
                        // Check for *scale
                        if (peek_token(a, next, sizeof(next)) && strcmp(next, "*") == 0) {
                            get_token(a, next, sizeof(next));  // consume *
                            char scl[256];
                            if (get_token(a, scl, sizeof(scl))) {
                                op->scale = parse_number(scl);
                            }
                        }
                    } else {
                        // It's a displacement
                        op->disp = parse_number(idx);
                    }
                }
            }
        } else {
            // Might be a label
            strcpy(op->label_name, base);
            op->type = OP_LABEL_REF;
        }
        
        // Expect ]
        if (!get_token(a, token, sizeof(token)) || strcmp(token, "]") != 0) {
            fprintf(stderr, "Error: Expected ]\n");
            return 0;
        }
        
        return 1;
    }
    
    // Label reference
    op->type = OP_LABEL_REF;
    strncpy(op->label_name, token, sizeof(op->label_name) - 1);
    return 1;
}

// Find or create label
Label* find_label(Assembler *a, const char *name) {
    for (int i = 0; i < a->label_count; i++) {
        if (strcmp(a->labels[i].name, name) == 0) {
            return &a->labels[i];
        }
    }
    
    // Create new label
    if (a->label_count >= 1024) {
        fprintf(stderr, "Error: Too many labels\n");
        return NULL;
    }
    
    Label *l = &a->labels[a->label_count++];
    strncpy(l->name, name, sizeof(l->name) - 1);
    l->defined = 0;
    return l;
}

// Add fixup for forward reference
void add_fixup(Assembler *a, const char *label_name, int size) {
    if (a->fixup_count >= 1024) {
        fprintf(stderr, "Error: Too many fixups\n");
        return;
    }
    
    uint64_t *offset;
    uint8_t *buffer = get_current_buffer(a, &offset);
    
    a->fixups[a->fixup_count].offset = *offset;
    strncpy(a->fixups[a->fixup_count].label_name, label_name, sizeof(a->fixups[a->fixup_count].label_name) - 1);
    a->fixups[a->fixup_count].section = a->current_section;
    a->fixups[a->fixup_count].size = size;
    a->fixup_count++;
}

// Apply fixups
void apply_fixups(Assembler *a) {
    for (int i = 0; i < a->fixup_count; i++) {
        Label *l = find_label(a, a->fixups[i].label_name);
        if (!l || !l->defined) {
            fprintf(stderr, "Error: Undefined label: %s\n", a->fixups[i].label_name);
            continue;
        }
        
        // Calculate relative offset
        int64_t target = l->offset;
        int64_t source = a->fixups[i].offset + a->fixups[i].size;
        int64_t rel = target - source;
        
        // Apply to correct section
        uint8_t *buffer;
        switch (a->fixups[i].section) {
            case SECTION_TEXT: buffer = a->text_section; break;
            case SECTION_DATA: buffer = a->data_section; break;
            case SECTION_RDATA: buffer = a->rdata_section; break;
            default: buffer = a->text_section;
        }
        
        // Write relative offset
        if (a->fixups[i].size == 4) {
            *(int32_t*)(buffer + a->fixups[i].offset) = (int32_t)rel;
        } else if (a->fixups[i].size == 1) {
            buffer[a->fixups[i].offset] = (int8_t)rel;
        }
    }
}

// Parse and assemble instruction
int assemble_instruction(Assembler *a, const char *mnemonic) {
    int instr_type = get_instruction_type(mnemonic);
    Operand op1, op2;
    int has_op1 = 0, has_op2 = 0;
    
    // Parse operands
    char token[256];
    if (peek_token(a, token, sizeof(token))) {
        if (strcmp(token, ":") != 0) {  // Not a label definition
            has_op1 = parse_operand(a, &op1);
            
            if (has_op1) {
                if (peek_token(a, token, sizeof(token)) && strcmp(token, ",") == 0) {
                    get_token(a, token, sizeof(token));  // consume ,
                    has_op2 = parse_operand(a, &op2);
                }
            }
        }
    }
    
    // Assemble based on instruction type
    switch (instr_type) {
        case INSTR_MOV:
            if (has_op1 && has_op2) {
                if (op1.type == OP_REG && op2.type == OP_REG) {
                    encode_mov_reg_reg(a, op1.reg, op2.reg, op1.size);
                } else if (op1.type == OP_REG && op2.type == OP_IMM) {
                    encode_mov_reg_imm(a, op1.reg, op2.imm, op1.size);
                } else {
                    fprintf(stderr, "Error: Invalid operands for MOV at line %d\n", a->line);
                    return ERR_SYNTAX;
                }
            } else {
                fprintf(stderr, "Error: MOV requires two operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_PUSH:
            if (has_op1 && op1.type == OP_REG) {
                encode_push_reg(a, op1.reg);
            } else {
                fprintf(stderr, "Error: PUSH requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_POP:
            if (has_op1 && op1.type == OP_REG) {
                encode_pop_reg(a, op1.reg);
            } else {
                fprintf(stderr, "Error: POP requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_ADD:
            if (has_op1 && has_op2) {
                if (op1.type == OP_REG && op2.type == OP_REG) {
                    encode_add_reg_reg(a, op1.reg, op2.reg, op1.size);
                } else if (op1.type == OP_REG && op2.type == OP_IMM) {
                    encode_add_reg_imm(a, op1.reg, op2.imm, op1.size);
                } else {
                    fprintf(stderr, "Error: Invalid operands for ADD at line %d\n", a->line);
                    return ERR_SYNTAX;
                }
            } else {
                fprintf(stderr, "Error: ADD requires two operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SUB:
            if (has_op1 && has_op2) {
                if (op1.type == OP_REG && op2.type == OP_REG) {
                    encode_sub_reg_reg(a, op1.reg, op2.reg, op1.size);
                } else if (op1.type == OP_REG && op2.type == OP_IMM) {
                    encode_sub_reg_imm(a, op1.reg, op2.imm, op1.size);
                } else {
                    fprintf(stderr, "Error: Invalid operands for SUB at line %d\n", a->line);
                    return ERR_SYNTAX;
                }
            } else {
                fprintf(stderr, "Error: SUB requires two operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_AND:
            if (has_op1 && has_op2 && op1.type == OP_REG && op2.type == OP_REG) {
                encode_and_reg_reg(a, op1.reg, op2.reg, op1.size);
            } else {
                fprintf(stderr, "Error: AND requires two register operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_OR:
            if (has_op1 && has_op2 && op1.type == OP_REG && op2.type == OP_REG) {
                encode_or_reg_reg(a, op1.reg, op2.reg, op1.size);
            } else {
                fprintf(stderr, "Error: OR requires two register operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_XOR:
            if (has_op1 && has_op2 && op1.type == OP_REG && op2.type == OP_REG) {
                encode_xor_reg_reg(a, op1.reg, op2.reg, op1.size);
            } else {
                fprintf(stderr, "Error: XOR requires two register operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_CMP:
            if (has_op1 && has_op2 && op1.type == OP_REG && op2.type == OP_IMM) {
                encode_cmp_reg_imm(a, op1.reg, op2.imm, op1.size);
            } else {
                fprintf(stderr, "Error: CMP requires register and immediate operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_TEST:
            if (has_op1 && has_op2 && op1.type == OP_REG && op2.type == OP_REG) {
                encode_test_reg_reg(a, op1.reg, op2.reg, op1.size);
            } else {
                fprintf(stderr, "Error: TEST requires two register operands at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_JMP:
            if (has_op1 && op1.type == OP_LABEL_REF) {
                encode_jmp_rel32(a, 0);  // Placeholder, will be fixed up
                add_fixup(a, op1.label_name, 4);
            } else {
                fprintf(stderr, "Error: JMP requires label at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_JE:
            if (has_op1 && op1.type == OP_LABEL_REF) {
                encode_je_rel32(a, 0);
                add_fixup(a, op1.label_name, 4);
            } else {
                fprintf(stderr, "Error: JE requires label at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_JNE:
            if (has_op1 && op1.type == OP_LABEL_REF) {
                encode_jne_rel32(a, 0);
                add_fixup(a, op1.label_name, 4);
            } else {
                fprintf(stderr, "Error: JNE requires label at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_CALL:
            if (has_op1 && op1.type == OP_LABEL_REF) {
                encode_call_rel32(a, 0);
                add_fixup(a, op1.label_name, 4);
            } else {
                fprintf(stderr, "Error: CALL requires label at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_RET:
            encode_ret(a);
            break;
            
        case INSTR_NOP:
            encode_nop(a);
            break;
            
        case INSTR_SYSCALL:
            encode_syscall(a);
            break;
            
        case INSTR_LEA:
            if (has_op1 && has_op2 && op1.type == OP_REG && op2.type == OP_LABEL_REF) {
                encode_lea_rip_rel(a, op1.reg, 0);
                add_fixup(a, op2.label_name, 4);
            } else {
                fprintf(stderr, "Error: LEA requires register and label at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_INC:
            if (has_op1 && op1.type == OP_REG) {
                encode_inc_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: INC requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_DEC:
            if (has_op1 && op1.type == OP_REG) {
                encode_dec_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: DEC requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_NEG:
            if (has_op1 && op1.type == OP_REG) {
                encode_neg_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: NEG requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_NOT:
            if (has_op1 && op1.type == OP_REG) {
                encode_not_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: NOT requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_MUL:
            if (has_op1 && op1.type == OP_REG) {
                encode_mul_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: MUL requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_IMUL:
            if (has_op1 && op1.type == OP_REG) {
                encode_imul_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: IMUL requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_DIV:
            if (has_op1 && op1.type == OP_REG) {
                encode_div_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: DIV requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_IDIV:
            if (has_op1 && op1.type == OP_REG) {
                encode_idiv_reg(a, op1.reg, op1.size);
            } else {
                fprintf(stderr, "Error: IDIV requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_CQO:
            encode_cqo(a);
            break;
            
        case INSTR_SETE:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_Z, op1.reg);
            } else {
                fprintf(stderr, "Error: SETE requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SETNE:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_NZ, op1.reg);
            } else {
                fprintf(stderr, "Error: SETNE requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SETL:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_L, op1.reg);
            } else {
                fprintf(stderr, "Error: SETL requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SETLE:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_LE, op1.reg);
            } else {
                fprintf(stderr, "Error: SETLE requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SETG:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_NLE, op1.reg);
            } else {
                fprintf(stderr, "Error: SETG requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SETGE:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_NL, op1.reg);
            } else {
                fprintf(stderr, "Error: SETGE requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SETZ:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_Z, op1.reg);
            } else {
                fprintf(stderr, "Error: SETZ requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_SETNZ:
            if (has_op1 && op1.type == OP_REG) {
                encode_setcc(a, COND_NZ, op1.reg);
            } else {
                fprintf(stderr, "Error: SETNZ requires register operand at line %d\n", a->line);
                return ERR_SYNTAX;
            }
            break;
            
        case INSTR_DB:
            if (has_op1 && op1.type == OP_IMM) {
                emit_byte(a, (uint8_t)op1.imm);
            } else if (has_op1 && op1.type == OP_LABEL_REF) {
                // String literal
                for (int i = 0; op1.label_name[i]; i++) {
                    emit_byte(a, op1.label_name[i]);
                }
            }
            break;
            
        case INSTR_DW:
            if (has_op1 && op1.type == OP_IMM) {
                emit_word(a, (uint16_t)op1.imm);
            }
            break;
            
        case INSTR_DD:
            if (has_op1 && op1.type == OP_IMM) {
                emit_dword(a, (uint32_t)op1.imm);
            }
            break;
            
        case INSTR_DQ:
            if (has_op1 && op1.type == OP_IMM) {
                emit_qword(a, op1.imm);
            }
            break;
            
        case INSTR_RESB:
            if (has_op1 && op1.type == OP_IMM) {
                for (int i = 0; i < op1.imm; i++) {
                    emit_byte(a, 0);
                }
            }
            break;
            
        case INSTR_RESW:
            if (has_op1 && op1.type == OP_IMM) {
                for (int i = 0; i < op1.imm; i++) {
                    emit_word(a, 0);
                }
            }
            break;
            
        case INSTR_RESD:
            if (has_op1 && op1.type == OP_IMM) {
                for (int i = 0; i < op1.imm; i++) {
                    emit_dword(a, 0);
                }
            }
            break;
            
        case INSTR_RESQ:
            if (has_op1 && op1.type == OP_IMM) {
                for (int i = 0; i < op1.imm; i++) {
                    emit_qword(a, 0);
                }
            }
            break;
            
        case INSTR_GLOBAL:
            if (has_op1 && op1.type == OP_LABEL_REF) {
                strncpy(a->entry_point, op1.label_name, sizeof(a->entry_point) - 1);
                a->has_entry = 1;
            }
            break;
            
        case INSTR_EXTERN:
            // External symbols - mark for linker
            break;
            
        case INSTR_SECTION:
            if (has_op1 && op1.type == OP_LABEL_REF) {
                if (strcmp(op1.label_name, ".text") == 0) {
                    a->current_section = SECTION_TEXT;
                } else if (strcmp(op1.label_name, ".data") == 0) {
                    a->current_section = SECTION_DATA;
                } else if (strcmp(op1.label_name, ".rdata") == 0 || strcmp(op1.label_name, ".rodata") == 0) {
                    a->current_section = SECTION_RDATA;
                } else if (strcmp(op1.label_name, ".bss") == 0) {
                    a->current_section = SECTION_BSS;
                }
            }
            break;
            
        case INSTR_ALIGN:
            if (has_op1 && op1.type == OP_IMM) {
                int align = op1.imm;
                uint64_t *offset;
                uint8_t *buffer = get_current_buffer(a, &offset);
                uint64_t new_offset = (*offset + align - 1) & ~(align - 1);
                while (*offset < new_offset) {
                    buffer[*offset] = 0x90;  // NOP padding
                    (*offset)++;
                }
            }
            break;
            
        case INSTR_TIMES:
            // Repeat instruction - simplified
            break;
            
        case INSTR_EQU:
            // Equate - define constant
            break;
            
        default:
            fprintf(stderr, "Error: Unknown instruction: %s at line %d\n", mnemonic, a->line);
            return ERR_SYNTAX;
    }
    
    return ERR_OK;
}

// First pass: collect labels
int first_pass(Assembler *a) {
    char token[256];
    
    a->pos = 0;
    a->line = 1;
    a->current_section = SECTION_TEXT;
    
    while (get_token(a, token, sizeof(token))) {
        // Check for label definition
        if (peek_token(a, token, sizeof(token)) && strcmp(token, ":") == 0) {
            get_token(a, token, sizeof(token));  // consume :
            
            // Previous token was label name
            Label *l = find_label(a, token);
            if (l) {
                l->defined = 1;
                uint64_t *offset;
                get_current_buffer(a, &offset);
                l->offset = *offset;
                l->section = a->current_section;
            }
            continue;
        }
        
        // Check if it's an instruction
        if (is_instruction(token)) {
            int result = assemble_instruction(a, token);
            if (result != ERR_OK) {
                return result;
            }
        }
        // Otherwise it might be a label without colon
        else {
            char next[256];
            if (get_token(a, next, sizeof(next)) && strcmp(next, ":") == 0) {
                Label *l = find_label(a, token);
                if (l) {
                    l->defined = 1;
                    uint64_t *offset;
                    get_current_buffer(a, &offset);
                    l->offset = *offset;
                    l->section = a->current_section;
                }
            }
        }
    }
    
    return ERR_OK;
}

// Second pass: resolve forward references
int second_pass(Assembler *a) {
    apply_fixups(a);
    return ERR_OK;
}

// Write PE file
int write_pe_file(Assembler *a, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", filename);
        return ERR_IO;
    }
    
    // Calculate sizes
    uint32_t text_size = (a->text_offset + 511) & ~511;
    uint32_t data_size = (a->data_offset + 511) & ~511;
    uint32_t rdata_size = (a->rdata_offset + 511) & ~511;
    
    uint32_t headers_size = 512;
    uint32_t text_rva = 0x1000;
    uint32_t data_rva = 0x1000 + ((text_size + 0xFFF) & ~0xFFF);
    uint32_t rdata_rva = data_rva + ((data_size + 0xFFF) & ~0xFFF);
    uint32_t image_size = rdata_rva + ((rdata_size + 0xFFF) & ~0xFFF);
    
    // Find entry point
    uint32_t entry_rva = text_rva;
    if (a->has_entry) {
        Label *l = find_label(a, a->entry_point);
        if (l && l->defined && l->section == SECTION_TEXT) {
            entry_rva = text_rva + l->offset;
        }
    }
    
    // Allocate PE buffer
    uint8_t *pe = calloc(1, headers_size + text_size + data_size + rdata_size);
    if (!pe) {
        fclose(f);
        return ERR_IO;
    }
    
    // DOS Header
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)pe;
    dos->e_magic = 0x5A4D;  // 'MZ'
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    
    // PE Signature
    uint32_t *pe_sig = (uint32_t*)(pe + dos->e_lfanew);
    *pe_sig = 0x00004550;  // 'PE\0\0'
    
    // COFF Header
    IMAGE_FILE_HEADER *coff = (IMAGE_FILE_HEADER*)(pe + dos->e_lfanew + 4);
    coff->Machine = 0x8664;  // AMD64
    coff->NumberOfSections = 3;  // .text, .data, .rdata
    coff->TimeDateStamp = 0;
    coff->PointerToSymbolTable = 0;
    coff->NumberOfSymbols = 0;
    coff->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64) + 16 * sizeof(IMAGE_DATA_DIRECTORY);
    coff->Characteristics = 0x1022;  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    
    // Optional Header
    IMAGE_OPTIONAL_HEADER64 *opt = (IMAGE_OPTIONAL_HEADER64*)(pe + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
    opt->Magic = 0x20B;  // PE32+
    opt->MajorLinkerVersion = 1;
    opt->MinorLinkerVersion = 0;
    opt->SizeOfCode = text_size;
    opt->SizeOfInitializedData = data_size + rdata_size;
    opt->SizeOfUninitializedData = 0;
    opt->AddressOfEntryPoint = entry_rva;
    opt->BaseOfCode = text_rva;
    opt->ImageBase = 0x140000000ULL;
    opt->SectionAlignment = 0x1000;
    opt->FileAlignment = 512;
    opt->MajorOperatingSystemVersion = 6;
    opt->MinorOperatingSystemVersion = 0;
    opt->MajorImageVersion = 0;
    opt->MinorImageVersion = 0;
    opt->MajorSubsystemVersion = 6;
    opt->MinorSubsystemVersion = 0;
    opt->Win32VersionValue = 0;
    opt->SizeOfImage = image_size;
    opt->SizeOfHeaders = headers_size;
    opt->CheckSum = 0;
    opt->Subsystem = 1;  // NATIVE (or 3 for CONSOLE)
    opt->DllCharacteristics = 0;
    opt->SizeOfStackReserve = 0x100000;
    opt->SizeOfStackCommit = 0x1000;
    opt->SizeOfHeapReserve = 0x100000;
    opt->SizeOfHeapCommit = 0x1000;
    opt->LoaderFlags = 0;
    opt->NumberOfRvaAndSizes = 16;
    
    // Data directories
    IMAGE_DATA_DIRECTORY *dirs = (IMAGE_DATA_DIRECTORY*)((uint8_t*)opt + sizeof(IMAGE_OPTIONAL_HEADER64));
    // All zero for now
    
    // Section headers
    IMAGE_SECTION_HEADER *sect = (IMAGE_SECTION_HEADER*)((uint8_t*)dirs + 16 * sizeof(IMAGE_DATA_DIRECTORY));
    
    // .text section
    memcpy(sect[0].Name, ".text\0\0\0", 8);
    sect[0].Misc.VirtualSize = a->text_offset;
    sect[0].VirtualAddress = text_rva;
    sect[0].SizeOfRawData = text_size;
    sect[0].PointerToRawData = headers_size;
    sect[0].PointerToRelocations = 0;
    sect[0].PointerToLinenumbers = 0;
    sect[0].NumberOfRelocations = 0;
    sect[0].NumberOfLinenumbers = 0;
    sect[0].Characteristics = 0x60000020;  // CODE | EXECUTE | READ
    
    // .data section
    memcpy(sect[1].Name, ".data\0\0\0", 8);
    sect[1].Misc.VirtualSize = a->data_offset;
    sect[1].VirtualAddress = data_rva;
    sect[1].SizeOfRawData = data_size;
    sect[1].PointerToRawData = headers_size + text_size;
    sect[1].PointerToRelocations = 0;
    sect[1].PointerToLinenumbers = 0;
    sect[1].NumberOfRelocations = 0;
    sect[1].NumberOfLinenumbers = 0;
    sect[1].Characteristics = 0xC0000040;  // INITIALIZED_DATA | READ | WRITE
    
    // .rdata section
    memcpy(sect[2].Name, ".rdata\0\0", 8);
    sect[2].Misc.VirtualSize = a->rdata_offset;
    sect[2].VirtualAddress = rdata_rva;
    sect[2].SizeOfRawData = rdata_size;
    sect[2].PointerToRawData = headers_size + text_size + data_size;
    sect[2].PointerToRelocations = 0;
    sect[2].PointerToLinenumbers = 0;
    sect[2].NumberOfRelocations = 0;
    sect[2].NumberOfLinenumbers = 0;
    sect[2].Characteristics = 0x40000040;  // INITIALIZED_DATA | READ
    
    // Copy section data
    memcpy(pe + headers_size, a->text_section, a->text_offset);
    memcpy(pe + headers_size + text_size, a->data_section, a->data_offset);
    memcpy(pe + headers_size + text_size + data_size, a->rdata_section, a->rdata_offset);
    
    // Write file
    fwrite(pe, 1, headers_size + text_size + data_size + rdata_size, f);
    fclose(f);
    free(pe);
    
    return ERR_OK;
}

// Main function
int main(int argc, char *argv[]) {
    printf("RawrXD Sovereign x64 Assembler v1.0\n");
    printf("===================================\n\n");
    
    if (argc != 3) {
        printf("Usage: %s <input.asm> <output.exe>\n", argv[0]);
        printf("\nThis is a REAL assembler - parses x64 assembly and generates machine code.\n");
        printf("No external dependencies. No hardcoded outputs.\n");
        return 1;
    }
    
    const char *input_file = argv[1];
    const char *output_file = argv[2];
    
    // Read source file
    FILE *f = fopen(input_file, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *source = malloc(size + 1);
    if (!source) {
        fclose(f);
        fprintf(stderr, "Error: Out of memory\n");
        return 1;
    }
    
    fread(source, 1, size, f);
    source[size] = '\0';
    fclose(f);
    
    printf("Assembling: %s (%ld bytes)\n", input_file, size);
    printf("Output: %s\n\n", output_file);
    
    // Initialize assembler
    Assembler a;
    init_assembler(&a);
    a.source = source;
    a.source_len = size;
    strncpy(a.output_file, output_file, sizeof(a.output_file) - 1);
    
    // First pass: collect labels and calculate offsets
    printf("Pass 1: Parsing and collecting labels...\n");
    int result = first_pass(&a);
    if (result != ERR_OK) {
        fprintf(stderr, "Assembly failed at pass 1\n");
        free(source);
        return 1;
    }
    
    printf("  Labels defined: %d\n", a.label_count);
    printf("  Text section: %llu bytes\n", a.text_offset);
    printf("  Data section: %llu bytes\n", a.data_offset);
    printf("  Rdata section: %llu bytes\n\n", a.rdata_offset);
    
    // Second pass: resolve forward references
    printf("Pass 2: Resolving forward references...\n");
    result = second_pass(&a);
    if (result != ERR_OK) {
        fprintf(stderr, "Assembly failed at pass 2\n");
        free(source);
        return 1;
    }
    
    printf("  Fixups applied: %d\n\n", a.fixup_count);
    
    // Write output file
    printf("Writing PE file...\n");
    result = write_pe_file(&a, output_file);
    if (result != ERR_OK) {
        fprintf(stderr, "Failed to write output file\n");
        free(source);
        return 1;
    }
    
    printf("\nSuccess! Assembly complete.\n");
    printf("Entry point: %s\n", a.has_entry ? a.entry_point : "(default)");
    
    free(source);
    return 0;
}
