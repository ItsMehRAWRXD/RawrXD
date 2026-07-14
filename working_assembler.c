// Working x64 Assembler - No Dependencies
// Produces COFF object files

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_SYMBOLS 1024
#define MAX_SECTIONS 16
#define MAX_RELOCATIONS 4096

// COFF structures
#pragma pack(push, 1)

typedef struct {
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t sym_table_offset;
    uint32_t num_symbols;
    uint16_t opt_header_size;
    uint16_t characteristics;
} coff_header_t;

typedef struct {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_addr;
    uint32_t raw_data_size;
    uint32_t raw_data_offset;
    uint32_t relocations_offset;
    uint32_t line_numbers_offset;
    uint16_t num_relocations;
    uint16_t num_line_numbers;
    uint32_t characteristics;
} coff_section_header_t;

typedef struct {
    uint32_t virtual_addr;
    uint32_t symbol_index;
    uint16_t type;
} coff_relocation_t;

typedef struct {
    union {
        char short_name[8];
        struct {
            uint32_t zeroes;
            uint32_t offset;
        } long_name;
    } name;
    uint32_t value;
    int16_t section;
    uint16_t type;
    uint8_t storage_class;
    uint8_t num_aux;
} coff_symbol_t;

#pragma pack(pop)

// x64 machine type
#define IMAGE_FILE_MACHINE_AMD64 0x8664

// Section characteristics
#define IMAGE_SCN_CNT_CODE      0x00000020
#define IMAGE_SCN_CNT_DATA      0x00000040
#define IMAGE_SCN_ALIGN_16BYTES 0x00000500
#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define IMAGE_SCN_MEM_READ      0x40000000
#define IMAGE_SCN_MEM_WRITE     0x80000000

// Symbol storage classes
#define IMAGE_SYM_CLASS_EXTERNAL 2
#define IMAGE_SYM_CLASS_STATIC   3

// Relocation types
#define IMAGE_REL_AMD64_ADDR64 1
#define IMAGE_REL_AMD64_ADDR32 2
#define IMAGE_REL_AMD64_REL32  4

// Assembler state
typedef struct {
    uint8_t *code;
    size_t code_size;
    size_t code_capacity;
    
    coff_relocation_t relocs[MAX_RELOCATIONS];
    int num_relocs;
    
    char *symbol_names;
    size_t symbol_names_size;
    size_t symbol_names_capacity;
    
    int current_section;
} assembler_state_t;

// Simple instruction encoder
static void emit_byte(assembler_state_t *state, uint8_t byte) {
    if (state->code_size >= state->code_capacity) {
        state->code_capacity = state->code_capacity ? state->code_capacity * 2 : 1024;
        state->code = realloc(state->code, state->code_capacity);
    }
    state->code[state->code_size++] = byte;
}

static void emit_bytes(assembler_state_t *state, const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        emit_byte(state, bytes[i]);
    }
}

static void emit_u32(assembler_state_t *state, uint32_t val) {
    emit_byte(state, val & 0xFF);
    emit_byte(state, (val >> 8) & 0xFF);
    emit_byte(state, (val >> 16) & 0xFF);
    emit_byte(state, (val >> 24) & 0xFF);
}

static void emit_u64(assembler_state_t *state, uint64_t val) {
    for (int i = 0; i < 8; i++) {
        emit_byte(state, (val >> (i * 8)) & 0xFF);
    }
}

// Encode mov rax, imm64
static void emit_mov_rax_imm64(assembler_state_t *state, uint64_t imm) {
    emit_byte(state, 0x48);  // REX.W
    emit_byte(state, 0xB8);  // MOV r64, imm64
    emit_u64(state, imm);
}

// Encode mov rcx, imm64
static void emit_mov_rcx_imm64(assembler_state_t *state, uint64_t imm) {
    emit_byte(state, 0x48);  // REX.W
    emit_byte(state, 0xB9);  // MOV rcx, imm64
    emit_u64(state, imm);
}

// Encode mov rdx, imm64
static void emit_mov_rdx_imm64(assembler_state_t *state, uint64_t imm) {
    emit_byte(state, 0x48);  // REX.W
    emit_byte(state, 0xBA);  // MOV rdx, imm64
    emit_u64(state, imm);
}

// Encode mov r8, imm64
static void emit_mov_r8_imm64(assembler_state_t *state, uint64_t imm) {
    emit_byte(state, 0x49);  // REX.W + REX.B
    emit_byte(state, 0xB8);  // MOV r8, imm64
    emit_u64(state, imm);
}

// Encode mov r9, imm64
static void emit_mov_r9_imm64(assembler_state_t *state, uint64_t imm) {
    emit_byte(state, 0x49);  // REX.W + REX.B
    emit_byte(state, 0xB9);  // MOV r9, imm64
    emit_u64(state, imm);
}

// Encode sub rsp, imm8
static void emit_sub_rsp_imm8(assembler_state_t *state, uint8_t imm) {
    emit_byte(state, 0x48);  // REX.W
    emit_byte(state, 0x83);  // SUB r/m64, imm8
    emit_byte(state, 0xEC);  // ModRM: 11 101 100 (RSP)
    emit_byte(state, imm);
}

// Encode add rsp, imm8
static void emit_add_rsp_imm8(assembler_state_t *state, uint8_t imm) {
    emit_byte(state, 0x48);  // REX.W
    emit_byte(state, 0x83);  // ADD r/m64, imm8
    emit_byte(state, 0xC4);  // ModRM: 11 000 100 (RSP)
    emit_byte(state, imm);
}

// Encode call rel32
static void emit_call_rel32(assembler_state_t *state, int32_t rel) {
    emit_byte(state, 0xE8);  // CALL rel32
    emit_u32(state, (uint32_t)rel);
}

// Encode ret
static void emit_ret(assembler_state_t *state) {
    emit_byte(state, 0xC3);  // RET
}

// Encode xor eax, eax
static void emit_xor_eax_eax(assembler_state_t *state) {
    emit_byte(state, 0x31);  // XOR r/m32, r32
    emit_byte(state, 0xC0);  // ModRM: 11 000 000 (EAX, EAX)
}

// Encode mov eax, imm32
static void emit_mov_eax_imm32(assembler_state_t *state, uint32_t imm) {
    emit_byte(state, 0xB8);  // MOV r32, imm32
    emit_u32(state, imm);
}

// Parse simple assembly line
// Returns: 0 = success, -1 = error, 1 = end of input
static int parse_line(const char *line, assembler_state_t *state) {
    char opcode[32] = {0};
    char operand1[64] = {0};
    char operand2[64] = {0};
    
    // Skip whitespace and comments
    while (*line == ' ' || *line == '\t') line++;
    if (*line == ';' || *line == '\0' || *line == '\n' || *line == '\r') {
        return 0;  // Empty line or comment
    }
    
    // Parse opcode
    int i = 0;
    while (*line && *line != ' ' && *line != '\t' && *line != '\n' && *line != '\r' && i < 31) {
        opcode[i++] = *line++;
    }
    opcode[i] = '\0';
    
    // Skip whitespace
    while (*line == ' ' || *line == '\t') line++;
    
    // Parse operand1
    i = 0;
    while (*line && *line != ',' && *line != '\n' && *line != '\r' && i < 63) {
        operand1[i++] = *line++;
    }
    operand1[i] = '\0';
    
    // Skip comma and whitespace
    if (*line == ',') line++;
    while (*line == ' ' || *line == '\t') line++;
    
    // Parse operand2
    i = 0;
    while (*line && *line != '\n' && *line != '\r' && i < 63) {
        operand2[i++] = *line++;
    }
    operand2[i] = '\0';
    
    // Trim trailing whitespace from operands
    char *p = operand1 + strlen(operand1) - 1;
    while (p >= operand1 && (*p == ' ' || *p == '\t')) *p-- = '\0';
    p = operand2 + strlen(operand2) - 1;
    while (p >= operand2 && (*p == ' ' || *p == '\t')) *p-- = '\0';
    
    // Process opcode
    if (strcmp(opcode, "ret") == 0) {
        emit_ret(state);
    }
    else if (strcmp(opcode, "xor") == 0 && strcmp(operand1, "eax") == 0 && strcmp(operand2, "eax") == 0) {
        emit_xor_eax_eax(state);
    }
    else if (strcmp(opcode, "mov") == 0) {
        if (strncmp(operand1, "eax", 3) == 0) {
            // mov eax, imm
            uint32_t imm = (uint32_t)strtoull(operand2, NULL, 0);
            emit_mov_eax_imm32(state, imm);
        }
        else if (strncmp(operand1, "rax", 3) == 0) {
            // mov rax, imm
            uint64_t imm = strtoull(operand2, NULL, 0);
            emit_mov_rax_imm64(state, imm);
        }
        else if (strncmp(operand1, "rcx", 3) == 0) {
            uint64_t imm = strtoull(operand2, NULL, 0);
            emit_mov_rcx_imm64(state, imm);
        }
        else if (strncmp(operand1, "rdx", 3) == 0) {
            uint64_t imm = strtoull(operand2, NULL, 0);
            emit_mov_rdx_imm64(state, imm);
        }
        else if (strncmp(operand1, "r8", 2) == 0) {
            uint64_t imm = strtoull(operand2, NULL, 0);
            emit_mov_r8_imm64(state, imm);
        }
        else if (strncmp(operand1, "r9", 2) == 0) {
            uint64_t imm = strtoull(operand2, NULL, 0);
            emit_mov_r9_imm64(state, imm);
        }
    }
    else if (strcmp(opcode, "sub") == 0 && strcmp(operand1, "rsp") == 0) {
        uint8_t imm = (uint8_t)strtoull(operand2, NULL, 0);
        emit_sub_rsp_imm8(state, imm);
    }
    else if (strcmp(opcode, "add") == 0 && strcmp(operand1, "rsp") == 0) {
        uint8_t imm = (uint8_t)strtoull(operand2, NULL, 0);
        emit_add_rsp_imm8(state, imm);
    }
    else if (strcmp(opcode, "call") == 0) {
        // Placeholder for call - emit call with 0 offset
        // Real implementation would need symbol resolution
        emit_call_rel32(state, 0);
        // Add relocation
        if (state->num_relocs < MAX_RELOCATIONS) {
            state->relocs[state->num_relocs].virtual_addr = (uint32_t)(state->code_size - 4);
            state->relocs[state->num_relocs].symbol_index = 0;  // Will be resolved later
            state->relocs[state->num_relocs].type = IMAGE_REL_AMD64_REL32;
            state->num_relocs++;
        }
    }
    else {
        printf("Warning: Unknown opcode '%s'\n", opcode);
    }
    
    return 0;
}

// Write COFF object file
static int write_coff(const char *filename, assembler_state_t *state) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open output file");
        return -1;
    }
    
    // Calculate offsets
    size_t header_size = sizeof(coff_header_t);
    size_t section_header_size = sizeof(coff_section_header_t);
    size_t code_offset = header_size + section_header_size;
    size_t reloc_offset = code_offset + state->code_size;
    // Align to 4 bytes
    if (reloc_offset % 4 != 0) {
        reloc_offset += 4 - (reloc_offset % 4);
    }
    size_t symbol_offset = reloc_offset + (state->num_relocs * sizeof(coff_relocation_t));
    
    // Write COFF header
    coff_header_t header = {0};
    header.machine = IMAGE_FILE_MACHINE_AMD64;
    header.num_sections = 1;
    header.timestamp = 0;
    header.sym_table_offset = (uint32_t)symbol_offset;
    header.num_symbols = 2;  // One for section, one for entry point
    header.opt_header_size = 0;
    header.characteristics = 0;
    
    fwrite(&header, sizeof(header), 1, fp);
    
    // Write section header
    coff_section_header_t section = {0};
    memcpy(section.name, ".text\0\0\0", 8);
    section.virtual_size = 0;
    section.virtual_addr = 0;
    section.raw_data_size = (uint32_t)state->code_size;
    section.raw_data_offset = (uint32_t)code_offset;
    section.relocations_offset = state->num_relocs > 0 ? (uint32_t)reloc_offset : 0;
    section.line_numbers_offset = 0;
    section.num_relocations = (uint16_t)state->num_relocs;
    section.num_line_numbers = 0;
    section.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | 
                              IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    
    fwrite(&section, sizeof(section), 1, fp);
    
    // Write code
    fwrite(state->code, 1, state->code_size, fp);
    
    // Pad to alignment
    size_t padding = reloc_offset - code_offset - state->code_size;
    for (size_t i = 0; i < padding; i++) {
        fputc(0, fp);
    }
    
    // Write relocations
    for (int i = 0; i < state->num_relocs; i++) {
        fwrite(&state->relocs[i], sizeof(coff_relocation_t), 1, fp);
    }
    
    // Write symbols
    // Section symbol
    coff_symbol_t section_sym = {0};
    memcpy(section_sym.name.short_name, ".text\0\0\0", 8);
    section_sym.value = 0;
    section_sym.section = 1;  // Section 1-based
    section_sym.type = 0;
    section_sym.storage_class = IMAGE_SYM_CLASS_STATIC;
    section_sym.num_aux = 0;
    fwrite(&section_sym, sizeof(section_sym), 1, fp);
    
    // Entry point symbol
    coff_symbol_t entry_sym = {0};
    memcpy(entry_sym.name.short_name, "_start\0\0", 8);
    entry_sym.value = 0;
    entry_sym.section = 1;
    entry_sym.type = 0x20;  // Function
    entry_sym.storage_class = IMAGE_SYM_CLASS_EXTERNAL;
    entry_sym.num_aux = 0;
    fwrite(&entry_sym, sizeof(entry_sym), 1, fp);
    
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Working x64 Assembler - No Dependencies\n");
        printf("Usage: %s <input.asm> <output.obj>\n", argv[0]);
        printf("\nSupported instructions:\n");
        printf("  mov rax, imm64\n");
        printf("  mov rcx/rdx/r8/r9, imm64\n");
        printf("  mov eax, imm32\n");
        printf("  xor eax, eax\n");
        printf("  sub/add rsp, imm8\n");
        printf("  call symbol\n");
        printf("  ret\n");
        return 1;
    }
    
    assembler_state_t state = {0};
    
    // Read input file
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Failed to open input file");
        return 1;
    }
    
    char line[256];
    int line_num = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        if (parse_line(line, &state) < 0) {
            fprintf(stderr, "Error on line %d\n", line_num);
            fclose(fp);
            free(state.code);
            return 1;
        }
    }
    fclose(fp);
    
    printf("Assembled %zu bytes\n", state.code_size);
    printf("Generated %d relocations\n", state.num_relocs);
    
    // Write output
    if (write_coff(argv[2], &state) < 0) {
        free(state.code);
        return 1;
    }
    
    printf("Output written to: %s\n", argv[2]);
    
    free(state.code);
    return 0;
}
