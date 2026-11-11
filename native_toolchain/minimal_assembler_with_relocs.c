/*
 * Native Assembler with RELOCATION support
 * Can assemble x64 instructions and generate COFF with relocations for externals
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

// COFF structures
#pragma pack(push, 1)
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HEADER;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECTION_HEADER;

typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } LongName;
    } Name;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} SYMBOL_TABLE_ENTRY;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} RELOCATION_ENTRY;
#pragma pack(pop)

// Relocation types
#define IMAGE_REL_AMD64_REL32  0x0004
#define IMAGE_REL_AMD64_ADDR64 0x0001  // For data addresses

// Storage classes
#define IMAGE_SYM_CLASS_EXTERNAL 2
#define IMAGE_SYM_CLASS_STATIC   3

// Section tracking
#define MAX_SECTIONS 2
#define SECTION_TEXT 0
#define SECTION_DATA 1

int current_section = SECTION_TEXT;
uint32_t data_section_size = 0;
uint8_t data_section[4096];

// Symbol table limit
#define MAX_SYMBOLS 256
#define MAX_RELOCATIONS 64

// Symbol table entry
typedef struct {
    char name[256];
    int is_external;
    int is_data;
    int symbol_index;
    uint32_t value;  // Offset within section (for labels)
} SYMBOL;

SYMBOL symbol_table[MAX_SYMBOLS];
int num_symbols = 0;
RELOCATION_ENTRY relocations[MAX_RELOCATIONS];
int num_relocations = 0;

// Check if a token is an external symbol (starts with uppercase or contains non-register chars)
int is_external_symbol(const char *token) {
    if (!token || !*token) return 0;
    
    // Known external functions
    if (strcmp(token, "ExitProcess") == 0) return 1;
    if (strcmp(token, "GetStdHandle") == 0) return 1;
    if (strcmp(token, "WriteFile") == 0) return 1;
    if (strcmp(token, "CreateWindowExA") == 0) return 1;
    if (strcmp(token, "GetMessageA") == 0) return 1;
    if (strcmp(token, "DispatchMessageA") == 0) return 1;
    if (strcmp(token, "PostQuitMessage") == 0) return 1;
    if (strcmp(token, "VirtualAlloc") == 0) return 1;
    if (strcmp(token, "VirtualFree") == 0) return 1;
    
    // Starts with uppercase = likely external
    if (isupper(token[0])) return 1;
    
    return 0;
}

// Add symbol to table
int add_symbol(const char *name, int is_external, int is_data, uint32_t value) {
    // Check if already exists
    for (int i = 0; i < num_symbols; i++) {
        if (strcmp(symbol_table[i].name, name) == 0) {
            // Update value if it's a label being defined
            if (!is_external && value != 0) {
                symbol_table[i].value = value;
            }
            return symbol_table[i].symbol_index;
        }
    }
    
    if (num_symbols >= MAX_SYMBOLS) return -1;
    
    strcpy(symbol_table[num_symbols].name, name);
    symbol_table[num_symbols].is_external = is_external;
    symbol_table[num_symbols].is_data = is_data;
    symbol_table[num_symbols].symbol_index = num_symbols;
    symbol_table[num_symbols].value = value;
    
    printf("  [SYMBOL] Added: %s (external=%d, data=%d, index=%d, value=%u)\n", 
           name, is_external, is_data, num_symbols, value);
    
    return num_symbols++;
}

// Add relocation
void add_relocation(uint32_t offset, int symbol_index) {
    if (num_relocations >= MAX_RELOCATIONS) return;
    
    relocations[num_relocations].VirtualAddress = offset;
    relocations[num_relocations].SymbolTableIndex = symbol_index;
    relocations[num_relocations].Type = IMAGE_REL_AMD64_REL32;
    
    printf("  [RELOC] Added at offset 0x%X for symbol %d\n", offset, symbol_index);
    
    num_relocations++;
}

// x64 instruction encoding
typedef struct {
    char *mnemonic;
    uint8_t opcode;
    uint8_t has_modrm;
    uint8_t reg_field;
} INSTRUCTION;

INSTRUCTION instructions[] = {
    {"nop", 0x90, 0, 0},
    {"ret", 0xC3, 0, 0},
    {"call", 0xE8, 0, 0},
    {"jmp", 0xE9, 0, 0},
    {"mov", 0x89, 1, 0},
    {"add", 0x01, 1, 0},
    {"sub", 0x29, 1, 0},
    {"push", 0x50, 0, 0},
    {"pop", 0x58, 0, 0},
    {"test", 0x85, 1, 0},   // test r/m64, r64
    {"cmp", 0x39, 1, 0},    // cmp r/m64, r64
    {"je", 0x74, 0, 0},     // je rel8
    {"jne", 0x75, 0, 0},    // jne rel8
    {"jz", 0x74, 0, 0},     // jz rel8 (same as je)
    {"jnz", 0x75, 0, 0},    // jnz rel8 (same as jne)
    {"lea", 0x8D, 1, 0},    // lea r64, m
    {"inc", 0xFF, 0, 1},    // inc r/m64 (opcode extension 0)
    {"dec", 0xFF, 0, 2},    // dec r/m64 (opcode extension 1)
    {NULL, 0, 0, 0}
};

char *registers[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};

int get_register_index(char *reg) {
    for (int i = 0; i < 16; i++) {
        if (_stricmp(reg, registers[i]) == 0) return i;
    }
    return -1;
}

int assemble_instruction(char *line, uint8_t *code, int *code_size, uint32_t code_offset) {
    char mnemonic[32] = {0};
    char op1[64] = {0};
    char op2[64] = {0};
    
    // Parse line
    sscanf(line, "%s %[^,], %s", mnemonic, op1, op2);
    
    // Trim whitespace from operands
    char *p = op1;
    while (*p == ' ' || *p == '\t') p++;
    if (p != op1) memmove(op1, p, strlen(p) + 1);
    
    // Find instruction
    INSTRUCTION *inst = NULL;
    for (int i = 0; instructions[i].mnemonic; i++) {
        if (_stricmp(mnemonic, instructions[i].mnemonic) == 0) {
            inst = &instructions[i];
            break;
        }
    }
    
    if (!inst) {
        printf("  [WARN] Unknown instruction: %s\n", mnemonic);
        return 0;
    }
    
    *code_size = 0;
    int reg1 = get_register_index(op1);
    int reg2 = get_register_index(op2);
    
    // Handle call to external symbol (indirect through IAT)
    if (strcmp(inst->mnemonic, "call") == 0 && op1[0] != '\0' && reg1 < 0) {
        // This is a call to an external symbol
        if (is_external_symbol(op1)) {
            int sym_idx = add_symbol(op1, 1, 0, 0);
            
            // Emit call qword ptr [rip+offset] (6 bytes: FF 15 + 4-byte displacement)
            // This is the correct way to call imports on x64 Windows
            // FF 15 xx xx xx xx = call qword ptr [rip+rel32]
            // Offset 0: FF (opcode)
            // Offset 1: 15 (ModR/M)
            // Offset 2-5: displacement (rel32)
            int disp_offset = *code_size + 2;  // Where displacement starts
            code[(*code_size)++] = 0xFF;
            code[(*code_size)++] = 0x15; // ModR/M: 00 000 101 = disp32, call
            code[(*code_size)++] = 0x00; // Placeholder for displacement
            code[(*code_size)++] = 0x00;
            code[(*code_size)++] = 0x00;
            code[(*code_size)++] = 0x00;
            
            // Add relocation at the displacement field offset
            // Type should be IMAGE_REL_AMD64_REL32 for RIP-relative addressing
            add_relocation(code_offset + disp_offset, sym_idx);
            
            printf("  [ASM] call %s (external, indirect via IAT)\n", op1);
            return 1;
        } else {
            // Internal symbol - use direct call E8 with relocation
            int sym_idx = add_symbol(op1, 0, 0, 0);
            
            // Emit call rel32 (5 bytes: E8 + 4-byte displacement)
            int disp_offset = *code_size + 1;  // Where displacement starts (after E8)
            code[(*code_size)++] = 0xE8;
            code[(*code_size)++] = 0x00; // Placeholder for displacement
            code[(*code_size)++] = 0x00;
            code[(*code_size)++] = 0x00;
            code[(*code_size)++] = 0x00;
            
            // Add relocation for the displacement
            add_relocation(code_offset + disp_offset, sym_idx);
            
            printf("  [ASM] call %s (internal, direct)\n", op1);
            return 1;
        }
    }
    
    // Handle sub reg, imm (like sub rsp, 40)
    if (strcmp(inst->mnemonic, "sub") == 0 && reg1 >= 0 && op2[0] != '\0') {
        // Check if op2 is an immediate
        char *endptr;
        long imm = strtol(op2, &endptr, 0);
        if (*endptr == '\0') {
            // sub r64, imm8
            code[(*code_size)++] = 0x48;
            if (reg1 >= 8) code[0] = 0x49;
            code[(*code_size)++] = 0x83; // sub r/m64, imm8
            code[(*code_size)++] = 0xE8 | (reg1 & 0x07); // /5 sub, mod=11, reg=101
            code[(*code_size)++] = (uint8_t)(imm & 0xFF);
            return 1;
        }
    }
    
    // Handle add reg, imm (like add rsp, 40)
    if (strcmp(inst->mnemonic, "add") == 0 && reg1 >= 0 && op2[0] != '\0') {
        char *endptr;
        long imm = strtol(op2, &endptr, 0);
        if (*endptr == '\0') {
            code[(*code_size)++] = 0x48;
            if (reg1 >= 8) code[0] = 0x49;
            code[(*code_size)++] = 0x83; // add r/m64, imm8
            code[(*code_size)++] = 0xC0 | (reg1 & 0x07); // /0 add, mod=11
            code[(*code_size)++] = (uint8_t)(imm & 0xFF);
            return 1;
        }
    }
    
    // Handle test reg, reg
    if (strcmp(inst->mnemonic, "test") == 0 && reg1 >= 0 && reg2 >= 0) {
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8 || reg2 >= 8) {
            code[0] = 0x48 | (reg1 >= 8 ? 0x01 : 0) | (reg2 >= 8 ? 0x04 : 0);
        }
        code[(*code_size)++] = 0x85; // test r/m64, r64
        code[(*code_size)++] = 0xC0 | ((reg2 & 0x07) << 3) | (reg1 & 0x07);
        return 1;
    }
    
    // Handle cmp reg, reg
    if (strcmp(inst->mnemonic, "cmp") == 0 && reg1 >= 0 && reg2 >= 0) {
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8 || reg2 >= 8) {
            code[0] = 0x48 | (reg1 >= 8 ? 0x01 : 0) | (reg2 >= 8 ? 0x04 : 0);
        }
        code[(*code_size)++] = 0x39; // cmp r/m64, r64
        code[(*code_size)++] = 0xC0 | ((reg2 & 0x07) << 3) | (reg1 & 0x07);
        return 1;
    }
    
    // Handle conditional jumps (je, jne, jz, jnz) - rel8
    if ((strcmp(inst->mnemonic, "je") == 0 || strcmp(inst->mnemonic, "jne") == 0 ||
         strcmp(inst->mnemonic, "jz") == 0 || strcmp(inst->mnemonic, "jnz") == 0) && op1[0] != '\0') {
        // For now, emit placeholder jump that will be fixed up later
        // In a real implementation, we'd need a label table
        code[(*code_size)++] = inst->opcode;
        code[(*code_size)++] = 0x00; // Placeholder offset
        printf("  [ASM] %s (placeholder)\n", inst->mnemonic);
        return 1;
    }
    
    // Handle jmp label - rel32
    if (strcmp(inst->mnemonic, "jmp") == 0 && op1[0] != '\0' && reg1 < 0) {
        // Add target as symbol
        int sym_idx = add_symbol(op1, 0, 0, 0);
        // jmp rel32 (5 bytes: E9 + 4-byte displacement)
        int disp_offset = *code_size + 1;  // Where displacement starts (after E9)
        code[(*code_size)++] = 0xE9;
        code[(*code_size)++] = 0x00; // Placeholder for displacement
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        // Add relocation for the displacement
        add_relocation(code_offset + disp_offset, sym_idx);
        printf("  [ASM] jmp %s (with relocation)\n", op1);
        return 1;
    }
    
    // Handle mov reg, [symbol] - RIP-relative load
    if (strcmp(inst->mnemonic, "mov") == 0 && reg1 >= 0 && op2[0] == '[') {
        // Extract symbol name from [symbol]
        char *sym_name = op2 + 1;
        char *end = strchr(sym_name, ']');
        if (end) *end = '\0';
        
        int sym_idx = add_symbol(sym_name, 0, 1, 0); // Internal data symbol
        
        // mov r64, [rip+disp32]
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8) code[0] = 0x49;
        code[(*code_size)++] = 0x8B; // mov r64, r/m64
        code[(*code_size)++] = 0x05 | ((reg1 & 0x07) << 3); // mod=00, reg=dst, rm=101 (RIP-relative)
        
        // 4-byte displacement (placeholder)
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        
        // Add relocation for RIP-relative addressing
        add_relocation(code_offset + 3, sym_idx);
        
        printf("  [ASM] mov %s, [%s] (RIP-relative)\n", op1, sym_name);
        return 1;
    }
    
    // Handle mov [symbol], reg - RIP-relative store
    if (strcmp(inst->mnemonic, "mov") == 0 && op1[0] == '[' && reg2 >= 0) {
        char *sym_name = op1 + 1;
        char *end = strchr(sym_name, ']');
        if (end) *end = '\0';
        
        int sym_idx = add_symbol(sym_name, 0, 1, 0);
        
        // mov [rip+disp32], r64
        code[(*code_size)++] = 0x48;
        if (reg2 >= 8) code[0] = 0x49;
        code[(*code_size)++] = 0x89; // mov r/m64, r64
        code[(*code_size)++] = 0x05 | ((reg2 & 0x07) << 3);
        
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        
        add_relocation(code_offset + 3, sym_idx);
        
        printf("  [ASM] mov [%s], %s (RIP-relative)\n", sym_name, op2);
        return 1;
    }
    
    // Handle lea reg, [symbol] - RIP-relative address computation
    if (strcmp(inst->mnemonic, "lea") == 0 && reg1 >= 0 && op2[0] == '[') {
        char *sym_name = op2 + 1;
        char *end = strchr(sym_name, ']');
        if (end) *end = '\0';
        
        int sym_idx = add_symbol(sym_name, 0, 1, 0);
        
        // lea r64, [rip+disp32]
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8) code[0] = 0x49;
        code[(*code_size)++] = 0x8D; // lea r64, m
        code[(*code_size)++] = 0x05 | ((reg1 & 0x07) << 3);
        
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        code[(*code_size)++] = 0x00;
        
        add_relocation(code_offset + 3, sym_idx);
        
        printf("  [ASM] lea %s, [%s] (RIP-relative)\n", op1, sym_name);
        return 1;
    }
    
    // Handle push/pop
    if ((strcmp(inst->mnemonic, "push") == 0 || strcmp(inst->mnemonic, "pop") == 0) && reg1 >= 0) {
        code[(*code_size)++] = inst->opcode + (reg1 & 0x07);
        if (reg1 >= 8) {
            memmove(&code[1], &code[0], *code_size);
            code[0] = 0x41;
            (*code_size)++;
        }
        return 1;
    }
    
    // Handle inc reg
    if (strcmp(inst->mnemonic, "inc") == 0 && reg1 >= 0) {
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8) code[0] = 0x49;
        code[(*code_size)++] = 0xFF; // inc r/m64
        code[(*code_size)++] = 0xC0 | (reg1 & 0x07); // /0 inc, mod=11
        printf("  [ASM] inc %s\n", op1);
        return 1;
    }
    
    // Handle dec reg
    if (strcmp(inst->mnemonic, "dec") == 0 && reg1 >= 0) {
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8) code[0] = 0x49;
        code[(*code_size)++] = 0xFF; // dec r/m64
        code[(*code_size)++] = 0xC8 | (reg1 & 0x07); // /1 dec, mod=11
        printf("  [ASM] dec %s\n", op1);
        return 1;
    }
    
    // Handle mov reg, imm (e.g., mov rax, 42)
    if (strcmp(inst->mnemonic, "mov") == 0 && reg1 >= 0 && op2[0] != '\0') {
        // Check if op2 is a number
        char* endptr;
        long imm = strtol(op2, &endptr, 0);
        if (*endptr == '\0') {
            // mov r64, imm32 - use 0xC7 /0 encoding
            code[(*code_size)++] = 0x48;
            if (reg1 >= 8) code[(*code_size - 1)] |= 0x01;
            code[(*code_size)++] = 0xC7;
            code[(*code_size)++] = 0xC0 | (reg1 & 0x07);
            // Emit 32-bit immediate
            code[(*code_size)++] = (uint8_t)(imm & 0xFF);
            code[(*code_size)++] = (uint8_t)((imm >> 8) & 0xFF);
            code[(*code_size)++] = (uint8_t)((imm >> 16) & 0xFF);
            code[(*code_size)++] = (uint8_t)((imm >> 24) & 0xFF);
            return 1;
        }
    }

    // Handle mov reg, reg
    if (strcmp(inst->mnemonic, "mov") == 0 && reg1 >= 0 && reg2 >= 0) {
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8 || reg2 >= 8) {
            code[0] |= 0x01;
            if (reg2 >= 8) code[0] |= 0x04;
        }
        code[(*code_size)++] = 0x89;
        code[(*code_size)++] = 0xC0 | ((reg2 & 0x07) << 3) | (reg1 & 0x07);
        return 1;
    }

    // Handle add/sub reg, reg
    if ((strcmp(inst->mnemonic, "add") == 0 || strcmp(inst->mnemonic, "sub") == 0) &&
        reg1 >= 0 && reg2 >= 0) {
        code[(*code_size)++] = 0x48;
        if (reg1 >= 8 || reg2 >= 8) {
            code[0] = 0x48 | (reg1 >= 8 ? 0x01 : 0) | (reg2 >= 8 ? 0x04 : 0);
        }
        code[(*code_size)++] = inst->opcode;
        code[(*code_size)++] = 0xC0 | ((reg2 & 0x07) << 3) | (reg1 & 0x07);
        return 1;
    }
    
    // Handle ret/nop
    if (strcmp(inst->mnemonic, "ret") == 0 || strcmp(inst->mnemonic, "nop") == 0) {
        code[(*code_size)++] = inst->opcode;
        return 1;
    }
    
    return 0;
}

// Write COFF object file with relocations and data section
int write_coff_object(const char *filename, uint8_t *code, int code_size) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        printf("[ERROR] Cannot create: %s\n", filename);
        return 0;
    }
    
    int has_data = (data_section_size > 0);
    int num_sections = has_data ? 2 : 1;
    
    // Calculate offsets
    int coff_header_size = sizeof(COFF_HEADER);
    int sect_header_size = sizeof(SECTION_HEADER);
    int headers_size = coff_header_size + sect_header_size * num_sections;
    
    int text_offset = headers_size;
    int text_reloc_offset = text_offset + code_size;
    int data_offset = text_reloc_offset + (num_relocations > 0 ? num_relocations * sizeof(RELOCATION_ENTRY) : 0);
    int symtab_offset = data_offset + data_section_size;
    
    // COFF Header
    COFF_HEADER coff = {0};
    coff.Machine = 0x8664;
    coff.NumberOfSections = num_sections;
    coff.TimeDateStamp = (uint32_t)time(NULL);
    coff.PointerToSymbolTable = symtab_offset;
    coff.NumberOfSymbols = 2 + num_symbols; // .text + @feat.00 + user symbols
    coff.SizeOfOptionalHeader = 0;
    coff.Characteristics = 0;
    fwrite(&coff, sizeof(coff), 1, f);
    
    // Text Section Header
    SECTION_HEADER text_sect = {0};
    memcpy(text_sect.Name, ".text", 5);
    text_sect.VirtualSize = code_size;
    text_sect.VirtualAddress = 0;
    text_sect.SizeOfRawData = code_size;
    text_sect.PointerToRawData = text_offset;
    text_sect.PointerToRelocations = num_relocations > 0 ? text_reloc_offset : 0;
    text_sect.PointerToLinenumbers = 0;
    text_sect.NumberOfRelocations = num_relocations;
    text_sect.NumberOfLinenumbers = 0;
    text_sect.Characteristics = 0x60000020; // CODE | EXECUTE | READ
    fwrite(&text_sect, sizeof(text_sect), 1, f);
    
    // Data Section Header (if present)
    if (has_data) {
        SECTION_HEADER data_sect = {0};
        memcpy(data_sect.Name, ".data", 5);
        data_sect.VirtualSize = data_section_size;
        data_sect.VirtualAddress = 0;
        data_sect.SizeOfRawData = data_section_size;
        data_sect.PointerToRawData = data_offset;
        data_sect.PointerToRelocations = 0;
        data_sect.PointerToLinenumbers = 0;
        data_sect.NumberOfRelocations = 0;
        data_sect.NumberOfLinenumbers = 0;
        data_sect.Characteristics = 0xC0000040; // INITIALIZED_DATA | READ | WRITE
        fwrite(&data_sect, sizeof(data_sect), 1, f);
    }
    
    // Text Section Data
    fwrite(code, code_size, 1, f);
    
    // Relocations
    if (num_relocations > 0) {
        fwrite(relocations, sizeof(RELOCATION_ENTRY), num_relocations, f);
    }
    
    // Data Section
    if (has_data) {
        fwrite(data_section, data_section_size, 1, f);
    }
    
    // Calculate string table size
    int string_table_size = 4; // Size field itself
    for (int i = 0; i < num_symbols; i++) {
        if (strlen(symbol_table[i].name) > 8) {
            string_table_size += strlen(symbol_table[i].name) + 1;
        }
    }
    
    // Symbol Table - USER SYMBOLS FIRST (indices 0 to num_symbols-1)
    // String table offsets are relative to the start of string table (including 4-byte size field)
    int string_offset = 4; // Start at 4 (after size field)
    for (int i = 0; i < num_symbols; i++) {
        SYMBOL_TABLE_ENTRY sym = {0};
        
        if (strlen(symbol_table[i].name) <= 8) {
            // Short name
            memcpy(sym.Name.ShortName, symbol_table[i].name, strlen(symbol_table[i].name));
        } else {
            // Long name in string table
            sym.Name.LongName.Zeroes = 0;
            sym.Name.LongName.Offset = string_offset;
            string_offset += strlen(symbol_table[i].name) + 1;
        }
        
        sym.Value = symbol_table[i].value;
        sym.SectionNumber = symbol_table[i].is_external ? 0 : 
                           (symbol_table[i].is_data ? 2 : 1);
        sym.Type = 0;
        sym.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
        sym.NumberOfAuxSymbols = 0;
        fwrite(&sym, sizeof(sym), 1, f);
    }
    
    // Section symbols AFTER user symbols
    // Section symbol (.text)
    SYMBOL_TABLE_ENTRY sect_sym = {0};
    memcpy(sect_sym.Name.ShortName, ".text", 5);
    sect_sym.Value = 0;
    sect_sym.SectionNumber = 1;
    sect_sym.Type = 0;
    sect_sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
    sect_sym.NumberOfAuxSymbols = 0;
    fwrite(&sect_sym, sizeof(sect_sym), 1, f);
    
    // Data section symbol (if present)
    if (has_data) {
        SYMBOL_TABLE_ENTRY data_sym = {0};
        memcpy(data_sym.Name.ShortName, ".data", 5);
        data_sym.Value = 0;
        data_sym.SectionNumber = 2;
        data_sym.Type = 0;
        data_sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
        data_sym.NumberOfAuxSymbols = 0;
        fwrite(&data_sym, sizeof(data_sym), 1, f);
    }
    
    // @feat.00 symbol
    SYMBOL_TABLE_ENTRY feat_sym = {0};
    memcpy(feat_sym.Name.ShortName, "@feat.00", 8);
    feat_sym.Value = 0;
    feat_sym.SectionNumber = -1; // ABS
    feat_sym.Type = 0;
    feat_sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
    feat_sym.NumberOfAuxSymbols = 0;
    fwrite(&feat_sym, sizeof(feat_sym), 1, f);
    
    // String Table
    fwrite(&string_table_size, 4, 1, f);
    for (int i = 0; i < num_symbols; i++) {
        if (strlen(symbol_table[i].name) > 8) {
            fwrite(symbol_table[i].name, strlen(symbol_table[i].name) + 1, 1, f);
        }
    }
    
    fclose(f);
    
    printf("[SUCCESS] Created: %s\n", filename);
    printf("  Code: %d bytes\n", code_size);
    printf("  Data: %d bytes\n", data_section_size);
    printf("  Relocations: %d\n", num_relocations);
    printf("  Symbols: %d\n", num_symbols);
    
    return 1;
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("Native Assembler WITH RELOCATIONS v1.0\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <input.asm> [output.obj]\n", argv[0]);
        return 0;
    }
    
    FILE *input = fopen(argv[1], "r");
    if (!input) {
        printf("[ERROR] Cannot open: %s\n", argv[1]);
        return 1;
    }
    
    printf("[ASSEMBLY] Reading: %s\n\n", argv[1]);
    
    uint8_t code[4096];
    int code_size = 0;
    char line[256];
    int instructions_assembled = 0;
    
    while (fgets(line, sizeof(line), input)) {
        // Trim whitespace
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (*p == '\0' || *p == ';' || *p == '\n' || *p == '\r') continue;
        
        // Remove comments
        char *comment = strchr(p, ';');
        if (comment) *comment = '\0';
        
        // Remove trailing whitespace
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        
        // Handle section directives
        if (strncmp(p, ".text", 5) == 0 || strncmp(p, "section .text", 13) == 0) {
            current_section = SECTION_TEXT;
            printf("  [SECTION] Switching to .text\n");
            continue;
        }
        if (strncmp(p, ".data", 5) == 0 || strncmp(p, "section .data", 13) == 0) {
            current_section = SECTION_DATA;
            printf("  [SECTION] Switching to .data\n");
            continue;
        }
        
        // Handle data definitions in .data section
        if (current_section == SECTION_DATA) {
            // Check for label (symbol:)
            char *colon = strchr(p, ':');
            if (colon) {
                *colon = '\0';
                add_symbol(p, 0, 1, data_section_size); // Add as internal data symbol
                printf("  [DATA LABEL] %s\n", p);
                p = colon + 1;
                while (*p == ' ' || *p == '\t') p++;
            }
            
            // Handle dd (define dword - 4 bytes)
            if (strncmp(p, "dd", 2) == 0 && (p[2] == ' ' || p[2] == '\t' || p[2] == '\0')) {
                char *val = p + 2;
                while (*val == ' ' || *val == '\t') val++;
                
                // Try to parse as number
                char *endptr;
                long val32 = strtol(val, &endptr, 0);
                if (*endptr == '\0') {
                    if (data_section_size + 4 <= sizeof(data_section)) {
                        int32_t signed_val = (int32_t)val32;
                        memcpy(data_section + data_section_size, &signed_val, 4);
                        data_section_size += 4;
                        printf("  [DATA] dd %ld (4 bytes)\n", val32);
                    }
                }
                continue;
            }
            
            // Handle dq (define quadword)
            if (strncmp(p, "dq", 2) == 0) {
                char *val = p + 2;
                while (*val == ' ' || *val == '\t') val++;
                
                // Check if it's a numeric value or 0
                if (strcmp(val, "0") == 0) {
                    // Reserve 8 bytes initialized to 0
                    if (data_section_size + 8 <= sizeof(data_section)) {
                        memset(data_section + data_section_size, 0, 8);
                        data_section_size += 8;
                        printf("  [DATA] dq 0 (8 bytes)\n");
                    }
                } else {
                    // Try to parse as number
                    char *endptr;
                    long long val64 = strtoll(val, &endptr, 0);
                    if (*endptr == '\0') {
                        if (data_section_size + 8 <= sizeof(data_section)) {
                            memcpy(data_section + data_section_size, &val64, 8);
                            data_section_size += 8;
                            printf("  [DATA] dq %lld (8 bytes)\n", val64);
                        }
                    }
                }
                continue;
            }
            
            // Handle db (define byte) for strings
            if (strncmp(p, "db", 2) == 0) {
                char *val = p + 2;
                while (*val == ' ' || *val == '\t') val++;
                
                // Check for string literal
                if (*val == '\"' || *val == '\'') {
                    char quote = *val++;
                    int len = 0;
                    while (*val && *val != quote && data_section_size < sizeof(data_section)) {
                        if (*val == '\\' && *(val+1)) {
                            val++;
                            switch (*val) {
                                case 'n': data_section[data_section_size++] = '\n'; break;
                                case 'r': data_section[data_section_size++] = '\r'; break;
                                case 't': data_section[data_section_size++] = '\t'; break;
                                case '0': data_section[data_section_size++] = '\0'; break;
                                default: data_section[data_section_size++] = *val; break;
                            }
                            val++;
                        } else {
                            data_section[data_section_size++] = *val++;
                        }
                        len++;
                    }
                    // Add null terminator
                    if (data_section_size < sizeof(data_section)) {
                        data_section[data_section_size++] = 0;
                    }
                    printf("  [DATA] db string (%d bytes + null)\n", len);
                }
                continue;
            }
        }
        
        // Skip labels in text section
        end = p + strlen(p) - 1;
        while (end > p && (*end == ' ' || *end == '\t')) end--;
        if (*end == ':') {
            *end = '\0';
            printf("  [LABEL] %s at offset %d\n", p, code_size);
            // Add label as internal symbol for linker with current offset as value
            add_symbol(p, 0, 0, code_size);
            continue;
        }
        
        // Assemble instruction (only in text section)
        if (current_section == SECTION_TEXT) {
            int inst_size = 0;
            if (assemble_instruction(p, &code[code_size], &inst_size, code_size)) {
                code_size += inst_size;
                instructions_assembled++;
            }
        }
    }
    
    fclose(input);
    
    printf("\n[SUMMARY] Assembled %d instructions, %d bytes\n", instructions_assembled, code_size);
    printf("  Symbols: %d, Relocations: %d\n\n", num_symbols, num_relocations);
    
    const char *output = (argc > 2) ? argv[2] : "output.obj";
    if (!write_coff_object(output, code, code_size)) {
        return 1;
    }
    
    printf("\n[TEST] PASS - Assembly with relocations complete\n");
    return 0;
}
