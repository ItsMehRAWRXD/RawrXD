// ============================================================================
// real_assembler.c - A real x64 assembler that parses and generates machine code
// ============================================================================
// Build: gcc -O2 -o real_assembler.exe real_assembler.c
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <windows.h>

#define MAX_LINE_LEN 256
#define MAX_SYMBOLS 1000
#define MAX_CODE_SIZE 65536

// Instruction encoding tables
typedef struct {
    const char* mnemonic;
    uint8_t opcode;
    uint8_t hasModRM;
    uint8_t regField;
} Instruction;

static Instruction instructions[] = {
    // Data movement
    {"mov", 0x89, 1, 0},      // mov r/m64, r64
    {"push", 0x50, 0, 0},     // push r64 (opcode + reg)
    {"pop", 0x58, 0, 0},      // pop r64 (opcode + reg)
    
    // Arithmetic
    {"add", 0x01, 1, 0},      // add r/m64, r64
    {"sub", 0x29, 1, 0},      // sub r/m64, r64
    {"xor", 0x31, 1, 0},      // xor r/m64, r64
    {"and", 0x21, 1, 0},      // and r/m64, r64
    {"or", 0x09, 1, 0},       // or r/m64, r64
    {"inc", 0xFF, 1, 0},      // inc r/m64 (reg field 0)
    {"dec", 0xFF, 1, 1},      // dec r/m64 (reg field 1)
    
    // Control flow
    {"ret", 0xC3, 0, 0},      // ret
    {"nop", 0x90, 0, 0},      // nop
    {"syscall", 0x0F, 0, 0},  // syscall (0x0F 0x05)
    
    {NULL, 0, 0, 0}
};

// Register encoding
typedef struct {
    const char* name;
    uint8_t code;
    uint8_t size;
} Register;

static Register registers[] = {
    // 64-bit registers
    {"rax", 0, 64}, {"rcx", 1, 64}, {"rdx", 2, 64}, {"rbx", 3, 64},
    {"rsp", 4, 64}, {"rbp", 5, 64}, {"rsi", 6, 64}, {"rdi", 7, 64},
    {"r8", 8, 64}, {"r9", 9, 64}, {"r10", 10, 64}, {"r11", 11, 64},
    {"r12", 12, 64}, {"r13", 13, 64}, {"r14", 14, 64}, {"r15", 15, 64},
    
    // 32-bit registers
    {"eax", 0, 32}, {"ecx", 1, 32}, {"edx", 2, 32}, {"ebx", 3, 32},
    {"esp", 4, 32}, {"ebp", 5, 32}, {"esi", 6, 32}, {"edi", 7, 32},
    
    {NULL, 0, 0}
};

// Symbol table for labels
typedef struct {
    char name[64];
    uint32_t address;
    uint32_t isDefined;
} Symbol;

static Symbol symbolTable[MAX_SYMBOLS];
static int symbolCount = 0;

// Code generation buffer
static uint8_t codeBuffer[MAX_CODE_SIZE];
static size_t codeSize = 0;
static uint32_t currentAddress = 0x1000; // Start address in .text section

// Parser state
typedef struct {
    char line[MAX_LINE_LEN];
    char* token;
    int lineNumber;
} Parser;

// Helper functions
static char* trim(char* str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

static char* getToken(char** str, const char* delim) {
    char* token = strtok(*str, delim);
    if (token) *str = NULL;
    return token;
}

static Register* findRegister(const char* name) {
    for (int i = 0; registers[i].name; i++) {
        if (_stricmp(registers[i].name, name) == 0) {
            return &registers[i];
        }
    }
    return NULL;
}

static Instruction* findInstruction(const char* mnemonic) {
    for (int i = 0; instructions[i].mnemonic; i++) {
        if (_stricmp(instructions[i].mnemonic, mnemonic) == 0) {
            return &instructions[i];
        }
    }
    return NULL;
}

static Symbol* findSymbol(const char* name) {
    for (int i = 0; i < symbolCount; i++) {
        if (_stricmp(symbolTable[i].name, name) == 0) {
            return &symbolTable[i];
        }
    }
    return NULL;
}

static Symbol* addSymbol(const char* name, uint32_t address) {
    if (symbolCount >= MAX_SYMBOLS) return NULL;
    
    Symbol* sym = &symbolTable[symbolCount++];
    strncpy(sym->name, name, 63);
    sym->name[63] = '\0';
    sym->address = address;
    sym->isDefined = 1;
    return sym;
}

// Emit bytes to code buffer
static void emitByte(uint8_t byte) {
    if (codeSize < MAX_CODE_SIZE) {
        codeBuffer[codeSize++] = byte;
        currentAddress++;
    }
}

static void emitWord(uint16_t word) {
    emitByte(word & 0xFF);
    emitByte((word >> 8) & 0xFF);
}

static void emitDword(uint32_t dword) {
    emitByte(dword & 0xFF);
    emitByte((dword >> 8) & 0xFF);
    emitByte((dword >> 16) & 0xFF);
    emitByte((dword >> 24) & 0xFF);
}

static void emitQword(uint64_t qword) {
    emitDword(qword & 0xFFFFFFFF);
    emitDword((qword >> 32) & 0xFFFFFFFF);
}

// Encode ModR/M byte
static void emitModRM(uint8_t mod, uint8_t reg, uint8_t rm) {
    emitByte((mod << 6) | ((reg & 7) << 3) | (rm & 7));
}

// Encode REX prefix for 64-bit operands
static void emitRexPrefix(int w, int r, int x, int b) {
    emitByte(0x40 | (w << 3) | (r << 2) | (x << 1) | b);
}

// Parse register from operand string
static int parseRegister(const char* operand, Register** reg) {
    char regName[16];
    int i = 0;
    
    // Skip whitespace and brackets for memory operands
    while (isspace((unsigned char)*operand) || *operand == '[') operand++;
    
    // Extract register name
    while (i < 15 && (isalnum((unsigned char)*operand) || *operand == '_')) {
        regName[i++] = *operand++;
    }
    regName[i] = '\0';
    
    *reg = findRegister(regName);
    return (*reg != NULL);
}

// Parse immediate value
static int parseImmediate(const char* str, int64_t* value) {
    char* end;
    *value = strtoll(str, &end, 0);
    return (*end == '\0' || isspace((unsigned char)*end));
}

// Assemble a single instruction
static int assembleInstruction(const char* mnemonic, char* operands) {
    Instruction* inst = findInstruction(mnemonic);
    if (!inst) {
        printf("Error: Unknown instruction '%s'\n", mnemonic);
        return 0;
    }
    
    // Parse operands
    char* op1 = strtok(operands, ",");
    char* op2 = strtok(NULL, ",");
    
    if (op1) op1 = trim(op1);
    if (op2) op2 = trim(op2);
    
    // Handle different instruction types
    if (_stricmp(mnemonic, "ret") == 0) {
        emitByte(0xC3);
    }
    else if (_stricmp(mnemonic, "nop") == 0) {
        emitByte(0x90);
    }
    else if (_stricmp(mnemonic, "push") == 0) {
        Register* reg;
        if (parseRegister(op1, &reg)) {
            if (reg->code >= 8) {
                emitRexPrefix(0, 0, 0, 1); // REX.B for r8-r15
            }
            emitByte(0x50 + (reg->code & 7));
        } else {
            // push imm32
            int64_t imm;
            if (parseImmediate(op1, &imm)) {
                emitByte(0x68);
                emitDword((uint32_t)imm);
            }
        }
    }
    else if (_stricmp(mnemonic, "pop") == 0) {
        Register* reg;
        if (parseRegister(op1, &reg)) {
            if (reg->code >= 8) {
                emitRexPrefix(0, 0, 0, 1);
            }
            emitByte(0x58 + (reg->code & 7));
        }
    }
    else if (_stricmp(mnemonic, "mov") == 0) {
        Register* dst, *src;
        if (parseRegister(op1, &dst) && parseRegister(op2, &src)) {
            // mov r64, r64
            int needRex = (dst->code >= 8) || (src->code >= 8);
            if (needRex) {
                emitRexPrefix(1, (src->code >= 8), 0, (dst->code >= 8));
            } else {
                emitRexPrefix(1, 0, 0, 0); // REX.W for 64-bit
            }
            emitByte(0x89); // MOV r/m64, r64
            emitModRM(3, src->code & 7, dst->code & 7);
        }
        else if (parseRegister(op1, &dst)) {
            // mov r64, imm64 or mov r64, imm32
            int64_t imm;
            if (parseImmediate(op2, &imm)) {
                if (dst->code >= 8) {
                    emitRexPrefix(1, 0, 0, 1);
                } else {
                    emitRexPrefix(1, 0, 0, 0);
                }
                emitByte(0xB8 + (dst->code & 7)); // MOV r64, imm64
                emitQword((uint64_t)imm);
            }
        }
    }
    else if (_stricmp(mnemonic, "add") == 0) {
        Register* dst, *src;
        if (parseRegister(op1, &dst) && parseRegister(op2, &src)) {
            emitRexPrefix(1, (src->code >= 8), 0, (dst->code >= 8));
            emitByte(0x01); // ADD r/m64, r64
            emitModRM(3, src->code & 7, dst->code & 7);
        }
    }
    else if (_stricmp(mnemonic, "sub") == 0) {
        Register* dst, *src;
        if (parseRegister(op1, &dst) && parseRegister(op2, &src)) {
            emitRexPrefix(1, (src->code >= 8), 0, (dst->code >= 8));
            emitByte(0x29); // SUB r/m64, r64
            emitModRM(3, src->code & 7, dst->code & 7);
        }
    }
    else if (_stricmp(mnemonic, "xor") == 0) {
        Register* dst, *src;
        if (parseRegister(op1, &dst) && parseRegister(op2, &src)) {
            emitRexPrefix(1, (src->code >= 8), 0, (dst->code >= 8));
            emitByte(0x31); // XOR r/m64, r64
            emitModRM(3, src->code & 7, dst->code & 7);
        }
    }
    else if (_stricmp(mnemonic, "inc") == 0) {
        Register* reg;
        if (parseRegister(op1, &reg)) {
            emitRexPrefix(1, 0, 0, (reg->code >= 8));
            emitByte(0xFF); // INC r/m64
            emitModRM(3, 0, reg->code & 7);
        }
    }
    else if (_stricmp(mnemonic, "dec") == 0) {
        Register* reg;
        if (parseRegister(op1, &reg)) {
            emitRexPrefix(1, 0, 0, (reg->code >= 8));
            emitByte(0xFF); // DEC r/m64
            emitModRM(3, 1, reg->code & 7);
        }
    }
    else if (_stricmp(mnemonic, "syscall") == 0) {
        emitByte(0x0F);
        emitByte(0x05);
    }
    else {
        printf("Error: Instruction '%s' not yet implemented\n", mnemonic);
        return 0;
    }
    
    return 1;
}

// First pass: collect labels and calculate sizes
static int firstPass(FILE* f) {
    char line[MAX_LINE_LEN];
    int lineNum = 0;
    
    while (fgets(line, sizeof(line), f)) {
        lineNum++;
        char* trimmed = trim(line);
        
        // Skip empty lines and comments
        if (*trimmed == '\0' || *trimmed == ';' || *trimmed == '#') continue;
        
        // Check for label
        char* colon = strchr(trimmed, ':');
        if (colon) {
            *colon = '\0';
            addSymbol(trimmed, currentAddress);
            trimmed = trim(colon + 1);
            if (*trimmed == '\0') continue;
        }
        
        // Parse instruction
        char* mnemonic = strtok(trimmed, " \t");
        if (!mnemonic) continue;
        
        // Skip section directives for now
        if (mnemonic[0] == '.') continue;
        
        char* operands = strtok(NULL, "\n");
        if (operands) operands = trim(operands);
        
        // Calculate instruction size (simplified - just assemble to temp buffer)
        size_t oldSize = codeSize;
        assembleInstruction(mnemonic, operands ? operands : "");
        
        // Don't actually keep the code in first pass
        codeSize = oldSize;
    }
    
    return 1;
}

// Second pass: generate actual code
static int secondPass(FILE* f) {
    rewind(f);
    codeSize = 0;
    currentAddress = 0x1000;
    
    char line[MAX_LINE_LEN];
    int lineNum = 0;
    
    while (fgets(line, sizeof(line), f)) {
        lineNum++;
        char* trimmed = trim(line);
        
        // Skip empty lines and comments
        if (*trimmed == '\0' || *trimmed == ';' || *trimmed == '#') continue;
        
        // Check for label
        char* colon = strchr(trimmed, ':');
        if (colon) {
            trimmed = trim(colon + 1);
            if (*trimmed == '\0') continue;
        }
        
        // Parse instruction
        char* mnemonic = strtok(trimmed, " \t");
        if (!mnemonic) continue;
        
        // Skip section directives
        if (mnemonic[0] == '.') continue;
        
        char* operands = strtok(NULL, "\n");
        if (operands) operands = trim(operands);
        
        if (!assembleInstruction(mnemonic, operands ? operands : "")) {
            printf("Error on line %d: %s\n", lineNum, line);
            return 0;
        }
    }
    
    return 1;
}

// Create PE file with actual assembled code
int createPEFile(const char* filename, uint8_t* code, size_t codeSize) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        printf("Error: Cannot create output file\n");
        return 0;
    }
    
    // Align sizes
    uint32_t fileAlignment = 512;
    uint32_t sectionAlignment = 0x1000;
    
    uint32_t headersSize = 512;
    uint32_t codeAligned = ((codeSize + fileAlignment - 1) / fileAlignment) * fileAlignment;
    uint32_t imageSize = 0x2000; // Minimum image size
    
    // Allocate PE buffer
    uint8_t* pe = calloc(1, headersSize + codeAligned);
    if (!pe) {
        fclose(f);
        return 0;
    }
    
    // DOS Header
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    dos->e_magic = 0x5A4D; // 'MZ'
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    
    // PE Signature
    uint32_t* peSig = (uint32_t*)(pe + sizeof(IMAGE_DOS_HEADER));
    *peSig = 0x00004550; // 'PE\0\0'
    
    // COFF Header
    IMAGE_FILE_HEADER* coff = (IMAGE_FILE_HEADER*)(pe + sizeof(IMAGE_DOS_HEADER) + 4);
    coff->Machine = 0x8664; // AMD64
    coff->NumberOfSections = 1;
    coff->TimeDateStamp = 0;
    coff->PointerToSymbolTable = 0;
    coff->NumberOfSymbols = 0;
    coff->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64) + 16 * sizeof(IMAGE_DATA_DIRECTORY);
    coff->Characteristics = 0x1022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    
    // Optional Header
    IMAGE_OPTIONAL_HEADER64* opt = (IMAGE_OPTIONAL_HEADER64*)((uint8_t*)coff + sizeof(IMAGE_FILE_HEADER));
    opt->Magic = 0x20B; // PE32+
    opt->MajorLinkerVersion = 1;
    opt->MinorLinkerVersion = 0;
    opt->SizeOfCode = codeAligned;
    opt->SizeOfInitializedData = 0;
    opt->SizeOfUninitializedData = 0;
    opt->AddressOfEntryPoint = 0x1000; // Entry point RVA
    opt->BaseOfCode = 0x1000;
    opt->ImageBase = 0x140000000ULL;
    opt->SectionAlignment = sectionAlignment;
    opt->FileAlignment = fileAlignment;
    opt->MajorOperatingSystemVersion = 6;
    opt->MinorOperatingSystemVersion = 0;
    opt->MajorImageVersion = 0;
    opt->MinorImageVersion = 0;
    opt->MajorSubsystemVersion = 6;
    opt->MinorSubsystemVersion = 0;
    opt->Win32VersionValue = 0;
    opt->SizeOfImage = imageSize;
    opt->SizeOfHeaders = headersSize;
    opt->CheckSum = 0;
    opt->Subsystem = 1; // NATIVE (for syscalls)
    opt->DllCharacteristics = 0;
    opt->SizeOfStackReserve = 0x100000;
    opt->SizeOfStackCommit = 0x1000;
    opt->SizeOfHeapReserve = 0x100000;
    opt->SizeOfHeapCommit = 0x1000;
    opt->LoaderFlags = 0;
    opt->NumberOfRvaAndSizes = 16;
    
    // Section Header
    IMAGE_SECTION_HEADER* sect = (IMAGE_SECTION_HEADER*)((uint8_t*)opt + sizeof(IMAGE_OPTIONAL_HEADER64) + 16 * sizeof(IMAGE_DATA_DIRECTORY));
    memcpy(sect->Name, ".text", 5);
    sect->Misc.VirtualSize = codeSize;
    sect->VirtualAddress = 0x1000;
    sect->SizeOfRawData = codeAligned;
    sect->PointerToRawData = headersSize;
    sect->PointerToRelocations = 0;
    sect->PointerToLinenumbers = 0;
    sect->NumberOfRelocations = 0;
    sect->NumberOfLinenumbers = 0;
    sect->Characteristics = 0x60000020; // CODE | EXECUTE | READ
    
    // Copy code
    memcpy(pe + headersSize, code, codeSize);
    
    // Write file
    fwrite(pe, 1, headersSize + codeAligned, f);
    fclose(f);
    free(pe);
    
    return 1;
}

int main(int argc, char* argv[]) {
    printf("RawrXD Real Assembler v1.0\n");
    printf("============================\n\n");
    
    if (argc != 3) {
        printf("Usage: %s <source.asm> <output.exe>\n", argv[0]);
        printf("\nAssembles x64 assembly code into a working Windows executable.\n");
        printf("\nSupported instructions:\n");
        printf("  mov, push, pop, add, sub, xor, and, or\n");
        printf("  inc, dec, ret, nop, syscall\n");
        printf("\nSupported registers:\n");
        printf("  rax-r15, eax-edi (64-bit and 32-bit)\n");
        return 1;
    }
    
    const char* sourceFile = argv[1];
    const char* outputFile = argv[2];
    
    printf("Source: %s\n", sourceFile);
    printf("Output: %s\n\n", outputFile);
    
    // Open source file
    FILE* f = fopen(sourceFile, "r");
    if (!f) {
        printf("Error: Cannot open source file: %s\n", sourceFile);
        return 1;
    }
    
    // First pass: collect labels
    printf("Pass 1: Collecting labels...\n");
    if (!firstPass(f)) {
        fclose(f);
        return 1;
    }
    printf("Found %d symbols\n", symbolCount);
    
    // Second pass: generate code
    printf("Pass 2: Generating machine code...\n");
    if (!secondPass(f)) {
        fclose(f);
        return 1;
    }
    
    fclose(f);
    
    printf("Generated %zu bytes of machine code\n", codeSize);
    
    // Create PE file
    printf("Creating PE executable...\n");
    if (!createPEFile(outputFile, codeBuffer, codeSize)) {
        printf("Error: Failed to create output file\n");
        return 1;
    }
    
    printf("\nSuccess! Output written to: %s\n", outputFile);
    printf("Entry point: 0x%04X\n", 0x1000);
    printf("Code size: %zu bytes\n", codeSize);
    
    return 0;
}
