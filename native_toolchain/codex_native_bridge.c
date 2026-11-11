//=============================================================================
// codex_native_bridge.c - Codex Disassembly ↔ Native Assembler Bridge
// Part of RawrXD Native Toolchain - RE Integration
// Converts between CodexAnalyzer output and native assembler input
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <windows.h>

#define CODEX_BRIDGE_VERSION "1.0.0"
#define MAX_LINE_LENGTH 1024
#define MAX_INSTRUCTIONS 65536

//=============================================================================
// Structures
//=============================================================================

typedef struct {
    uint64_t address;
    uint8_t bytes[15];      // Max x64 instruction length
    int byte_count;
    char mnemonic[32];
    char operands[128];
    char comment[256];
} CodexInstruction;

typedef struct {
    CodexInstruction* instructions;
    int count;
    int capacity;
    uint64_t base_address;
    char module_name[256];
} CodexDisassembly;

typedef struct {
    char* lines;
    int count;
    int capacity;
    char* buffer;
    size_t buffer_pos;
    size_t buffer_size;
} NativeAssembly;

//=============================================================================
// x64 Instruction Database for Native Assembly Generation
//=============================================================================

typedef struct {
    const char* codex_mnemonic;    // Mnemonic from Codex
    const char* native_mnemonic;   // Mnemonic for native assembler
    int operand_count;
    int needs_rex_w;               // Needs REX.W prefix for 64-bit
    int encoding_type;             // 0=direct, 1=register, 2=memory, etc.
} InstructionMapping;

// Common instruction mappings (Codex format → Native format)
InstructionMapping instruction_map[] = {
    // Data movement
    {"mov", "mov", 2, 1, 1},
    {"movabs", "mov", 2, 1, 1},
    {"push", "push", 1, 0, 0},
    {"pop", "pop", 1, 0, 0},
    {"lea", "lea", 2, 1, 2},
    {"xchg", "xchg", 2, 1, 1},
    
    // Arithmetic
    {"add", "add", 2, 1, 1},
    {"sub", "sub", 2, 1, 1},
    {"inc", "inc", 1, 1, 0},
    {"dec", "dec", 1, 1, 0},
    {"imul", "imul", 2, 1, 1},
    {"idiv", "idiv", 1, 1, 0},
    {"neg", "neg", 1, 1, 0},
    {"cmp", "cmp", 2, 1, 1},
    
    // Logical
    {"and", "and", 2, 1, 1},
    {"or", "or", 2, 1, 1},
    {"xor", "xor", 2, 1, 1},
    {"not", "not", 1, 1, 0},
    {"test", "test", 2, 1, 1},
    
    // Shifts
    {"shl", "shl", 2, 1, 0},
    {"shr", "shr", 2, 1, 0},
    {"sar", "sar", 2, 1, 0},
    
    // Control flow
    {"call", "call", 1, 0, 3},   // 3=relative offset
    {"ret", "ret", 0, 0, 0},
    {"jmp", "jmp", 1, 0, 3},
    {"je", "je", 1, 0, 3},
    {"jne", "jne", 1, 0, 3},
    {"jg", "jg", 1, 0, 3},
    {"jge", "jge", 1, 0, 3},
    {"jl", "jl", 1, 0, 3},
    {"jle", "jle", 1, 0, 3},
    {"ja", "ja", 1, 0, 3},
    {"jae", "jae", 1, 0, 3},
    {"jb", "jb", 1, 0, 3},
    {"jbe", "jbe", 1, 0, 3},
    
    // System
    {"syscall", "syscall", 0, 0, 0},
    {"sysret", "sysret", 0, 0, 0},
    {"int3", "int3", 0, 0, 0},
    {"nop", "nop", 0, 0, 0},
    
    // AVX/AVX-512
    {"vmovaps", "vmovaps", 2, 0, 1},
    {"vmovups", "vmovups", 2, 0, 1},
    {"vaddps", "vaddps", 3, 0, 1},
    {"vsubps", "vsubps", 3, 0, 1},
    {"vmulps", "vmulps", 3, 0, 1},
    {"vdivps", "vdivps", 3, 0, 1},
    {"vsqrtps", "vsqrtps", 2, 0, 1},
    {"vxorps", "vxorps", 3, 0, 1},
    {"vfmadd213ps", "vfmadd213ps", 3, 0, 1},
    
    {NULL, NULL, 0, 0, 0}
};

//=============================================================================
// Codex Disassembly Parser
//=============================================================================

CodexDisassembly* codex_disassembly_create(void) {
    CodexDisassembly* disasm = (CodexDisassembly*)calloc(1, sizeof(CodexDisassembly));
    if (!disasm) return NULL;
    
    disasm->capacity = 1024;
    disasm->instructions = (CodexInstruction*)calloc(disasm->capacity, sizeof(CodexInstruction));
    if (!disasm->instructions) {
        free(disasm);
        return NULL;
    }
    
    return disasm;
}

void codex_disassembly_destroy(CodexDisassembly* disasm) {
    if (disasm) {
        free(disasm->instructions);
        free(disasm);
    }
}

// Parse Codex JSON output (simplified format)
int codex_parse_json(CodexDisassembly* disasm, const char* json_text) {
    // Simplified JSON parser for Codex output
    // Expected format: {"address": "0x1234", "bytes": "48 89 C8", "mnemonic": "mov", "operands": "rax, rcx"}
    
    const char* p = json_text;
    int in_object = 0;
    
    while (*p) {
        // Skip whitespace
        while (*p && isspace(*p)) p++;
        
        if (*p == '{') {
            in_object = 1;
            p++;
            
            if (disasm->count >= disasm->capacity) {
                // Grow array
                int new_capacity = disasm->capacity * 2;
                CodexInstruction* new_instr = (CodexInstruction*)realloc(
                    disasm->instructions, new_capacity * sizeof(CodexInstruction));
                if (!new_instr) return 0;
                disasm->instructions = new_instr;
                disasm->capacity = new_capacity;
            }
            
            CodexInstruction* instr = &disasm->instructions[disasm->count];
            memset(instr, 0, sizeof(CodexInstruction));
            
            // Parse fields
            while (*p && *p != '}') {
                // Skip whitespace and commas
                while (*p && (isspace(*p) || *p == ',')) p++;
                
                // Parse field name
                if (*p == '"') {
                    p++;
                    char field_name[64] = {0};
                    int i = 0;
                    while (*p && *p != '"' && i < 63) {
                        field_name[i++] = *p++;
                    }
                    if (*p == '"') p++;
                    
                    // Skip to value
                    while (*p && (isspace(*p) || *p == ':')) p++;
                    
                    // Parse value
                    if (*p == '"') {
                        p++;
                        char value[512] = {0};
                        i = 0;
                        while (*p && *p != '"' && i < 511) {
                            value[i++] = *p++;
                        }
                        if (*p == '"') p++;
                        
                        // Store in appropriate field
                        if (strcmp(field_name, "address") == 0) {
                            instr->address = strtoull(value, NULL, 16);
                        } else if (strcmp(field_name, "bytes") == 0) {
                            // Parse hex bytes
                            char* byte_str = strtok(value, " ");
                            while (byte_str && instr->byte_count < 15) {
                                instr->bytes[instr->byte_count++] = (uint8_t)strtoul(byte_str, NULL, 16);
                                byte_str = strtok(NULL, " ");
                            }
                        } else if (strcmp(field_name, "mnemonic") == 0) {
                            strncpy(instr->mnemonic, value, 31);
                        } else if (strcmp(field_name, "operands") == 0) {
                            strncpy(instr->operands, value, 127);
                        } else if (strcmp(field_name, "comment") == 0) {
                            strncpy(instr->comment, value, 255);
                        }
                    }
                }
                
                if (*p && *p != '}') p++;
            }
            
            if (*p == '}') {
                p++;
                disasm->count++;
            }
        } else {
            p++;
        }
    }
    
    return disasm->count;
}

// Parse Codex text output (alternative to JSON)
int codex_parse_text(CodexDisassembly* disasm, const char* text) {
    const char* line = text;
    char buffer[MAX_LINE_LENGTH];
    
    while (*line) {
        // Copy line to buffer
        int i = 0;
        while (*line && *line != '\n' && i < MAX_LINE_LENGTH - 1) {
            buffer[i++] = *line++;
        }
        buffer[i] = '\0';
        if (*line == '\n') line++;
        
        // Parse line: "00007FF123456789  48 89 C8          mov     rax, rcx"
        // Or: "123456789:       48 89 C8          mov     rax, rcx"
        char addr_str[32] = {0};
        char bytes_str[64] = {0};
        char mnemonic[32] = {0};
        char operands[128] = {0};
        
        // Try to parse address
        char* p = buffer;
        while (*p && isspace(*p)) p++;
        
        // Skip if empty or comment
        if (*p == '\0' || *p == ';' || *p == '#') continue;
        
        // Parse address (hex)
        i = 0;
        while (*p && (isxdigit(*p) || *p == 'x' || *p == 'X')) {
            addr_str[i++] = *p++;
        }
        addr_str[i] = '\0';
        
        // Skip separator
        while (*p && (isspace(*p) || *p == ':')) p++;
        
        // Parse bytes (hex pairs)
        i = 0;
        while (*p && i < 63) {
            if (isxdigit(*p)) {
                bytes_str[i++] = *p++;
            } else if (isspace(*p)) {
                p++;
            } else {
                break;
            }
        }
        bytes_str[i] = '\0';
        
        // Skip whitespace
        while (*p && isspace(*p)) p++;
        
        // Parse mnemonic
        i = 0;
        while (*p && !isspace(*p) && i < 31) {
            mnemonic[i++] = *p++;
        }
        mnemonic[i] = '\0';
        
        // Skip whitespace
        while (*p && isspace(*p)) p++;
        
        // Parse operands (rest of line)
        i = 0;
        while (*p && *p != ';' && *p != '#' && i < 127) {
            operands[i++] = *p++;
        }
        // Trim trailing whitespace
        while (i > 0 && isspace(operands[i-1])) i--;
        operands[i] = '\0';
        
        // Add instruction if we have valid data
        if (strlen(mnemonic) > 0 && disasm->count < MAX_INSTRUCTIONS) {
            if (disasm->count >= disasm->capacity) {
                int new_capacity = disasm->capacity * 2;
                CodexInstruction* new_instr = (CodexInstruction*)realloc(
                    disasm->instructions, new_capacity * sizeof(CodexInstruction));
                if (!new_instr) return 0;
                disasm->instructions = new_instr;
                disasm->capacity = new_capacity;
            }
            
            CodexInstruction* instr = &disasm->instructions[disasm->count];
            memset(instr, 0, sizeof(CodexInstruction));
            
            if (strlen(addr_str) > 0) {
                instr->address = strtoull(addr_str, NULL, 16);
            }
            
            // Parse bytes
            char* byte_ptr = bytes_str;
            while (*byte_ptr && instr->byte_count < 15) {
                char byte_hex[3] = {byte_ptr[0], byte_ptr[1] ? byte_ptr[1] : '0', '\0'};
                instr->bytes[instr->byte_count++] = (uint8_t)strtoul(byte_hex, NULL, 16);
                byte_ptr += 2;
                while (*byte_ptr && isspace(*byte_ptr)) byte_ptr++;
            }
            
            strncpy(instr->mnemonic, mnemonic, 31);
            strncpy(instr->operands, operands, 127);
            
            disasm->count++;
        }
    }
    
    return disasm->count;
}

//=============================================================================
// Native Assembly Generator
//=============================================================================

NativeAssembly* native_assembly_create(void) {
    NativeAssembly* asm_out = (NativeAssembly*)calloc(1, sizeof(NativeAssembly));
    if (!asm_out) return NULL;
    
    asm_out->buffer_size = 1024 * 1024;  // 1MB initial
    asm_out->buffer = (char*)malloc(asm_out->buffer_size);
    if (!asm_out->buffer) {
        free(asm_out);
        return NULL;
    }
    
    return asm_out;
}

void native_assembly_destroy(NativeAssembly* asm_out) {
    if (asm_out) {
        free(asm_out->buffer);
        free(asm_out);
    }
}

void native_assembly_append(NativeAssembly* asm_out, const char* fmt, ...) {
    if (!asm_out || !asm_out->buffer) return;
    
    va_list args;
    va_start(args, fmt);
    
    char temp[1024];
    int len = vsnprintf(temp, sizeof(temp), fmt, args);
    va_end(args);
    
    if (len < 0) return;
    
    // Ensure buffer has space
    if (asm_out->buffer_pos + len + 1 > asm_out->buffer_size) {
        size_t new_size = asm_out->buffer_size * 2;
        char* new_buffer = (char*)realloc(asm_out->buffer, new_size);
        if (!new_buffer) return;
        asm_out->buffer = new_buffer;
        asm_out->buffer_size = new_size;
    }
    
    memcpy(asm_out->buffer + asm_out->buffer_pos, temp, len);
    asm_out->buffer_pos += len;
    asm_out->buffer[asm_out->buffer_pos] = '\0';
}

const char* get_native_mnemonic(const char* codex_mnemonic) {
    for (int i = 0; instruction_map[i].codex_mnemonic; i++) {
        if (_stricmp(codex_mnemonic, instruction_map[i].codex_mnemonic) == 0) {
            return instruction_map[i].native_mnemonic;
        }
    }
    return codex_mnemonic;  // Pass through if not found
}

// Convert Codex disassembly to native assembler format
int codex_to_native_asm(CodexDisassembly* disasm, NativeAssembly* asm_out) {
    // Write header
    native_assembly_append(asm_out, ";=============================================================================\n");
    native_assembly_append(asm_out, "; Generated by Codex-Native Bridge v%s\n", CODEX_BRIDGE_VERSION);
    native_assembly_append(asm_out, "; Source: Codex Disassembly\n");
    native_assembly_append(asm_out, ";=============================================================================\n\n");
    
    // Write section directive
    native_assembly_append(asm_out, ".code\n\n");
    
    // Track current function
    char current_function[256] = {0};
    uint64_t last_addr = 0;
    
    for (int i = 0; i < disasm->count; i++) {
        CodexInstruction* instr = &disasm->instructions[i];
        
        // Add label for function entry (heuristic: large address gap)
        if (i == 0 || (instr->address - last_addr > 0x100)) {
            if (strlen(current_function) > 0) {
                native_assembly_append(asm_out, "\n");
            }
            snprintf(current_function, sizeof(current_function), "func_%llX", instr->address);
            native_assembly_append(asm_out, "%s:\n", current_function);
        }
        last_addr = instr->address;
        
        // Add address comment
        native_assembly_append(asm_out, "    ; %016llX: ", instr->address);
        for (int j = 0; j < instr->byte_count && j < 8; j++) {
            native_assembly_append(asm_out, "%02X ", instr->bytes[j]);
        }
        native_assembly_append(asm_out, "\n");
        
        // Get native mnemonic
        const char* native_mnem = get_native_mnemonic(instr->mnemonic);
        
        // Write instruction
        if (strlen(instr->operands) > 0) {
            native_assembly_append(asm_out, "    %s %s\n", native_mnem, instr->operands);
        } else {
            native_assembly_append(asm_out, "    %s\n", native_mnem);
        }
    }
    
    native_assembly_append(asm_out, "\n; End of disassembly\n");
    
    return 1;
}

//=============================================================================
// File I/O
//=============================================================================

char* read_file(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    fread(buffer, 1, size, f);
    buffer[size] = '\0';
    fclose(f);
    
    return buffer;
}

int write_file(const char* filename, const char* content) {
    FILE* f = fopen(filename, "wb");
    if (!f) return 0;
    
    fwrite(content, 1, strlen(content), f);
    fclose(f);
    
    return 1;
}

//=============================================================================
// Main Entry Point
//=============================================================================

void print_usage(const char* prog) {
    printf("Codex-Native Bridge v%s\n", CODEX_BRIDGE_VERSION);
    printf("Usage: %s [options] <input> <output>\n", prog);
    printf("\nOptions:\n");
    printf("  /disasm <file>     Disassemble binary and output native ASM\n");
    printf("  /convert <file>    Convert Codex output to native ASM format\n");
    printf("  /format <type>     Input format: text|json (default: text)\n");
    printf("  /verify            Verify roundtrip (disasm->asm->assemble)\n");
    printf("\nExamples:\n");
    printf("  %s /convert codex_output.txt output.asm\n", prog);
    printf("  %s /disasm kernel32.dll kernel32.asm\n", prog);
}

int main(int argc, char* argv[]) {
    printf("=============================================================================\n");
    printf("  Codex-Native Bridge v%s\n", CODEX_BRIDGE_VERSION);
    printf("  RawrXD Native Toolchain Integration\n");
    printf("=============================================================================\n\n");
    
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* command = argv[1];
    const char* input_file = NULL;
    const char* output_file = NULL;
    const char* format = "text";
    int verify = 0;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "/convert") == 0 || strcmp(argv[i], "-convert") == 0) {
            if (i + 2 < argc) {
                input_file = argv[++i];
                output_file = argv[++i];
            }
        } else if (strcmp(argv[i], "/format") == 0 || strcmp(argv[i], "-format") == 0) {
            if (i + 1 < argc) {
                format = argv[++i];
            }
        } else if (strcmp(argv[i], "/verify") == 0 || strcmp(argv[i], "-verify") == 0) {
            verify = 1;
        }
    }
    
    if (!input_file || !output_file) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Read input file
    printf("[INFO] Reading: %s\n", input_file);
    char* input_content = read_file(input_file);
    if (!input_content) {
        printf("[ERROR] Cannot read input file: %s\n", input_file);
        return 1;
    }
    
    // Create disassembly container
    CodexDisassembly* disasm = codex_disassembly_create();
    if (!disasm) {
        printf("[ERROR] Failed to create disassembly container\n");
        free(input_content);
        return 1;
    }
    
    // Parse input
    printf("[INFO] Parsing Codex output (format: %s)...\n", format);
    int parsed_count = 0;
    if (strcmp(format, "json") == 0) {
        parsed_count = codex_parse_json(disasm, input_content);
    } else {
        parsed_count = codex_parse_text(disasm, input_content);
    }
    
    printf("[INFO] Parsed %d instructions\n", parsed_count);
    
    if (parsed_count == 0) {
        printf("[WARN] No instructions parsed - check input format\n");
        codex_disassembly_destroy(disasm);
        free(input_content);
        return 1;
    }
    
    // Create native assembly output
    NativeAssembly* asm_out = native_assembly_create();
    if (!asm_out) {
        printf("[ERROR] Failed to create assembly output\n");
        codex_disassembly_destroy(disasm);
        free(input_content);
        return 1;
    }
    
    // Convert to native format
    printf("[INFO] Converting to native assembler format...\n");
    if (!codex_to_native_asm(disasm, asm_out)) {
        printf("[ERROR] Conversion failed\n");
        native_assembly_destroy(asm_out);
        codex_disassembly_destroy(disasm);
        free(input_content);
        return 1;
    }
    
    // Write output
    printf("[INFO] Writing: %s\n", output_file);
    if (!write_file(output_file, asm_out->buffer)) {
        printf("[ERROR] Failed to write output file\n");
        native_assembly_destroy(asm_out);
        codex_disassembly_destroy(disasm);
        free(input_content);
        return 1;
    }
    
    printf("[SUCCESS] Converted %d instructions to native ASM format\n", parsed_count);
    printf("[OUTPUT] %s (%zu bytes)\n", output_file, strlen(asm_out->buffer));
    
    // Cleanup
    native_assembly_destroy(asm_out);
    codex_disassembly_destroy(disasm);
    free(input_content);
    
    // Verify if requested
    if (verify) {
        printf("\n[INFO] Verification mode enabled - would assemble and compare\n");
        // TODO: Call native assembler and compare byte output
    }
    
    return 0;
}
