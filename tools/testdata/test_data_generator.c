//=============================================================================
// test_data_generator.c - Test Data Generator
// Production-ready test data generation for fuzzing and testing
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h

//=============================================================================
// Generator Configuration
//=============================================================================

#define MAX_STRING_LENGTH 1024
#define MAX_ARRAY_SIZE 1000

typedef enum {
    GEN_TYPE_INT,
    GEN_TYPE_FLOAT,
    GEN_TYPE_STRING,
    GEN_TYPE_BOOL,
    GEN_TYPE_ARRAY,
    GEN_TYPE_BINARY
} DataType;

typedef struct {
    int seed;
    int min_int;
    int max_int;
    double min_float;
    double max_float;
    int min_string_len;
    int max_string_len;
    int min_array_size;
    int max_array_size;
} GeneratorConfig;

//=============================================================================
// Random Number Generation
//=============================================================================

static uint32_t g_seed = 0;

void init_random(int seed) {
    g_seed = seed ? seed : (uint32_t)time(NULL);
    srand(g_seed);
}

uint32_t random_u32(void) {
    return (uint32_t)rand();
}

int random_int(int min, int max) {
    if (min >= max) return min;
    return min + (rand() % (max - min + 1));
}

double random_double(double min, double max) {
    if (min >= max) return min;
    return min + ((double)rand() / RAND_MAX) * (max - min);
}

//=============================================================================
// String Generation
//=============================================================================

void generate_random_string(char* buffer, int min_len, int max_len, int printable_only) {
    int len = random_int(min_len, max_len);
    
    for (int i = 0; i < len; i++) {
        if (printable_only) {
            // Printable ASCII: 32-126
            buffer[i] = (char)random_int(32, 126);
        } else {
            // Any byte
            buffer[i] = (char)random_int(0, 255);
        }
    }
    buffer[len] = '\0';
}

void generate_alpha_string(char* buffer, int min_len, int max_len) {
    int len = random_int(min_len, max_len);
    const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int char_count = strlen(chars);
    
    for (int i = 0; i < len; i++) {
        buffer[i] = chars[random_int(0, char_count - 1)];
    }
    buffer[len] = '\0';
}

void generate_alphanumeric_string(char* buffer, int min_len, int max_len) {
    int len = random_int(min_len, max_len);
    const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int char_count = strlen(chars);
    
    for (int i = 0; i < len; i++) {
        buffer[i] = chars[random_int(0, char_count - 1)];
    }
    buffer[len] = '\0';
}

void generate_hex_string(char* buffer, int min_len, int max_len) {
    int len = random_int(min_len, max_len);
    const char* chars = "0123456789abcdef";
    
    for (int i = 0; i < len; i++) {
        buffer[i] = chars[random_int(0, 15)];
    }
    buffer[len] = '\0';
}

void generate_email(char* buffer, int max_len) {
    char local[64], domain[64], tld[16];
    generate_alphanumeric_string(local, 5, 20);
    generate_alpha_string(domain, 5, 15);
    const char* tlds[] = {"com", "org", "net", "edu", "io"};
    strncpy(tld, tlds[random_int(0, 4)], sizeof(tld) - 1);
    
    snprintf(buffer, max_len, "%s@%s.%s", local, domain, tld);
}

void generate_url(char* buffer, int max_len) {
    const char* protocols[] = {"http", "https"};
    const char* tlds[] = {"com", "org", "net", "io", "dev"};
    
    char domain[64];
    generate_alphanumeric_string(domain, 5, 20);
    
    snprintf(buffer, max_len, "%s://www.%s.%s",
             protocols[random_int(0, 1)],
             domain,
             tlds[random_int(0, 4)]);
}

//=============================================================================
// Assembly Code Generation
//=============================================================================

void generate_assembly_instruction(char* buffer, int max_len) {
    const char* instructions[] = {
        "mov", "add", "sub", "mul", "div",
        "and", "or", "xor", "not", "shl", "shr",
        "jmp", "je", "jne", "jg", "jl",
        "push", "pop", "call", "ret", "nop"
    };
    
    const char* registers[] = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    
    const char* instr = instructions[random_int(0, sizeof(instructions)/sizeof(instructions[0]) - 1)];
    
    int variant = random_int(0, 3);
    switch (variant) {
        case 0: // reg, reg
            snprintf(buffer, max_len, "%s %s, %s",
                    instr, registers[random_int(0, 13)], registers[random_int(0, 13)]);
            break;
        case 1: // reg, imm
            snprintf(buffer, max_len, "%s %s, 0x%x",
                    instr, registers[random_int(0, 13)], random_int(0, 0xFFFF));
            break;
        case 2: // reg
            snprintf(buffer, max_len, "%s %s",
                    instr, registers[random_int(0, 13)]);
            break;
        default: // no operands
            snprintf(buffer, max_len, "%s", instr);
            break;
    }
}

void generate_assembly_program(char* buffer, int max_len, int num_instructions) {
    int pos = 0;
    
    // Header
    pos += snprintf(buffer + pos, max_len - pos, "; Generated test program\n");
    pos += snprintf(buffer + pos, max_len - pos, "; Instructions: %d\n\n", num_instructions);
    
    // Instructions
    for (int i = 0; i < num_instructions && pos < max_len - 100; i++) {
        char instr[256];
        generate_assembly_instruction(instr, sizeof(instr));
        pos += snprintf(buffer + pos, max_len - pos, "%s\n", instr);
    }
    
    // Footer
    pos += snprintf(buffer + pos, max_len - pos, "ret\n");
}

//=============================================================================
// C Code Generation
//=============================================================================

void generate_c_expression(char* buffer, int max_len, int depth) {
    if (depth <= 0) {
        int variant = random_int(0, 2);
        switch (variant) {
            case 0:
                snprintf(buffer, max_len, "%d", random_int(0, 100));
                break;
            case 1:
                snprintf(buffer, max_len, "x%d", random_int(0, 10));
                break;
            default:
                snprintf(buffer, max_len, "(%d)", random_int(0, 100));
                break;
        }
        return;
    }
    
    const char* operators[] = {"+", "-", "*", "/", "%", "&", "|", "^"};
    const char* op = operators[random_int(0, 7)];
    
    char left[256], right[256];
    generate_c_expression(left, sizeof(left), depth - 1);
    generate_c_expression(right, sizeof(right), depth - 1);
    
    snprintf(buffer, max_len, "(%s %s %s)", left, op, right);
}

void generate_c_function(char* buffer, int max_len) {
    char name[64];
    generate_alpha_string(name, 5, 20);
    name[0] = tolower(name[0]);
    
    int num_params = random_int(0, 4);
    
    int pos = 0;
    pos += snprintf(buffer + pos, max_len - pos, "int %s(", name);
    
    for (int i = 0; i < num_params; i++) {
        if (i > 0) pos += snprintf(buffer + pos, max_len - pos, ", ");
        pos += snprintf(buffer + pos, max_len - pos, "int arg%d", i);
    }
    
    if (num_params == 0) {
        pos += snprintf(buffer + pos, max_len - pos, "void");
    }
    
    pos += snprintf(buffer + pos, max_len - pos, ") {\n");
    
    // Generate body
    int num_lines = random_int(1, 10);
    for (int i = 0; i < num_lines; i++) {
        int stmt_type = random_int(0, 3);
        switch (stmt_type) {
            case 0: { // Variable declaration
                char expr[256];
                generate_c_expression(expr, sizeof(expr), 2);
                pos += snprintf(buffer + pos, max_len - pos, "    int var%d = %s;\n", i, expr);
                break;
            }
            case 1: { // Assignment
                char expr[256];
                generate_c_expression(expr, sizeof(expr), 2);
                pos += snprintf(buffer + pos, max_len - pos, "    var%d = %s;\n", i, expr);
                break;
            }
            case 2: { // If statement
                char expr[256];
                generate_c_expression(expr, sizeof(expr), 2);
                pos += snprintf(buffer + pos, max_len - pos, "    if (%s) {\n", expr);
                pos += snprintf(buffer + pos, max_len - pos, "        // Branch %d\n", i);
                pos += snprintf(buffer + pos, max_len - pos, "    }\n");
                break;
            }
            default: // Comment
                pos += snprintf(buffer + pos, max_len - pos, "    // Line %d\n", i);
                break;
        }
    }
    
    pos += snprintf(buffer + pos, max_len - pos, "    return %d;\n", random_int(0, 100));
    pos += snprintf(buffer + pos, max_len - pos, "}\n");
}

//=============================================================================
// Binary Data Generation
//=============================================================================

void generate_binary_data(uint8_t* buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (uint8_t)random_int(0, 255);
    }
}

void generate_coff_header(uint8_t* buffer, size_t max_size) {
    if (max_size < 20) return;
    
    // COFF header for x64
    buffer[0] = 0x64; buffer[1] = 0x86; // Machine: AMD64
    buffer[2] = 0x01; buffer[3] = 0x00; // Number of sections: 1
    buffer[4] = 0x00; buffer[5] = 0x00; buffer[6] = 0x00; buffer[7] = 0x00; // Timestamp
    buffer[8] = 0x00; buffer[9] = 0x00; buffer[10] = 0x00; buffer[11] = 0x00; // Symbol table
    buffer[12] = 0x00; buffer[13] = 0x00; buffer[14] = 0x00; buffer[15] = 0x00; // Symbol count
    buffer[16] = 0x00; buffer[17] = 0x00; // Optional header size
    buffer[18] = 0x00; buffer[19] = 0x00; // Characteristics
}

//=============================================================================
// File Output
//=============================================================================

void write_test_file(const char* filename, const char* content) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    fprintf(f, "%s", content);
    fclose(f);
    printf("  Generated: %s\n", filename);
}

void write_binary_file(const char* filename, const uint8_t* data, size_t size) {
    FILE* f = fopen(filename, "wb");
    if (!f) return;
    fwrite(data, 1, size, f);
    fclose(f);
    printf("  Generated: %s (%zu bytes)\n", filename, size);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Test Data Generator\n");
    printf("==========================\n\n");
    
    int seed = 0;
    int count = 10;
    const char* output_dir = "test_data";
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        }
    }
    
    // Initialize random
    init_random(seed);
    printf("Seed: %d\n", g_seed);
    printf("Count: %d\n", count);
    printf("Output: %s\n\n", output_dir);
    
    // Create output directory
    #ifdef _WIN32
    CreateDirectoryA(output_dir, NULL);
    #else
    mkdir(output_dir, 0755);
    #endif
    
    char path[512];
    
    // Generate assembly files
    printf("Generating assembly test files...\n");
    for (int i = 0; i < count; i++) {
        char content[4096];
        generate_assembly_program(content, sizeof(content), random_int(10, 100));
        
        snprintf(path, sizeof(path), "%s%sasm_test_%d.asm", output_dir, PATH_SEP, i);
        write_test_file(path, content);
    }
    
    // Generate C files
    printf("\nGenerating C test files...\n");
    for (int i = 0; i < count / 2; i++) {
        char content[4096];
        generate_c_function(content, sizeof(content));
        
        snprintf(path, sizeof(path), "%s%sc_test_%d.c", output_dir, PATH_SEP, i);
        write_test_file(path, content);
    }
    
    // Generate binary files
    printf("\nGenerating binary test files...\n");
    for (int i = 0; i < count / 5; i++) {
        uint8_t data[256];
        generate_coff_header(data, sizeof(data));
        generate_binary_data(data + 20, sizeof(data) - 20);
        
        snprintf(path, sizeof(path), "%s%sobj_test_%d.obj", output_dir, PATH_SEP, i);
        write_binary_file(path, data, sizeof(data));
    }
    
    // Generate string data
    printf("\nGenerating string test data...\n");
    {
        char content[4096];
        int pos = 0;
        
        pos += snprintf(content + pos, sizeof(content) - pos, "# Test String Data\n\n");
        
        for (int i = 0; i < 100; i++) {
            char email[256], url[256], hex[64], alpha[64];
            generate_email(email, sizeof(email));
            generate_url(url, sizeof(url));
            generate_hex_string(hex, 8, 32);
            generate_alpha_string(alpha, 5, 20);
            
            pos += snprintf(content + pos, sizeof(content) - pos,
                          "email_%d: %s\nurl_%d: %s\nhex_%d: %s\nalpha_%d: %s\n\n",
                          i, email, i, url, i, hex, i, alpha);
        }
        
        snprintf(path, sizeof(path), "%s%sstrings.txt", output_dir, PATH_SEP);
        write_test_file(path, content);
    }
    
    printf("\nTest data generation complete!\n");
    printf("Generated files in: %s\n", output_dir);
    
    return 0;
}
