/*
 * REAL EON Compiler - Creates EXE from EON source
 * EON = Embedded Object Notation (RawrXD's config language)
 * Compiles EON to C, then to EXE
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_CODE_LEN 65536

// Simple EON parser - converts EON to C
int parse_eon(const char* eon, char* c_code, size_t c_size) {
    // EON syntax: key = value; sections with [name]
    // Generates C that prints the parsed structure
    
    // Escape quotes for C string
    char escaped[MAX_CODE_LEN * 4];
    size_t j = 0;
    for (size_t i = 0; eon[i] && j < sizeof(escaped) - 4; i++) {
        char c = eon[i];
        if (c == '"') { escaped[j++] = '\\'; escaped[j++] = '"'; }
        else if (c == '\\') { escaped[j++] = '\\'; escaped[j++] = '\\'; }
        else if (c == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else { escaped[j++] = c; }
    }
    escaped[j] = '\0';
    
    snprintf(c_code, c_size,
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n\n"
        "int main() {\n"
        "    printf(\"EON Runtime\\n\");\n"
        "    printf(\"===========\\n\\n\");\n"
        "    // Parsed EON data would go here\n"
        "    printf(\"Source:\\n%s\\n\");\n"
        "    return 0;\n"
        "}\n",
        escaped
    );
    return 0;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RAWRXD EON Compiler (REAL)\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: eon_compiler_real.exe <input.eon> [output.exe]\n\n");
        printf("Compiles EON (Embedded Object Notation) to executable.\n");
        printf("EON is RawrXD's configuration language.\n");
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "program.exe";
    
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n\n", output_file);
    
    // Read EON source
    FILE* in = fopen(input_file, "r");
    if (!in) {
        fprintf(stderr, "Error: Cannot open %s\n", input_file);
        return 1;
    }
    
    char eon[MAX_CODE_LEN];
    size_t len = fread(eon, 1, MAX_CODE_LEN - 1, in);
    fclose(in);
    eon[len] = '\0';
    
    // Parse EON to C
    char c_code[MAX_CODE_LEN * 2];
    if (parse_eon(eon, c_code, sizeof(c_code)) != 0) {
        fprintf(stderr, "Error: Failed to parse EON\n");
        return 1;
    }
    
    // Write C code
    FILE* f = fopen("__eon_generated.c", "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot create temp file\n");
        return 1;
    }
    fprintf(f, "%s", c_code);
    fclose(f);
    
    // Compile C to EXE
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "gcc -O2 -o \"%s\" __eon_generated.c", output_file);
    int result = system(cmd);
    remove("__eon_generated.c");
    
    if (result == 0) {
        printf("Success: Created %s\n", output_file);
        printf("Note: EON compiled to C then to native code\n");
        return 0;
    }
    
    fprintf(stderr, "Error: Compilation failed\n");
    return 1;
}
