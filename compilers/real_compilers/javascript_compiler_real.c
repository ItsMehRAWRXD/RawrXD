/*
 * REAL JavaScript Compiler - Week 1, Day 2
 * Honest wrapper that creates standalone EXE from JS using Node.js
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_PATH_LEN 1024
#define MAX_CODE_LEN 65536

/* Find node.exe */
int find_node(char* node_path, size_t path_size) {
    const char* locations[] = {
        "C:\\Program Files\\nodejs\\node.exe",
        "C:\\Program Files (x86)\\nodejs\\node.exe",
        "C:\\nodejs\\node.exe",
        "node.exe"  // Try PATH
    };
    
    for (int i = 0; i < sizeof(locations)/sizeof(locations[0]); i++) {
        if (GetFileAttributesA(locations[i]) != INVALID_FILE_ATTRIBUTES) {
            strncpy(node_path, locations[i], path_size);
            node_path[path_size-1] = '\0';
            return 0;
        }
    }
    
    return -1;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RAWRXD JavaScript Compiler (REAL)\n");
    printf("========================================\n");
    printf("\n");
    
    if (argc < 2) {
        printf("Usage: javascript_compiler_real.exe <input.js> [output.exe]\n");
        printf("\n");
        printf("Creates a standalone executable from JavaScript using Node.js\n");
        printf("\n");
        printf("Example:\n");
        printf("  javascript_compiler_real.exe hello.js hello.exe\n");
        printf("  hello.exe  # Runs the JavaScript\n");
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "program.exe";
    
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n", output_file);
    printf("\n");
    
    // Check if input exists
    if (GetFileAttributesA(input_file) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: Input file not found: %s\n", input_file);
        return 1;
    }
    
    // Find Node.js
    char node_path[MAX_PATH_LEN];
    if (find_node(node_path, sizeof(node_path)) != 0) {
        fprintf(stderr, "Error: Cannot find node.exe\n");
        fprintf(stderr, "Please install Node.js from https://nodejs.org/\n");
        return 1;
    }
    
    printf("Using Node.js: %s\n", node_path);
    
    // Read JavaScript source
    FILE* in = fopen(input_file, "r");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file\n");
        return 1;
    }
    
    char source_code[MAX_CODE_LEN];
    size_t source_len = fread(source_code, 1, MAX_CODE_LEN - 1, in);
    fclose(in);
    source_code[source_len] = '\0';
    
    // Escape for C string
    char escaped_code[MAX_CODE_LEN * 4];
    size_t j = 0;
    for (size_t i = 0; i < source_len && j < sizeof(escaped_code) - 4; i++) {
        char c = source_code[i];
        if (c == '"') {
            escaped_code[j++] = '\\';
            escaped_code[j++] = '"';
        } else if (c == '\\') {
            escaped_code[j++] = '\\';
            escaped_code[j++] = '\\';
        } else if (c == '\n') {
            escaped_code[j++] = '\\';
            escaped_code[j++] = 'n';
        } else if (c == '\r') {
            // Skip
        } else if (c == '\t') {
            escaped_code[j++] = '\\';
            escaped_code[j++] = 't';
        } else {
            escaped_code[j++] = c;
        }
    }
    escaped_code[j] = '\0';
    
    // Create C wrapper
    FILE* wrapper = fopen("__js_wrapper.c", "w");
    if (!wrapper) {
        fprintf(stderr, "Error: Cannot create wrapper file\n");
        return 1;
    }
    
    fprintf(wrapper, "#include <windows.h>\n");
    fprintf(wrapper, "#include <stdio.h>\n");
    fprintf(wrapper, "#include <stdlib.h>\n");
    fprintf(wrapper, "\n");
    fprintf(wrapper, "int main(int argc, char* argv[]) {\n");
    fprintf(wrapper, "    /* Create temp file with JS code */\n");
    fprintf(wrapper, "    FILE* f = fopen(\"__embedded_script.js\", \"w\");\n");
    fprintf(wrapper, "    if (!f) return 1;\n");
    fprintf(wrapper, "    fprintf(f, \"%s\");\n", escaped_code);
    fprintf(wrapper, "    fclose(f);\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    /* Execute with Node.js */\n");
    fprintf(wrapper, "    STARTUPINFOA si = {0};\n");
    fprintf(wrapper, "    si.cb = sizeof(si);\n");
    fprintf(wrapper, "    PROCESS_INFORMATION pi = {0};\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    char cmd[4096];\n");
    // Escape backslashes in node_path for C string
    char node_path_escaped[MAX_PATH_LEN * 2];
    size_t k = 0;
    for (size_t i = 0; i < strlen(node_path) && k < sizeof(node_path_escaped) - 2; i++) {
        if (node_path[i] == '\\') {
            node_path_escaped[k++] = '\\';
            node_path_escaped[k++] = '\\';
        } else {
            node_path_escaped[k++] = node_path[i];
        }
    }
    node_path_escaped[k] = '\0';
    fprintf(wrapper, "    snprintf(cmd, sizeof(cmd), \"\\\"%s\\\" \\\"__embedded_script.js\\\"\");\n", node_path_escaped);
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(wrapper, "        printf(\"Error: Failed to launch Node.js\\n\");\n");
    fprintf(wrapper, "        DeleteFileA(\"__embedded_script.js\");\n");
    fprintf(wrapper, "        return 1;\n");
    fprintf(wrapper, "    }\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    DWORD exit_code = 0;\n");
    fprintf(wrapper, "    GetExitCodeProcess(pi.hProcess, &exit_code);\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    CloseHandle(pi.hProcess);\n");
    fprintf(wrapper, "    CloseHandle(pi.hThread);\n");
    fprintf(wrapper, "    DeleteFileA(\"__embedded_script.js\");\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    return (int)exit_code;\n");
    fprintf(wrapper, "}\n");
    
    fclose(wrapper);
    
    // Compile wrapper
    char compile_cmd[MAX_PATH_LEN * 2];
    snprintf(compile_cmd, sizeof(compile_cmd),
             "gcc -O2 -o \"%s\" __js_wrapper.c -lkernel32",
             output_file);
    
    printf("Compiling wrapper...\n");
    int result = system(compile_cmd);
    
    // Cleanup
    remove("__js_wrapper.c");
    
    if (result == 0) {
        printf("\n");
        printf("========================================\n");
        printf("Success: Created %s\n", output_file);
        printf("========================================\n");
        printf("\n");
        printf("Note: Requires Node.js installed to run\n");
        return 0;
    } else {
        fprintf(stderr, "Error: Compilation failed\n");
        return 1;
    }
}
