/*
 * REAL PowerShell Compiler - Creates EXE from PS script
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_CODE_LEN 65536

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RAWRXD PowerShell Compiler (REAL)\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: powershell_compiler_real.exe <input.ps1> [output.exe]\n\n");
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "program.exe";
    
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n\n", output_file);
    
    // Read script
    FILE* in = fopen(input_file, "r");
    if (!in) { fprintf(stderr, "Error: Cannot open %s\n", input_file); return 1; }
    
    char script[MAX_CODE_LEN];
    size_t len = fread(script, 1, MAX_CODE_LEN - 1, in);
    fclose(in);
    script[len] = '\0';
    
    // Escape for C string
    char escaped[MAX_CODE_LEN * 4];
    size_t j = 0;
    for (size_t i = 0; i < len && j < sizeof(escaped) - 4; i++) {
        char c = script[i];
        if (c == '"') { escaped[j++] = '\\'; escaped[j++] = '"'; }
        else if (c == '\\') { escaped[j++] = '\\'; escaped[j++] = '\\'; }
        else if (c == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else { escaped[j++] = c; }
    }
    escaped[j] = '\0';
    
    // Create wrapper
    FILE* f = fopen("__ps_wrapper.c", "w");
    if (!f) { fprintf(stderr, "Error: Cannot create wrapper\n"); return 1; }
    
    fprintf(f, "#include <windows.h>\n#include <stdio.h>\n\n");
    fprintf(f, "int main() {\n");
    fprintf(f, "    FILE* f = fopen(\"__temp.ps1\", \"w\");\n");
    fprintf(f, "    if (!f) return 1;\n");
    fprintf(f, "    fprintf(f, \"%s\");\n", escaped);
    fprintf(f, "    fclose(f);\n\n");
    
    fprintf(f, "    STARTUPINFOA si = {0}; si.cb = sizeof(si);\n");
    fprintf(f, "    PROCESS_INFORMATION pi = {0};\n");
    fprintf(f, "    char cmd[4096];\n");
    fprintf(f, "    snprintf(cmd, sizeof(cmd), \"powershell -ExecutionPolicy Bypass -File __temp.ps1\");\n");
    fprintf(f, "    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "        DeleteFileA(\"__temp.ps1\"); return 1;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);\n");
    fprintf(f, "    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n");
    fprintf(f, "    DeleteFileA(\"__temp.ps1\");\n");
    fprintf(f, "    return (int)code;\n");
    fprintf(f, "}\n");
    fclose(f);
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "gcc -O2 -o \"%s\" __ps_wrapper.c", output_file);
    int result = system(cmd);
    remove("__ps_wrapper.c");
    
    if (result == 0) {
        printf("Success: Created %s\n", output_file);
        printf("Note: Requires PowerShell\n");
        return 0;
    }
    return 1;
}
