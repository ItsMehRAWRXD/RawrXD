/*
 * REAL Bash Compiler - Creates EXE from Bash script
 * Embeds bash script in C wrapper for WSL/Git Bash
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_CODE_LEN 65536

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RAWRXD Bash Compiler (REAL)\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: bash_compiler_real.exe <input.sh> [output.exe]\n\n");
        printf("Creates executable from Bash script.\n");
        printf("Requires WSL or Git Bash to run.\n");
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "program.exe";
    
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n\n", output_file);
    
    // Read bash script
    FILE* in = fopen(input_file, "r");
    if (!in) {
        fprintf(stderr, "Error: Cannot open %s\n", input_file);
        return 1;
    }
    
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
    
    // Create wrapper that tries WSL first, then Git Bash
    FILE* f = fopen("__bash_wrapper.c", "w");
    if (!f) { fprintf(stderr, "Error: Cannot create wrapper\n"); return 1; }
    
    fprintf(f, "#include <windows.h>\n#include <stdio.h>\n\n");
    fprintf(f, "int main() {\n");
    fprintf(f, "    FILE* f = fopen(\"__temp.sh\", \"wb\");\n");
    fprintf(f, "    if (!f) return 1;\n");
    fprintf(f, "    const char* script = \"%s\";\n", escaped);
    fprintf(f, "    // Write with Unix line endings\n");
    fprintf(f, "    for (const char* p = script; *p; p++) {\n");
    fprintf(f, "        if (*p == '\\\\' && *(p+1) == 'n') { fputc('\\n', f); p++; }\n");
    fprintf(f, "        else { fputc(*p, f); }\n");
    fprintf(f, "    }\n");
    fprintf(f, "    fclose(f);\n\n");
    
    // Try WSL first
    fprintf(f, "    STARTUPINFOA si = {0}; si.cb = sizeof(si);\n");
    fprintf(f, "    PROCESS_INFORMATION pi = {0};\n");
    fprintf(f, "    char cmd[4096];\n\n");
    
    fprintf(f, "    // Try WSL bash\n");
    fprintf(f, "    snprintf(cmd, sizeof(cmd), \"wsl bash __temp.sh\");\n");
    fprintf(f, "    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "        WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "        DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);\n");
    fprintf(f, "        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n");
    fprintf(f, "        DeleteFileA(\"__temp.sh\"); return (int)code;\n");
    fprintf(f, "    }\n\n");
    
    // Try Git Bash
    fprintf(f, "    // Try Git Bash\n");
    fprintf(f, "    snprintf(cmd, sizeof(cmd), \"\\\"C:\\\\Program Files\\\\Git\\\\bin\\\\bash.exe\\\" __temp.sh\");\n");
    fprintf(f, "    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "        WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "        DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);\n");
    fprintf(f, "        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n");
    fprintf(f, "        DeleteFileA(\"__temp.sh\"); return (int)code;\n");
    fprintf(f, "    }\n\n");
    
    fprintf(f, "    printf(\"Error: No bash found. Install WSL or Git Bash.\\n\");\n");
    fprintf(f, "    DeleteFileA(\"__temp.sh\");\n");
    fprintf(f, "    return 1;\n");
    fprintf(f, "}\n");
    fclose(f);
    
    // Compile
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "gcc -O2 -o \"%s\" __bash_wrapper.c", output_file);
    int result = system(cmd);
    remove("__bash_wrapper.c");
    
    if (result == 0) {
        printf("Success: Created %s\n", output_file);
        printf("Note: Requires WSL or Git Bash\n");
        return 0;
    }
    return 1;
}
