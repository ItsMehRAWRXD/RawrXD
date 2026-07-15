/*
 * REAL C# Compiler - Creates EXE from C# source
 * Embeds C# source and compiles with csc.exe
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_CODE_LEN 65536

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RAWRXD C# Compiler (REAL)\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: csharp_compiler_real.exe <input.cs> [output.exe]\n\n");
        printf("Creates executable from C# source.\n");
        printf("Requires .NET SDK or csc.exe.\n");
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "program.exe";
    
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n\n", output_file);
    
    // Read C# source
    FILE* in = fopen(input_file, "r");
    if (!in) {
        fprintf(stderr, "Error: Cannot open %s\n", input_file);
        return 1;
    }
    
    char source[MAX_CODE_LEN];
    size_t len = fread(source, 1, MAX_CODE_LEN - 1, in);
    fclose(in);
    source[len] = '\0';
    
    // Escape for C string
    char escaped[MAX_CODE_LEN * 4];
    size_t j = 0;
    for (size_t i = 0; i < len && j < sizeof(escaped) - 4; i++) {
        char c = source[i];
        if (c == '"') { escaped[j++] = '\\'; escaped[j++] = '"'; }
        else if (c == '\\') { escaped[j++] = '\\'; escaped[j++] = '\\'; }
        else if (c == '\n') { escaped[j++] = '\\'; escaped[j++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else { escaped[j++] = c; }
    }
    escaped[j] = '\0';
    
    // Create wrapper that compiles and runs C#
    FILE* f = fopen("__cs_wrapper.c", "w");
    if (!f) { fprintf(stderr, "Error: Cannot create wrapper\n"); return 1; }
    
    fprintf(f, "#include <windows.h>\n#include <stdio.h>\n\n");
    fprintf(f, "int main() {\n");
    fprintf(f, "    // Write C# source\n");
    fprintf(f, "    FILE* f = fopen(\"__temp.cs\", \"w\");\n");
    fprintf(f, "    if (!f) return 1;\n");
    fprintf(f, "    fprintf(f, \"%s\");\n", escaped);
    fprintf(f, "    fclose(f);\n\n");
    
    fprintf(f, "    // Try to compile with csc.exe\n");
    fprintf(f, "    STARTUPINFOA si = {0}; si.cb = sizeof(si);\n");
    fprintf(f, "    PROCESS_INFORMATION pi = {0};\n");
    fprintf(f, "    char cmd[4096];\n\n");
    
    // Try dotnet CLI first
    fprintf(f, "    // Try dotnet CLI\n");
    fprintf(f, "    snprintf(cmd, sizeof(cmd), \"dotnet build __temp.cs -o . --no-restore 2>nul\");\n");
    fprintf(f, "    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "        WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "        DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);\n");
    fprintf(f, "        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n");
    fprintf(f, "        if (code == 0) {\n");
    fprintf(f, "            // Run the compiled exe\n");
    fprintf(f, "            snprintf(cmd, sizeof(cmd), \"__temp.exe\");\n");
    fprintf(f, "            if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "                WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "                GetExitCodeProcess(pi.hProcess, &code);\n");
    fprintf(f, "                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n");
    fprintf(f, "            }\n");
    fprintf(f, "            DeleteFileA(\"__temp.cs\"); DeleteFileA(\"__temp.exe\");\n");
    fprintf(f, "            return (int)code;\n");
    fprintf(f, "        }\n");
    fprintf(f, "    }\n\n");
    
    // Try csc.exe
    fprintf(f, "    // Try csc.exe\n");
    fprintf(f, "    snprintf(cmd, sizeof(cmd), \"csc.exe __temp.cs /out:__temp.exe 2>nul\");\n");
    fprintf(f, "    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "        WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "        DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);\n");
    fprintf(f, "        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n");
    fprintf(f, "        if (code == 0) {\n");
    fprintf(f, "            // Run the compiled exe\n");
    fprintf(f, "            snprintf(cmd, sizeof(cmd), \"__temp.exe\");\n");
    fprintf(f, "            if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "                WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "                GetExitCodeProcess(pi.hProcess, &code);\n");
    fprintf(f, "                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);\n");
    fprintf(f, "            }\n");
    fprintf(f, "            DeleteFileA(\"__temp.cs\"); DeleteFileA(\"__temp.exe\");\n");
    fprintf(f, "            return (int)code;\n");
    fprintf(f, "        }\n");
    fprintf(f, "    }\n\n");
    
    fprintf(f, "    printf(\"Error: No C# compiler found. Install .NET SDK.\\n\");\n");
    fprintf(f, "    DeleteFileA(\"__temp.cs\");\n");
    fprintf(f, "    return 1;\n");
    fprintf(f, "}\n");
    fclose(f);
    
    // Compile wrapper
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "gcc -O2 -o \"%s\" __cs_wrapper.c", output_file);
    int result = system(cmd);
    remove("__cs_wrapper.c");
    
    if (result == 0) {
        printf("Success: Created %s\n", output_file);
        printf("Note: Requires .NET SDK or csc.exe\n");
        return 0;
    }
    return 1;
}
