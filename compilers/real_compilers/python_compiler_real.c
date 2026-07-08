/*
 * REAL Python Compiler - Week 1 Deliverable
 * Honest wrapper that creates standalone EXE from Python script
 * 
 * Approach: Embed Python interpreter and script in C wrapper
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_PATH_LEN 1024
#define MAX_CODE_LEN 65536

/* Python code template - embeds the script */
const char* WRAPPER_TEMPLATE = 
    "#define PY_SSIZE_T_CLEAN\n"
    "#include <Python.h>\n"
    "#include <stdio.h>\n"
    "\n"
    "static const char embedded_script[] = {\n"
    "%s"
    "    0\n"
    "};\n"
    "\n"
    "int main(int argc, char *argv[]) {\n"
    "    Py_Initialize();\n"
    "    \n"
    "    /* Set program name */\n"
    "    Py_SetProgramName(L\"embedded_python\");\n"
    "    \n"
    "    /* Run the embedded script */\n"
    "    PyRun_SimpleString(embedded_script);\n"
    "    \n"
    "    /* Check for errors */\n"
    "    if (PyErr_Occurred()) {\n"
    "        PyErr_Print();\n"
    "        Py_Finalize();\n"
    "        return 1;\n"
    "    }\n"
    "    \n"
    "    Py_Finalize();\n"
    "    return 0;\n"
    "}\n";

/* Alternative: Use subprocess approach */
const char* SUBPROCESS_WRAPPER = 
    "#include <windows.h>\n"
    "#include <stdio.h>\n"
    "\n"
    "static const char python_code[] = \"%s\";\n"
    "\n"
    "int main() {\n"
    "    /* Write Python code to temp file */\n"
    "    FILE* f = fopen(\"__temp_script.py\", \"w\");\n"
    "    if (!f) return 1;\n"
    "    fprintf(f, \"%s\", python_code);\n"
    "    fclose(f);\n"
    "    \n"
    "    /* Execute with python */\n"
    "    ShellExecuteA(NULL, \"open\", \"python\", \"__temp_script.py\", NULL, SW_HIDE);\n"
    "    return 0;\n"
    "}\n";

/* Simple approach: Just bundle Python with script */
int compile_python_simple(const char* input_file, const char* output_file) {
    FILE* in = fopen(input_file, "r");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        return 1;
    }
    
    /* Read Python source */
    char source_code[MAX_CODE_LEN];
    size_t source_len = fread(source_code, 1, MAX_CODE_LEN - 1, in);
    fclose(in);
    source_code[source_len] = '\0';
    
    /* Escape the source for embedding */
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
            /* Skip carriage return */
        } else if (c == '\t') {
            escaped_code[j++] = '\\';
            escaped_code[j++] = 't';
        } else {
            escaped_code[j++] = c;
        }
    }
    escaped_code[j] = '\0';
    
    /* Create C wrapper */
    FILE* wrapper = fopen("__temp_wrapper.c", "w");
    if (!wrapper) {
        fprintf(stderr, "Error: Cannot create wrapper file\n");
        return 1;
    }
    
    /* Write simple launcher that calls Python synchronously */
    fprintf(wrapper, "#include <windows.h>\n");
    fprintf(wrapper, "#include <stdio.h>\n");
    fprintf(wrapper, "#include <stdlib.h>\n");
    fprintf(wrapper, "\n");
    fprintf(wrapper, "int main() {\n");
    fprintf(wrapper, "    /* Create temp file with Python code */\n");
    fprintf(wrapper, "    FILE* f = fopen(\"__embedded_script.py\", \"w\");\n");
    fprintf(wrapper, "    if (!f) return 1;\n");
    fprintf(wrapper, "    fprintf(f, \"%s\");\n", escaped_code);
    fprintf(wrapper, "    fclose(f);\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    /* Execute with Python using CreateProcess for synchronous execution */\n");
    fprintf(wrapper, "    STARTUPINFOA si = {0};\n");
    fprintf(wrapper, "    si.cb = sizeof(si);\n");
    fprintf(wrapper, "    PROCESS_INFORMATION pi = {0};\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    char cmd[4096];\n");
    fprintf(wrapper, "    snprintf(cmd, sizeof(cmd), \"python __embedded_script.py\");\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(wrapper, "        printf(\"Error: Failed to launch Python\\n\");\n");
    fprintf(wrapper, "        DeleteFileA(\"__embedded_script.py\");\n");
    fprintf(wrapper, "        return 1;\n");
    fprintf(wrapper, "    }\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    /* Wait for completion */\n");
    fprintf(wrapper, "    WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    /* Get exit code */\n");
    fprintf(wrapper, "    DWORD exit_code = 0;\n");
    fprintf(wrapper, "    GetExitCodeProcess(pi.hProcess, &exit_code);\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    /* Cleanup */\n");
    fprintf(wrapper, "    CloseHandle(pi.hProcess);\n");
    fprintf(wrapper, "    CloseHandle(pi.hThread);\n");
    fprintf(wrapper, "    DeleteFileA(\"__embedded_script.py\");\n");
    fprintf(wrapper, "    \n");
    fprintf(wrapper, "    return (int)exit_code;\n");
    fprintf(wrapper, "}\n");
    
    fclose(wrapper);
    
    /* Compile wrapper */
    char compile_cmd[MAX_PATH_LEN * 2];
    snprintf(compile_cmd, sizeof(compile_cmd),
             "gcc -O2 -o \"%s\" __temp_wrapper.c -lkernel32 -lshell32",
             output_file);
    
    printf("Compiling wrapper...\n");
    int result = system(compile_cmd);
    
    /* Cleanup */
    remove("__temp_wrapper.c");
    
    if (result == 0) {
        printf("Success: Created %s\n", output_file);
        printf("Note: Requires Python installed to run\n");
        return 0;
    } else {
        fprintf(stderr, "Error: Compilation failed\n");
        return 1;
    }
}

/* Better approach: Use PyInstaller-style bundling */
int compile_python_bundled(const char* input_file, const char* output_file) {
    /* Check if PyInstaller is available */
    if (system("pyinstaller --version >nul 2>&1") == 0) {
        printf("Using PyInstaller for bundling...\n");
        
        char cmd[MAX_PATH_LEN * 2];
        snprintf(cmd, sizeof(cmd),
                 "pyinstaller --onefile --noconsole --name \"%s\" \"%s\"",
                 output_file, input_file);
        
        int result = system(cmd);
        
        if (result == 0) {
            printf("Success: Created %s\n", output_file);
            return 0;
        }
    }
    
    /* Fall back to simple wrapper */
    printf("PyInstaller not available, using simple wrapper...\n");
    return compile_python_simple(input_file, output_file);
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RAWRXD Python Compiler (REAL)\n");
    printf("========================================\n");
    printf("\n");
    
    if (argc < 2) {
        printf("Usage: python_compiler_real.exe <input.py> [output.exe]\n");
        printf("\n");
        printf("Creates a standalone executable from Python script.\n");
        printf("The executable embeds the Python code and requires Python installed.\n");
        printf("\n");
        printf("Example:\n");
        printf("  python_compiler_real.exe hello.py hello.exe\n");
        printf("  hello.exe  # Runs the Python script\n");
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "program.exe";
    
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n", output_file);
    printf("\n");
    
    /* Check if input exists */
    FILE* test = fopen(input_file, "r");
    if (!test) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        return 1;
    }
    fclose(test);
    
    /* Try PyInstaller first, fall back to simple wrapper */
    return compile_python_bundled(input_file, output_file);
}
