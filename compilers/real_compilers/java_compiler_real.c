/*
 * REAL Java Compiler - Week 1, Day 2
 * Honest wrapper that compiles Java to EXE via javac + launcher
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_PATH_LEN 1024
#define MAX_CMD_LEN 4096

/* Find javac.exe in PATH or common locations */
int find_javac(char* javac_path, size_t path_size) {
    // Try common locations
    const char* locations[] = {
        "C:\\Program Files\\Java\\jdk-21\\bin\\javac.exe",
        "C:\\Program Files\\Java\\jdk-17\\bin\\javac.exe",
        "C:\\Program Files\\Java\\jdk-11\\bin\\javac.exe",
        "C:\\Program Files\\Java\\jdk-1.8\\bin\\javac.exe",
        "C:\\Program Files\\Eclipse Adoptium\\jdk-21\\bin\\javac.exe",
        "C:\\Program Files\\Eclipse Adoptium\\jdk-17\\bin\\javac.exe",
        "javac.exe"  // Try PATH last
    };
    
    for (int i = 0; i < sizeof(locations)/sizeof(locations[0]); i++) {
        if (GetFileAttributesA(locations[i]) != INVALID_FILE_ATTRIBUTES) {
            strncpy(javac_path, locations[i], path_size);
            javac_path[path_size-1] = '\0';
            return 0;
        }
    }
    
    return -1;
}

/* Find java.exe */
int find_java(char* java_path, size_t path_size) {
    const char* locations[] = {
        "C:\\Program Files\\Java\\jdk-21\\bin\\java.exe",
        "C:\\Program Files\\Java\\jdk-17\\bin\\java.exe",
        "C:\\Program Files\\Java\\jdk-11\\bin\\java.exe",
        "C:\\Program Files\\Java\\jdk-1.8\\bin\\java.exe",
        "C:\\Program Files\\Eclipse Adoptium\\jdk-21\\bin\\java.exe",
        "C:\\Program Files\\Eclipse Adoptium\\jdk-17\\bin\\java.exe",
        "java.exe"
    };
    
    for (int i = 0; i < sizeof(locations)/sizeof(locations[0]); i++) {
        if (GetFileAttributesA(locations[i]) != INVALID_FILE_ATTRIBUTES) {
            strncpy(java_path, locations[i], path_size);
            java_path[path_size-1] = '\0';
            return 0;
        }
    }
    
    return -1;
}

/* Compile Java source to class file */
int compile_java(const char* input_file, const char* class_name) {
    char javac_path[MAX_PATH_LEN];
    
    if (find_javac(javac_path, sizeof(javac_path)) != 0) {
        fprintf(stderr, "Error: Cannot find javac.exe\n");
        fprintf(stderr, "Please install Java JDK and ensure it's in PATH\n");
        return 1;
    }
    
    printf("Using javac: %s\n", javac_path);
    
    // Build compile command - use quotes properly for paths with spaces
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\"", javac_path, input_file);
    
    printf("Compiling: %s\n", input_file);
    printf("Command: %s\n", cmd);
    
    // Execute javac
    int result = system(cmd);
    if (result != 0) {
        fprintf(stderr, "Error: Java compilation failed\n");
        return 1;
    }
    
    // Check if .class file was created
    char class_file[MAX_PATH_LEN];
    snprintf(class_file, sizeof(class_file), "%s.class", class_name);
    
    if (GetFileAttributesA(class_file) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: Class file not created: %s\n", class_file);
        return 1;
    }
    
    printf("Created: %s\n", class_file);
    return 0;
}

/* Create C wrapper that launches Java class */
int create_wrapper(const char* class_name, const char* output_file) {
    char java_path[MAX_PATH_LEN];
    
    if (find_java(java_path, sizeof(java_path)) != 0) {
        fprintf(stderr, "Error: Cannot find java.exe\n");
        return 1;
    }
    
    // Create C wrapper source
    FILE* f = fopen("__java_wrapper.c", "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot create wrapper file\n");
        return 1;
    }
    
    fprintf(f, "#include <windows.h>\n");
    fprintf(f, "#include <stdio.h>\n");
    fprintf(f, "#include <stdlib.h>\n");
    fprintf(f, "\n");
    fprintf(f, "int main(int argc, char* argv[]) {\n");
    fprintf(f, "    STARTUPINFOA si = {0};\n");
    fprintf(f, "    si.cb = sizeof(si);\n");
    fprintf(f, "    PROCESS_INFORMATION pi = {0};\n");
    fprintf(f, "    \n");
    fprintf(f, "    char cmd[4096];\n");
    fprintf(f, "    snprintf(cmd, sizeof(cmd), \"\\\"%s\\\" %s\");\n", java_path, class_name);
    fprintf(f, "    \n");
    fprintf(f, "    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n");
    fprintf(f, "        printf(\"Error: Failed to launch Java\\n\");\n");
    fprintf(f, "        return 1;\n");
    fprintf(f, "    }\n");
    fprintf(f, "    \n");
    fprintf(f, "    WaitForSingleObject(pi.hProcess, INFINITE);\n");
    fprintf(f, "    \n");
    fprintf(f, "    DWORD exit_code = 0;\n");
    fprintf(f, "    GetExitCodeProcess(pi.hProcess, &exit_code);\n");
    fprintf(f, "    \n");
    fprintf(f, "    CloseHandle(pi.hProcess);\n");
    fprintf(f, "    CloseHandle(pi.hThread);\n");
    fprintf(f, "    \n");
    fprintf(f, "    return (int)exit_code;\n");
    fprintf(f, "}\n");
    
    fclose(f);
    
    // Compile wrapper
    char compile_cmd[MAX_CMD_LEN];
    snprintf(compile_cmd, sizeof(compile_cmd),
             "gcc -O2 -o \"%s\" __java_wrapper.c -lkernel32",
             output_file);
    
    printf("Creating launcher: %s\n", output_file);
    int result = system(compile_cmd);
    
    // Cleanup
    remove("__java_wrapper.c");
    
    if (result != 0) {
        fprintf(stderr, "Error: Failed to create launcher\n");
        return 1;
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RAWRXD Java Compiler (REAL)\n");
    printf("========================================\n");
    printf("\n");
    
    if (argc < 2) {
        printf("Usage: java_compiler_real.exe <input.java> [output.exe]\n");
        printf("\n");
        printf("Compiles Java source to standalone executable.\n");
        printf("Requires Java JDK installed.\n");
        printf("\n");
        printf("Example:\n");
        printf("  java_compiler_real.exe Hello.java Hello.exe\n");
        printf("  Hello.exe  # Runs the Java program\n");
        return 1;
    }
    
    const char* input_file = argv[1];
    const char* output_file = (argc > 2) ? argv[2] : "program.exe";
    
    // Extract class name from input file
    char class_name[MAX_PATH_LEN];
    strncpy(class_name, input_file, sizeof(class_name));
    class_name[sizeof(class_name)-1] = '\0';
    
    // Remove .java extension if present
    char* ext = strstr(class_name, ".java");
    if (ext) *ext = '\0';
    
    // Remove path
    char* basename = strrchr(class_name, '\\');
    if (basename) {
        memmove(class_name, basename + 1, strlen(basename));
    } else {
        basename = strrchr(class_name, '/');
        if (basename) {
            memmove(class_name, basename + 1, strlen(basename));
        }
    }
    
    printf("Input:  %s\n", input_file);
    printf("Output: %s\n", output_file);
    printf("Class:  %s\n", class_name);
    printf("\n");
    
    // Check if input exists
    if (GetFileAttributesA(input_file) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Error: Input file not found: %s\n", input_file);
        return 1;
    }
    
    // Step 1: Compile Java to .class
    if (compile_java(input_file, class_name) != 0) {
        return 1;
    }
    
    // Step 2: Create C wrapper
    if (create_wrapper(class_name, output_file) != 0) {
        return 1;
    }
    
    printf("\n");
    printf("========================================\n");
    printf("Success: Created %s\n", output_file);
    printf("========================================\n");
    printf("\n");
    printf("Note: Requires Java Runtime to execute\n");
    printf("The .class file must be in the same directory as the .exe\n");
    
    return 0;
}
