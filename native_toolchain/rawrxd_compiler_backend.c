//=============================================================================
// rawrxd_compiler_backend.c - RawrXDCompiler Native Toolchain Backend
// Part of RawrXD Native Toolchain - RE Integration
// Replaces external ML64/LINK calls with native implementations
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <process.h>

#define COMPILER_BACKEND_VERSION "1.0.0"
#define MAX_PATH_LENGTH 512
#define MAX_ERROR_LENGTH 4096

//=============================================================================
// Native Toolchain Configuration
//=============================================================================

typedef struct {
    char assembler_path[MAX_PATH_LENGTH];
    char linker_path[MAX_PATH_LENGTH];
    char librarian_path[MAX_PATH_LENGTH];
    char temp_dir[MAX_PATH_LENGTH];
    int verbose;
    int keep_temp;
} ToolchainConfig;

typedef struct {
    int success;
    char object_file[MAX_PATH_LENGTH];
    char executable[MAX_PATH_LENGTH];
    char errors[MAX_ERROR_LENGTH];
    int error_count;
    int warning_count;
    int verbose;
} CompileResult;

typedef struct {
    char** items;
    int count;
    int capacity;
} StringList;

//=============================================================================
// String List Utilities
//=============================================================================

StringList* string_list_create(int capacity) {
    StringList* list = (StringList*)calloc(1, sizeof(StringList));
    if (!list) return NULL;
    
    list->capacity = capacity > 0 ? capacity : 16;
    list->items = (char**)calloc(list->capacity, sizeof(char*));
    if (!list->items) {
        free(list);
        return NULL;
    }
    
    return list;
}

void string_list_destroy(StringList* list) {
    if (list) {
        for (int i = 0; i < list->count; i++) {
            free(list->items[i]);
        }
        free(list->items);
        free(list);
    }
}

int string_list_add(StringList* list, const char* str) {
    if (!list || !str) return 0;
    
    if (list->count >= list->capacity) {
        int new_capacity = list->capacity * 2;
        char** new_items = (char**)realloc(list->items, new_capacity * sizeof(char*));
        if (!new_items) return 0;
        list->items = new_items;
        list->capacity = new_capacity;
    }
    
    list->items[list->count] = _strdup(str);
    if (!list->items[list->count]) return 0;
    
    list->count++;
    return 1;
}

//=============================================================================
// Native Assembler Interface
//=============================================================================

// Forward declarations for minimal_assembler.c functions
// These would be linked or included from minimal_assembler.c

extern int assemble_file(const char* input_file, const char* output_file, char* errors, int max_errors);
extern int assemble_string(const char* asm_code, const char* output_file, char* errors, int max_errors);

// Native assembler wrapper
int native_assemble(const char* source_file, const char* output_obj, CompileResult* result) {
    printf("[ASSEMBLE] %s -> %s\n", source_file, output_obj);
    
    // Try to use built-in assembler first
    // If not available, fall back to external minimal_assembler.exe
    
    char command[MAX_PATH_LENGTH * 4];
    snprintf(command, sizeof(command), "minimal_assembler.exe \"%s\" \"%s\" 2>&1", 
             source_file, output_obj);
    
    if (result->verbose) {
        printf("[CMD] %s\n", command);
    }
    
    // Execute assembler
    FILE* pipe = _popen(command, "r");
    if (!pipe) {
        snprintf(result->errors, MAX_ERROR_LENGTH, "Failed to execute assembler: %s\n", command);
        result->error_count = 1;
        return 0;
    }
    
    // Capture output
    char buffer[1024];
    result->errors[0] = '\0';
    while (fgets(buffer, sizeof(buffer), pipe)) {
        strncat(result->errors, buffer, MAX_ERROR_LENGTH - strlen(result->errors) - 1);
        
        if (strstr(buffer, "ERROR") || strstr(buffer, "error:")) {
            result->error_count++;
        } else if (strstr(buffer, "WARNING") || strstr(buffer, "warning:")) {
            result->warning_count++;
        }
    }
    
    int exit_code = _pclose(pipe);
    
    // Check if object file was created
    if (exit_code == 0 && GetFileAttributesA(output_obj) != INVALID_FILE_ATTRIBUTES) {
        strncpy(result->object_file, output_obj, MAX_PATH_LENGTH - 1);
        result->success = 1;
        printf("[SUCCESS] Assembled: %s\n", output_obj);
        return 1;
    } else {
        result->success = 0;
        printf("[FAILED] Assembly failed with exit code: %d\n", exit_code);
        return 0;
    }
}

//=============================================================================
// Native Linker Interface
//=============================================================================

// Forward declarations for linker_with_imports.c functions
extern int link_objects(const char** obj_files, int obj_count, const char* output_exe, 
                        const char** libs, int lib_count, char* errors, int max_errors);

int native_link(const char* obj_file, const char* output_exe, const char** libs, int lib_count, 
                CompileResult* result) {
    printf("[LINK] %s -> %s\n", obj_file, output_exe);
    
    char command[MAX_PATH_LENGTH * 8];
    
    // Build command
    snprintf(command, sizeof(command), "linker_with_imports.exe \"%s\" \"%s\"", 
             obj_file, output_exe);
    
    // Add libraries
    for (int i = 0; i < lib_count; i++) {
        strncat(command, " \"", sizeof(command) - strlen(command) - 1);
        strncat(command, libs[i], sizeof(command) - strlen(command) - 1);
        strncat(command, "\"", sizeof(command) - strlen(command) - 1);
    }
    
    if (result->verbose) {
        printf("[CMD] %s\n", command);
    }
    
    // Execute linker
    FILE* pipe = _popen(command, "r");
    if (!pipe) {
        snprintf(result->errors + strlen(result->errors), 
                 MAX_ERROR_LENGTH - strlen(result->errors),
                 "Failed to execute linker: %s\n", command);
        result->error_count++;
        return 0;
    }
    
    // Capture output
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        strncat(result->errors, buffer, MAX_ERROR_LENGTH - strlen(result->errors) - 1);
        
        if (strstr(buffer, "ERROR") || strstr(buffer, "error:")) {
            result->error_count++;
        } else if (strstr(buffer, "WARNING") || strstr(buffer, "warning:")) {
            result->warning_count++;
        }
    }
    
    int exit_code = _pclose(pipe);
    
    // Check if executable was created
    if (exit_code == 0 && GetFileAttributesA(output_exe) != INVALID_FILE_ATTRIBUTES) {
        strncpy(result->executable, output_exe, MAX_PATH_LENGTH - 1);
        result->success = 1;
        printf("[SUCCESS] Linked: %s\n", output_exe);
        return 1;
    } else {
        result->success = 0;
        printf("[FAILED] Linking failed with exit code: %d\n", exit_code);
        return 0;
    }
}

//=============================================================================
// High-Level Compile Interface (RawrXDCompiler Backend)
//=============================================================================

CompileResult* compile_result_create(void) {
    CompileResult* result = (CompileResult*)calloc(1, sizeof(CompileResult));
    return result;
}

void compile_result_destroy(CompileResult* result) {
    free(result);
}

// Main compile function - replaces RawrXDCompiler::CompileASM
int rawrxd_compile_asm(const char* asm_source, const char* output_exe, 
                       ToolchainConfig* config, CompileResult* result) {
    
    printf("=============================================================================\n");
    printf("  RawrXDCompiler Native Backend v%s\n", COMPILER_BACKEND_VERSION);
    printf("=============================================================================\n\n");
    
    result->success = 0;
    result->error_count = 0;
    result->warning_count = 0;
    result->errors[0] = '\0';
    
    // Generate temp file names
    char temp_asm[MAX_PATH_LENGTH];
    char temp_obj[MAX_PATH_LENGTH];
    
    if (strlen(config->temp_dir) > 0) {
        snprintf(temp_asm, sizeof(temp_asm), "%s\\__rawrxd_temp.asm", config->temp_dir);
        snprintf(temp_obj, sizeof(temp_obj), "%s\\__rawrxd_temp.obj", config->temp_dir);
    } else {
        GetTempPathA(MAX_PATH_LENGTH, temp_asm);
        strcat(temp_asm, "__rawrxd_temp.asm");
        GetTempPathA(MAX_PATH_LENGTH, temp_obj);
        strcat(temp_obj, "__rawrxd_temp.obj");
    }
    
    // Determine if input is file or string
    int is_file = 0;
    DWORD attribs = GetFileAttributesA(asm_source);
    if (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        is_file = 1;
    }
    
    const char* asm_file = asm_source;
    
    // If input is code string, write to temp file
    if (!is_file) {
        printf("[INFO] Writing assembly to temp file: %s\n", temp_asm);
        FILE* f = fopen(temp_asm, "w");
        if (!f) {
            snprintf(result->errors, MAX_ERROR_LENGTH, "Failed to create temp file: %s\n", temp_asm);
            result->error_count = 1;
            return 0;
        }
        fprintf(f, "%s", asm_source);
        fclose(f);
        asm_file = temp_asm;
    }
    
    // Step 1: Assemble
    printf("\n[STEP 1/2] Assembling...\n");
    if (!native_assemble(asm_file, temp_obj, result)) {
        // Assembly failed
        if (!config->keep_temp && !is_file) {
            DeleteFileA(temp_asm);
        }
        return 0;
    }
    
    // Step 2: Link
    printf("\n[STEP 2/2] Linking...\n");
    const char* default_libs[] = {"kernel32.lib"};
    if (!native_link(temp_obj, output_exe, default_libs, 1, result)) {
        // Linking failed
        if (!config->keep_temp) {
            DeleteFileA(temp_obj);
        }
        if (!config->keep_temp && !is_file) {
            DeleteFileA(temp_asm);
        }
        return 0;
    }
    
    // Cleanup temp files
    if (!config->keep_temp) {
        DeleteFileA(temp_obj);
        if (!is_file) {
            DeleteFileA(temp_asm);
        }
    }
    
    printf("\n=============================================================================\n");
    printf("  COMPILE SUCCESS\n");
    printf("  Output: %s\n", output_exe);
    printf("  Errors: %d, Warnings: %d\n", result->error_count, result->warning_count);
    printf("=============================================================================\n");
    
    return 1;
}

// Compile from memory buffer
int rawrxd_compile_asm_buffer(const char* asm_code, size_t code_len,
                               const char* output_exe,
                               ToolchainConfig* config, CompileResult* result) {
    // Write code to temp file then compile
    char temp_asm[MAX_PATH_LENGTH];
    GetTempPathA(MAX_PATH_LENGTH, temp_asm);
    strcat(temp_asm, "__rawrxd_asm_XXXXXX.asm");
    
    // Generate unique filename
    for (int i = 0; i < 10000; i++) {
        snprintf(temp_asm, sizeof(temp_asm), "%s\\__rawrxd_asm_%04d.asm", 
                 config->temp_dir[0] ? config->temp_dir : ".", i);
        if (GetFileAttributesA(temp_asm) == INVALID_FILE_ATTRIBUTES) {
            break;
        }
    }
    
    FILE* f = fopen(temp_asm, "w");
    if (!f) {
        snprintf(result->errors, MAX_ERROR_LENGTH, "Failed to create temp file\n");
        result->error_count = 1;
        return 0;
    }
    
    fwrite(asm_code, 1, code_len, f);
    fclose(f);
    
    int success = rawrxd_compile_asm(temp_asm, output_exe, config, result);
    
    if (!config->keep_temp) {
        DeleteFileA(temp_asm);
    }
    
    return success;
}

//=============================================================================
// C Compiler Integration
//=============================================================================

// Compile C source to executable using native toolchain
int rawrxd_compile_c(const char* c_source, const char* output_exe,
                     ToolchainConfig* config, CompileResult* result) {
    
    printf("=============================================================================\n");
    printf("  RawrXD C Compiler (Native Backend) v%s\n", COMPILER_BACKEND_VERSION);
    printf("=============================================================================\n\n");
    
    // Step 1: Compile C to assembly using c_compiler_minimal
    printf("[STEP 1/3] Compiling C to assembly...\n");
    
    char temp_asm[MAX_PATH_LENGTH];
    GetTempPathA(MAX_PATH_LENGTH, temp_asm);
    strcat(temp_asm, "__rawrxd_c_temp.asm");
    
    char command[MAX_PATH_LENGTH * 4];
    snprintf(command, sizeof(command), "c_compiler_minimal.exe \"%s\" \"%s\" 2>&1",
             c_source, temp_asm);
    
    if (result->verbose) {
        printf("[CMD] %s\n", command);
    }
    
    FILE* pipe = _popen(command, "r");
    if (!pipe) {
        snprintf(result->errors, MAX_ERROR_LENGTH, "Failed to execute C compiler\n");
        result->error_count = 1;
        return 0;
    }
    
    // Capture output
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        strncat(result->errors, buffer, MAX_ERROR_LENGTH - strlen(result->errors) - 1);
        if (strstr(buffer, "error") || strstr(buffer, "ERROR")) {
            result->error_count++;
        }
    }
    
    int exit_code = _pclose(pipe);
    if (exit_code != 0) {
        printf("[FAILED] C compilation failed\n");
        return 0;
    }
    
    // Step 2 & 3: Assemble and link
    printf("[STEP 2-3/3] Assembling and linking...\n");
    int success = rawrxd_compile_asm(temp_asm, output_exe, config, result);
    
    if (!config->keep_temp) {
        DeleteFileA(temp_asm);
    }
    
    return success;
}

//=============================================================================
// Command Line Interface
//=============================================================================

void print_usage(const char* prog) {
    printf("RawrXDCompiler Native Backend v%s\n", COMPILER_BACKEND_VERSION);
    printf("Usage: %s [options] <input> <output>\n", prog);
    printf("\nOptions:\n");
    printf("  /c, /compile       Compile mode (default)\n");
    printf("  /asm               Assembly mode (input is .asm file)\n");
    printf("  /c-source          C mode (input is .c file, uses c_compiler_minimal)\n");
    printf("  /v, /verbose       Verbose output\n");
    printf("  /k, /keep          Keep temporary files\n");
    printf("  /temp <dir>        Set temp directory\n");
    printf("\nExamples:\n");
    printf("  %s code.asm output.exe\n", prog);
    printf("  %s /c-source main.c main.exe\n", prog);
    printf("  %s /v /k test.asm test.exe\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Parse arguments
    ToolchainConfig config = {0};
    config.verbose = 0;
    config.keep_temp = 0;
    strcpy(config.temp_dir, ".");
    
    int mode = 0;  // 0=auto, 1=asm, 2=c
    const char* input_file = NULL;
    const char* output_file = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "/v") == 0 || strcmp(argv[i], "/verbose") == 0) {
            config.verbose = 1;
        } else if (strcmp(argv[i], "/k") == 0 || strcmp(argv[i], "/keep") == 0) {
            config.keep_temp = 1;
        } else if (strcmp(argv[i], "/asm") == 0) {
            mode = 1;
        } else if (strcmp(argv[i], "/c-source") == 0) {
            mode = 2;
        } else if (strcmp(argv[i], "/temp") == 0 && i + 1 < argc) {
            strncpy(config.temp_dir, argv[++i], MAX_PATH_LENGTH - 1);
        } else if (argv[i][0] != '/' && argv[i][0] != '-') {
            if (!input_file) {
                input_file = argv[i];
            } else if (!output_file) {
                output_file = argv[i];
            }
        }
    }
    
    if (!input_file || !output_file) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Auto-detect mode from extension
    if (mode == 0) {
        size_t len = strlen(input_file);
        if (len > 2 && _stricmp(input_file + len - 2, ".c") == 0) {
            mode = 2;
        } else {
            mode = 1;  // Default to assembly
        }
    }
    
    // Create result container
    CompileResult* result = compile_result_create();
    if (!result) {
        printf("[ERROR] Failed to allocate result structure\n");
        return 1;
    }
    
    result->verbose = config.verbose;
    
    // Execute compilation
    int success = 0;
    if (mode == 2) {
        success = rawrxd_compile_c(input_file, output_file, &config, result);
    } else {
        success = rawrxd_compile_asm(input_file, output_file, &config, result);
    }
    
    // Print results
    if (!success) {
        printf("\n[ERRORS]\n%s\n", result->errors);
    }
    
    // Cleanup
    compile_result_destroy(result);
    
    return success ? 0 : 1;
}
