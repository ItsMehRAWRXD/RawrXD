//==============================================================================
// rawrxd_cc.c
// RAWRXD Unified Compiler Driver v1.0
//
// Usage: rawrxd-cc [options] <source-file>... [-o <output>]
//==============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEP "\\"
#else
#define PATH_SEP "/"
#endif

#define VERSION "1.0.0"
#define MAX_BACKENDS 16
#define MAX_DIAGNOSTICS 256

//==============================================================================
// Types and Structures
//==============================================================================

typedef enum {
    LANG_UNKNOWN = 0,
    LANG_C,
    LANG_ASM,
    LANG_CSHARP,
    LANG_IR,
    LANG_COUNT
} Language;

typedef enum {
    EMIT_AUTO,
    EMIT_EXE,
    EMIT_DLL,
    EMIT_OBJ,
    EMIT_ASM,
    EMIT_IR
} EmitType;

typedef enum {
    SEVERITY_ERROR = 0,
    SEVERITY_WARNING,
    SEVERITY_INFO,
    SEVERITY_HINT
} Severity;

typedef struct {
    Severity severity;
    char code[16];
    char message[512];
    char file[256];
    int line;
    int column;
    int length;
} Diagnostic;

typedef struct Backend {
    const char* id;
    const char* name;
    Language language;
    const char** extensions;
    const char* executable;
    int (*compile)(const char* source, const char* output, 
                   const char** args, int arg_count,
                   Diagnostic** diagnostics, int* diag_count);
    int (*can_handle)(const char* path);
} Backend;

typedef struct {
    const char** inputs;
    int input_count;
    const char* output;
    Language lang;
    EmitType emit;
    int verbose;
    int analyze_only;
    const char* target;
    const char* backend_hint;
} Options;

typedef struct {
    int success;
    char output_path[512];
    Diagnostic diagnostics[MAX_DIAGNOSTICS];
    int diag_count;
    double compile_time_ms;
} Result;

//==============================================================================
// Language Detection
//==============================================================================

static const char* lang_names[] = {
    "unknown", "c", "asm", "csharp", "ir"
};

static const char* c_extensions[] = { ".c", ".h", ".cpp", ".hpp", NULL };
static const char* asm_extensions[] = { ".asm", ".s", ".nasm", ".masm", NULL };
static const char* cs_extensions[] = { ".cs", ".csx", NULL };
static const char* ir_extensions[] = { ".rxir", ".ir", NULL };

Language detect_language(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return LANG_UNKNOWN;
    
    // Check C extensions
    for (int i = 0; c_extensions[i]; i++) {
        if (_stricmp(ext, c_extensions[i]) == 0) return LANG_C;
    }
    
    // Check ASM extensions
    for (int i = 0; asm_extensions[i]; i++) {
        if (_stricmp(ext, asm_extensions[i]) == 0) return LANG_ASM;
    }
    
    // Check C# extensions
    for (int i = 0; cs_extensions[i]; i++) {
        if (_stricmp(ext, cs_extensions[i]) == 0) return LANG_CSHARP;
    }
    
    // Check IR extensions
    for (int i = 0; ir_extensions[i]; i++) {
        if (_stricmp(ext, ir_extensions[i]) == 0) return LANG_IR;
    }
    
    return LANG_UNKNOWN;
}

const char* language_to_string(Language lang) {
    if (lang >= 0 && lang < LANG_COUNT) {
        return lang_names[lang];
    }
    return "unknown";
}

//==============================================================================
// Backend Implementations
//==============================================================================

// C Backend - uses c_compiler_working.exe
int c_backend_compile(const char* source, const char* output,
                      const char** args, int arg_count,
                      Diagnostic** diagnostics, int* diag_count) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "c_compiler_working.exe \"%s\" \"%s\"", 
             source, output);
    
    // Add additional args
    for (int i = 0; i < arg_count; i++) {
        strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, args[i], sizeof(cmd) - strlen(cmd) - 1);
    }
    
    if (system(cmd) == 0) {
        return 0;
    }
    
    // Add diagnostic on failure
    if (diagnostics && diag_count && *diag_count < MAX_DIAGNOSTICS) {
        Diagnostic* d = &(*diagnostics)[*diag_count];
        d->severity = SEVERITY_ERROR;
        strcpy(d->code, "C0001");
        snprintf(d->message, sizeof(d->message), "C compilation failed: %s", source);
        strcpy(d->file, source);
        d->line = 0;
        d->column = 0;
        (*diag_count)++;
    }
    
    return -1;
}

// ASM Backend - uses real_assembler.exe
int asm_backend_compile(const char* source, const char* output,
                        const char** args, int arg_count,
                        Diagnostic** diagnostics, int* diag_count) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "real_assembler.exe \"%s\" \"%s\"", 
             source, output);
    
    for (int i = 0; i < arg_count; i++) {
        strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, args[i], sizeof(cmd) - strlen(cmd) - 1);
    }
    
    if (system(cmd) == 0) {
        return 0;
    }
    
    if (diagnostics && diag_count && *diag_count < MAX_DIAGNOSTICS) {
        Diagnostic* d = &(*diagnostics)[*diag_count];
        d->severity = SEVERITY_ERROR;
        strcpy(d->code, "ASM0001");
        snprintf(d->message, sizeof(d->message), "Assembly failed: %s", source);
        strcpy(d->file, source);
        d->line = 0;
        d->column = 0;
        (*diag_count)++;
    }
    
    return -1;
}

// Roslyn Backend - uses MicroRoslyn_Test.exe
int roslyn_backend_compile(const char* source, const char* output,
                           const char** args, int arg_count,
                           Diagnostic** diagnostics, int* diag_count) {
    char cmd[1024];
    // MicroRoslyn doesn't actually compile to exe, just parses
    // For now, we'll call it and check if parsing succeeds
    snprintf(cmd, sizeof(cmd), "MicroRoslyn_Test.exe \"%s\" 2>&1", source);
    
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) {
        if (diagnostics && diag_count && *diag_count < MAX_DIAGNOSTICS) {
            Diagnostic* d = &(*diagnostics)[*diag_count];
            d->severity = SEVERITY_ERROR;
            strcpy(d->code, "CS0001");
            snprintf(d->message, sizeof(d->message), 
                     "Failed to invoke Roslyn compiler");
            strcpy(d->file, source);
            (*diag_count)++;
        }
        return -1;
    }
    
    char buffer[1024];
    int success = 0;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        // Check for pass/fail in output
        if (strstr(buffer, "[PASS]") || strstr(buffer, "All tests complete")) {
            success = 1;
        }
        if (strstr(buffer, "[DIAG]")) {
            // Parse diagnostic
            if (diagnostics && diag_count && *diag_count < MAX_DIAGNOSTICS) {
                Diagnostic* d = &(*diagnostics)[*diag_count];
                d->severity = SEVERITY_WARNING;
                strcpy(d->code, "CS9999");
                strncpy(d->message, buffer, sizeof(d->message) - 1);
                strcpy(d->file, source);
                (*diag_count)++;
            }
        }
    }
    
    _pclose(pipe);
    
    if (!success) {
        if (diagnostics && diag_count && *diag_count < MAX_DIAGNOSTICS) {
            Diagnostic* d = &(*diagnostics)[*diag_count];
            d->severity = SEVERITY_ERROR;
            strcpy(d->code, "CS0002");
            snprintf(d->message, sizeof(d->message), 
                     "C# compilation failed: %s", source);
            strcpy(d->file, source);
            (*diag_count)++;
        }
        return -1;
    }
    
    return 0;
}

//==============================================================================
// Backend Registry
//==============================================================================

static Backend backends[MAX_BACKENDS];
static int backend_count = 0;

void register_backends() {
    // C Backend
    backends[backend_count].id = "rawrxd-c";
    backends[backend_count].name = "RAWRXD C Compiler";
    backends[backend_count].language = LANG_C;
    backends[backend_count].extensions = c_extensions;
    backends[backend_count].executable = "c_compiler_working.exe";
    backends[backend_count].compile = c_backend_compile;
    backend_count++;
    
    // ASM Backend
    backends[backend_count].id = "rawrxd-asm";
    backends[backend_count].name = "RAWRXD x64 Assembler";
    backends[backend_count].language = LANG_ASM;
    backends[backend_count].extensions = asm_extensions;
    backends[backend_count].executable = "real_assembler.exe";
    backends[backend_count].compile = asm_backend_compile;
    backend_count++;
    
    // Roslyn Backend
    backends[backend_count].id = "micro-roslyn";
    backends[backend_count].name = "MicroRoslyn C#";
    backends[backend_count].language = LANG_CSHARP;
    backends[backend_count].extensions = cs_extensions;
    backends[backend_count].executable = "MicroRoslyn_Test.exe";
    backends[backend_count].compile = roslyn_backend_compile;
    backend_count++;
}

Backend* find_backend(Language lang) {
    for (int i = 0; i < backend_count; i++) {
        if (backends[i].language == lang) {
            return &backends[i];
        }
    }
    return NULL;
}

Backend* find_backend_by_id(const char* id) {
    for (int i = 0; i < backend_count; i++) {
        if (strcmp(backends[i].id, id) == 0) {
            return &backends[i];
        }
    }
    return NULL;
}

//==============================================================================
// Command Line Parsing
//==============================================================================

void print_usage(const char* prog) {
    printf("RAWRXD Unified Compiler Driver v%s\n", VERSION);
    printf("Usage: %s [options] <source-file>... [-o <output>]\n\n", prog);
    printf("Options:\n");
    printf("  --target=<triple>    Target architecture\n");
    printf("  --emit=<type>          Output type: exe, dll, obj, asm, ir\n");
    printf("  --backend=<name>       Force specific backend\n");
    printf("  --analyze              Run static analysis only\n");
    printf("  --verbose              Show compilation pipeline\n");
    printf("  --help                 Show this help\n");
    printf("  --version              Show version\n");
    printf("\nExamples:\n");
    printf("  %s hello.cs                    # Compile C#\n", prog);
    printf("  %s hello.c -o hello.exe        # Compile C\n", prog);
    printf("  %s hello.asm --emit=obj      # Assemble to object\n", prog);
}

Options parse_args(int argc, char** argv) {
    Options opts = {0};
    opts.lang = LANG_UNKNOWN;
    opts.emit = EMIT_AUTO;
    
    // Allocate space for inputs
    opts.inputs = malloc(argc * sizeof(char*));
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        }
        else if (strcmp(argv[i], "--version") == 0) {
            printf("RAWRXD Compiler Driver v%s\n", VERSION);
            exit(0);
        }
        else if (strncmp(argv[i], "--target=", 9) == 0) {
            opts.target = argv[i] + 9;
        }
        else if (strncmp(argv[i], "--emit=", 7) == 0) {
            const char* emit_str = argv[i] + 7;
            if (strcmp(emit_str, "exe") == 0) opts.emit = EMIT_EXE;
            else if (strcmp(emit_str, "dll") == 0) opts.emit = EMIT_DLL;
            else if (strcmp(emit_str, "obj") == 0) opts.emit = EMIT_OBJ;
            else if (strcmp(emit_str, "asm") == 0) opts.emit = EMIT_ASM;
            else if (strcmp(emit_str, "ir") == 0) opts.emit = EMIT_IR;
        }
        else if (strncmp(argv[i], "--backend=", 10) == 0) {
            opts.backend_hint = argv[i] + 10;
        }
        else if (strcmp(argv[i], "--analyze") == 0) {
            opts.analyze_only = 1;
        }
        else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            opts.verbose = 1;
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            opts.output = argv[++i];
        }
        else if (argv[i][0] != '-') {
            // Input file
            opts.inputs[opts.input_count++] = argv[i];
        }
    }
    
    return opts;
}

//==============================================================================
// Compilation Pipeline
//==============================================================================

const char* get_default_output(const char* input, EmitType emit) {
    static char output[512];
    
    // Remove extension
    strncpy(output, input, sizeof(output) - 1);
    char* dot = strrchr(output, '.');
    if (dot) *dot = '\0';
    
    // Add appropriate extension
    switch (emit) {
        case EMIT_EXE: strcat(output, ".exe"); break;
        case EMIT_DLL: strcat(output, ".dll"); break;
        case EMIT_OBJ: strcat(output, ".obj"); break;
        case EMIT_ASM: strcat(output, ".asm"); break;
        case EMIT_IR:  strcat(output, ".rxir"); break;
        default:       strcat(output, ".exe"); break;
    }
    
    return output;
}

Result compile_file(const char* input, const Options* opts) {
    Result result = {0};
    result.diag_count = 0;
    
    clock_t start = clock();
    
    // Detect language
    Language lang = opts->lang;
    if (lang == LANG_UNKNOWN) {
        lang = detect_language(input);
    }
    
    if (lang == LANG_UNKNOWN) {
        result.success = 0;
        result.diagnostics[result.diag_count].severity = SEVERITY_ERROR;
        strcpy(result.diagnostics[result.diag_count].code, "RXD0001");
        snprintf(result.diagnostics[result.diag_count].message, 512,
                 "Cannot detect language for: %s", input);
        strcpy(result.diagnostics[result.diag_count].file, input);
        result.diag_count++;
        return result;
    }
    
    if (opts->verbose) {
        printf("[INFO] Detected language: %s\n", language_to_string(lang));
    }
    
    // Find backend
    Backend* backend = NULL;
    if (opts->backend_hint) {
        backend = find_backend_by_id(opts->backend_hint);
    }
    if (!backend) {
        backend = find_backend(lang);
    }
    
    if (!backend) {
        result.success = 0;
        result.diagnostics[result.diag_count].severity = SEVERITY_ERROR;
        strcpy(result.diagnostics[result.diag_count].code, "RXD0002");
        snprintf(result.diagnostics[result.diag_count].message, 512,
                 "No backend available for language: %s", language_to_string(lang));
        result.diag_count++;
        return result;
    }
    
    if (opts->verbose) {
        printf("[INFO] Using backend: %s\n", backend->name);
    }
    
    // Determine output
    const char* output = opts->output;
    if (!output) {
        output = get_default_output(input, opts->emit);
    }
    strncpy(result.output_path, output, sizeof(result.output_path) - 1);
    
    // Compile
    if (opts->analyze_only) {
        // Just analyze, don't produce output
        if (opts->verbose) {
            printf("[INFO] Analysis mode - no output produced\n");
        }
        result.success = 1;
    } else {
        int ret = backend->compile(input, output, NULL, 0,
                                   result.diagnostics, &result.diag_count);
        result.success = (ret == 0);
    }
    
    clock_t end = clock();
    result.compile_time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    return result;
}

//==============================================================================
// Diagnostic Output
//==============================================================================

const char* severity_to_string(Severity s) {
    switch (s) {
        case SEVERITY_ERROR:   return "error";
        case SEVERITY_WARNING: return "warning";
        case SEVERITY_INFO:    return "info";
        case SEVERITY_HINT:    return "hint";
        default:               return "unknown";
    }
}

void print_diagnostics(const Result* result) {
    int errors = 0, warnings = 0, infos = 0;
    
    for (int i = 0; i < result->diag_count; i++) {
        const Diagnostic* d = &result->diagnostics[i];
        
        switch (d->severity) {
            case SEVERITY_ERROR:   errors++;   break;
            case SEVERITY_WARNING: warnings++; break;
            case SEVERITY_INFO:    infos++;    break;
            default: break;
        }
        
        printf("%s[%s] %s\n", 
               severity_to_string(d->severity),
               d->code,
               d->message);
        
        if (d->file[0] && d->line > 0) {
            printf("  at %s:%d:%d\n", d->file, d->line, d->column);
        }
    }
    
    if (result->diag_count > 0) {
        printf("\n%d error(s), %d warning(s), %d info(s)\n",
               errors, warnings, infos);
    }
}

void print_json_output(const Result* result, const char* input) {
    printf("{\n");
    printf("  \"success\": %s,\n", result->success ? "true" : "false");
    printf("  \"input\": \"%s\",\n", input);
    printf("  \"output\": \"%s\",\n", result->output_path);
    printf("  \"compile_time_ms\": %.2f,\n", result->compile_time_ms);
    printf("  \"diagnostics\": [\n");
    
    for (int i = 0; i < result->diag_count; i++) {
        const Diagnostic* d = &result->diagnostics[i];
        printf("    {\n");
        printf("      \"severity\": \"%s\",\n", severity_to_string(d->severity));
        printf("      \"code\": \"%s\",\n", d->code);
        printf("      \"message\": \"%s\",\n", d->message);
        printf("      \"location\": {\n");
        printf("        \"file\": \"%s\",\n", d->file);
        printf("        \"line\": %d,\n", d->line);
        printf("        \"column\": %d\n", d->column);
        printf("      }\n");
        printf("    }%s\n", (i < result->diag_count - 1) ? "," : "");
    }
    
    printf("  ]\n");
    printf("}\n");
}

//==============================================================================
// Main Entry Point
//==============================================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Register backends
    register_backends();
    
    // Parse arguments
    Options opts = parse_args(argc, argv);
    
    if (opts.input_count == 0) {
        fprintf(stderr, "Error: No input files specified\n");
        return 1;
    }
    
    // Process each input
    int overall_success = 1;
    
    for (int i = 0; i < opts.input_count; i++) {
        const char* input = opts.inputs[i];
        
        if (opts.verbose) {
            printf("[INFO] Compiling: %s\n", input);
        }
        
        Result result = compile_file(input, &opts);
        
        // Print diagnostics
        print_diagnostics(&result);
        
        if (result.success) {
            if (opts.verbose) {
                printf("[SUCCESS] Compiled to: %s (%.2f ms)\n",
                       result.output_path, result.compile_time_ms);
            }
        } else {
            overall_success = 0;
            if (opts.verbose) {
                printf("[FAILED] Compilation failed\n");
            }
        }
    }
    
    // Cleanup
    free(opts.inputs);
    
    return overall_success ? 0 : 1;
}
