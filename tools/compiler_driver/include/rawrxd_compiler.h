//==============================================================================
// RAWRXD Compiler Driver API
// Version 1.0.0
//
// Unified compiler interface for RAWRXD toolchain
// Supports: C, x64 Assembly, C# (via Roslyn)
//==============================================================================

#ifndef RAWRXD_COMPILER_H
#define RAWRXD_COMPILER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Version and Constants
//==============================================================================

#define RAWRXD_COMPILER_VERSION_MAJOR 1
#define RAWRXD_COMPILER_VERSION_MINOR 0
#define RAWRXD_COMPILER_VERSION_PATCH 0

#define RAWRXD_MAX_PATH 260
#define RAWRXD_MAX_DIAGNOSTICS 256
#define RAWRXD_MAX_OUTPUT_SIZE 8192

//==============================================================================
// Enums
//==============================================================================

typedef enum {
    RXD_LANG_UNKNOWN = 0,
    RXD_LANG_C,
    RXD_LANG_ASM,
    RXD_LANG_CSHARP,
    RXD_LANG_CPP,
    RXD_LANG_COUNT
} rxd_language_t;

typedef enum {
    RXD_SEVERITY_INFO = 0,
    RXD_SEVERITY_WARNING,
    RXD_SEVERITY_ERROR,
    RXD_SEVERITY_FATAL
} rxd_severity_t;

typedef enum {
    RXD_RESULT_OK = 0,
    RXD_RESULT_ERROR_INVALID_INPUT,
    RXD_RESULT_ERROR_COMPILER_NOT_FOUND,
    RXD_RESULT_ERROR_COMPILATION_FAILED,
    RXD_RESULT_ERROR_LINK_FAILED,
    RXD_RESULT_ERROR_IO,
    RXD_RESULT_ERROR_MEMORY,
    RXD_RESULT_ERROR_UNKNOWN
} rxd_result_t;

typedef enum {
    RXD_STAGE_INIT,
    RXD_STAGE_PARSE,
    RXD_STAGE_COMPILE,
    RXD_STAGE_ASSEMBLE,
    RXD_STAGE_LINK,
    RXD_STAGE_COMPLETE
} rxd_stage_t;

//==============================================================================
// Structures
//==============================================================================

typedef struct {
    rxd_severity_t severity;
    int line;
    int column;
    int length;
    char file[RAWRXD_MAX_PATH];
    char message[1024];
    char code[32];  // Error code (e.g., "CS1001", "ASM001")
} rxd_diagnostic_t;

typedef struct {
    rxd_diagnostic_t items[RAWRXD_MAX_DIAGNOSTICS];
    int count;
    int error_count;
    int warning_count;
    int info_count;
} rxd_diagnostic_list_t;

typedef struct {
    char input_file[RAWRXD_MAX_PATH];
    char output_file[RAWRXD_MAX_PATH];
    char intermediate_dir[RAWRXD_MAX_PATH];
    rxd_language_t language;
    bool optimize;
    bool debug_info;
    int verbose_level;
    void* user_data;
} rxd_compile_options_t;

typedef struct {
    rxd_result_t result;
    rxd_stage_t completed_stage;
    rxd_diagnostic_list_t diagnostics;
    char output_path[RAWRXD_MAX_PATH];
    uint64_t compile_time_ms;
    size_t output_size;
} rxd_compile_result_t;

typedef struct {
    char id[64];
    char name[128];
    char version[32];
    char executable_path[RAWRXD_MAX_PATH];
    rxd_language_t language;
    const char** file_extensions;
    int extension_count;
    bool is_available;
} rxd_compiler_info_t;

// Backend vtable for pluggable compilers
typedef struct rxd_backend_vtable {
    const char* name;
    const char* version;
    rxd_language_t language;
    
    // Lifecycle
    int (*init)(void** context);
    void (*shutdown)(void* context);
    
    // Capabilities
    bool (*can_compile)(const char* file_path);
    
    // Compilation
    rxd_result_t (*compile)(void* context, const rxd_compile_options_t* options, 
                           rxd_compile_result_t* result);
    
    // Diagnostics
    void (*get_diagnostics)(void* context, rxd_diagnostic_list_t* diagnostics);
    void (*clear_diagnostics)(void* context);
    
} rxd_backend_vtable_t;

//==============================================================================
// Driver API
//==============================================================================

// Initialize the compiler driver
int rxd_driver_init(void);

// Shutdown the compiler driver
void rxd_driver_shutdown(void);

// Get driver version
const char* rxd_driver_get_version(void);

// Register a compiler backend
int rxd_driver_register_backend(const rxd_backend_vtable_t* backend);

// Get number of registered backends
int rxd_driver_get_backend_count(void);

// Get backend info by index
int rxd_driver_get_backend_info(int index, rxd_compiler_info_t* info);

// Detect language from file extension
rxd_language_t rxd_detect_language(const char* file_path);

// Get language name
const char* rxd_language_to_string(rxd_language_t lang);

//==============================================================================
// Compilation API
//==============================================================================

// Compile a single file
rxd_result_t rxd_compile_file(const char* source_file, const char* output_file,
                              const rxd_compile_options_t* options,
                              rxd_compile_result_t* result);

// Compile multiple files (project)
rxd_result_t rxd_compile_project(const char** source_files, int file_count,
                                 const char* output_file,
                                 const rxd_compile_options_t* options,
                                 rxd_compile_result_t* result);

// Quick compile with defaults
rxd_result_t rxd_compile_simple(const char* source_file, rxd_compile_result_t* result);

//==============================================================================
// Options API
//==============================================================================

// Initialize options with defaults
void rxd_options_init(rxd_compile_options_t* options);

// Set output file
void rxd_options_set_output(rxd_compile_options_t* options, const char* output_file);

// Set optimization
void rxd_options_set_optimize(rxd_compile_options_t* options, bool optimize);

// Set debug info
void rxd_options_set_debug(rxd_compile_options_t* options, bool debug);

//==============================================================================
// Result API
//==============================================================================

// Initialize result structure
void rxd_result_init(rxd_compile_result_t* result);

// Check if compilation succeeded
bool rxd_result_success(const rxd_compile_result_t* result);

// Get error count
int rxd_result_get_error_count(const rxd_compile_result_t* result);

// Get warning count
int rxd_result_get_warning_count(const rxd_compile_result_t* result);

// Print diagnostics to stdout
void rxd_result_print_diagnostics(const rxd_compile_result_t* result);

// Free result resources
void rxd_result_free(rxd_compile_result_t* result);

//==============================================================================
// Utility API
//==============================================================================

// Get error string for result code
const char* rxd_result_to_string(rxd_result_t result);

// Get severity string
const char* rxd_severity_to_string(rxd_severity_t severity);

// Get stage string
const char* rxd_stage_to_string(rxd_stage_t stage);

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_COMPILER_H
