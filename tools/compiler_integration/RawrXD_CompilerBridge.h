/*
 * RawrXD IDE - Compiler Driver Integration Bridge
 * Full IDE Integration for GUI and CLI parity
 * Version: 1.0.0
 */

#ifndef RAWRXD_COMPILER_BRIDGE_H
#define RAWRXD_COMPILER_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

/* Compiler Driver Integration Version */
#define RAWRXD_COMPILER_BRIDGE_VERSION_MAJOR 1
#define RAWRXD_COMPILER_BRIDGE_VERSION_MINOR 0
#define RAWRXD_COMPILER_BRIDGE_VERSION_PATCH 0
#define RAWRXD_COMPILER_BRIDGE_VERSION_STRING "1.0.0"

/* Maximum path length */
#define RAWRXD_MAX_PATH 4096
#define RAWRXD_MAX_CMD_LENGTH 32768
#define RAWRXD_MAX_OUTPUT_LENGTH 1048576

/* Compiler Types */
typedef enum {
    RAWRXD_COMPILER_UNKNOWN = 0,
    RAWRXD_COMPILER_C,
    RAWRXD_COMPILER_CPP,
    RAWRXD_COMPILER_ASM,
    RAWRXD_COMPILER_CSHARP,
    RAWRXD_COMPILER_RUST,
    RAWRXD_COMPILER_GO,
    RAWRXD_COMPILER_JAVA,
    RAWRXD_COMPILER_PYTHON,
    RAWRXD_COMPILER_JAVASCRIPT,
    RAWRXD_COMPILER_TYPESCRIPT,
    RAWRXD_COMPILER_COUNT
} RawrXD_CompilerType;

/* Build Configuration */
typedef enum {
    RAWRXD_BUILD_DEBUG = 0,
    RAWRXD_BUILD_RELEASE,
    RAWRXD_BUILD_RELWITHDEBINFO,
    RAWRXD_BUILD_MINSIZEREL,
    RAWRXD_BUILD_CUSTOM
} RawrXD_BuildType;

/* Architecture Target */
typedef enum {
    RAWRXD_ARCH_X86 = 0,
    RAWRXD_ARCH_X64,
    RAWRXD_ARCH_ARM32,
    RAWRXD_ARCH_ARM64,
    RAWRXD_ARCH_WASM32,
    RAWRXD_ARCH_WASM64,
    RAWRXD_ARCH_NATIVE
} RawrXD_Architecture;

/* Compilation Result */
typedef struct {
    bool success;
    int exit_code;
    char output[RAWRXD_MAX_OUTPUT_LENGTH];
    char errors[RAWRXD_MAX_OUTPUT_LENGTH];
    char output_file[RAWRXD_MAX_PATH];
    uint64_t compile_time_ms;
    uint64_t link_time_ms;
    uint64_t total_time_ms;
    size_t warnings;
    size_t errors_count;
} RawrXD_CompileResult;

/* Compiler Options */
typedef struct {
    RawrXD_CompilerType compiler_type;
    RawrXD_BuildType build_type;
    RawrXD_Architecture target_arch;
    
    /* Paths */
    char source_file[RAWRXD_MAX_PATH];
    char output_file[RAWRXD_MAX_PATH];
    char working_directory[RAWRXD_MAX_PATH];
    char include_paths[16][RAWRXD_MAX_PATH];
    char library_paths[16][RAWRXD_MAX_PATH];
    char libraries[32][256];
    int include_count;
    int library_path_count;
    int library_count;
    
    /* Flags */
    bool optimize;
    int optimization_level; /* 0-3 */
    bool debug_info;
    bool warnings_as_errors;
    bool verbose;
    bool static_linking;
    bool position_independent;
    
    /* Defines */
    char defines[64][256];
    int define_count;
    
    /* Custom flags */
    char custom_flags[1024];
    
    /* IDE Integration */
    bool capture_output;
    bool show_in_gui;
    bool add_to_project;
    bool auto_run;
} RawrXD_CompilerOptions;

/* IDE Integration Callbacks */
typedef void (*RawrXD_CompileProgressCallback)(const char* file, int percent, void* user_data);
typedef void (*RawrXD_CompileOutputCallback)(const char* output, bool is_error, void* user_data);
typedef void (*RawrXD_CompileCompleteCallback)(const RawrXD_CompileResult* result, void* user_data);

/* IDE Integration Context */
typedef struct {
    HWND ide_window;
    HWND output_panel;
    HWND error_list;
    void* project_context;
    
    /* Callbacks */
    RawrXD_CompileProgressCallback on_progress;
    RawrXD_CompileOutputCallback on_output;
    RawrXD_CompileCompleteCallback on_complete;
    void* callback_user_data;
} RawrXD_IDEContext;

/* ============================================================================
 * Initialization and Cleanup
 * ============================================================================ */

/* Initialize the compiler bridge */
bool RawrXD_CompilerBridge_Init(void);

/* Cleanup the compiler bridge */
void RawrXD_CompilerBridge_Cleanup(void);

/* Get version string */
const char* RawrXD_CompilerBridge_GetVersion(void);

/* Check if compiler driver is available */
bool RawrXD_CompilerBridge_IsAvailable(void);

/* Get compiler driver path */
bool RawrXD_CompilerBridge_GetDriverPath(char* path, size_t path_size);

/* ============================================================================
 * IDE Integration
 * ============================================================================ */

/* Set IDE context for GUI integration */
bool RawrXD_CompilerBridge_SetIDEContext(const RawrXD_IDEContext* context);

/* Get current IDE context */
bool RawrXD_CompilerBridge_GetIDEContext(RawrXD_IDEContext* context);

/* Register IDE window for output */
bool RawrXD_CompilerBridge_RegisterOutputWindow(HWND hwnd);

/* ============================================================================
 * Compilation Functions
 * ============================================================================ */

/* Compile a single file */
bool RawrXD_CompilerBridge_Compile(const RawrXD_CompilerOptions* options, 
                                    RawrXD_CompileResult* result);

/* Compile with IDE integration */
bool RawrXD_CompilerBridge_CompileWithIDE(const RawrXD_CompilerOptions* options);

/* Build entire project */
bool RawrXD_CompilerBridge_BuildProject(const char* project_file,
                                        RawrXD_BuildType build_type,
                                        RawrXD_CompileResult* result);

/* Clean build artifacts */
bool RawrXD_CompilerBridge_Clean(const char* project_directory);

/* Run compiled executable */
bool RawrXD_CompilerBridge_Run(const char* executable, 
                               const char* args,
                               RawrXD_CompileResult* result);

/* ============================================================================
 * Language Detection
 * ============================================================================ */

/* Detect language from file extension */
RawrXD_CompilerType RawrXD_CompilerBridge_DetectLanguage(const char* filename);

/* Get compiler type name */
const char* RawrXD_CompilerBridge_GetCompilerName(RawrXD_CompilerType type);

/* Get file extensions for compiler type */
const char** RawrXD_CompilerBridge_GetExtensions(RawrXD_CompilerType type, int* count);

/* ============================================================================
 * Configuration
 * ============================================================================ */

/* Load compiler configuration from file */
bool RawrXD_CompilerBridge_LoadConfig(const char* config_file);

/* Save compiler configuration to file */
bool RawrXD_CompilerBridge_SaveConfig(const char* config_file);

/* Set default compiler for file type */
bool RawrXD_CompilerBridge_SetDefaultCompiler(RawrXD_CompilerType type);

/* Get default compiler for file type */
RawrXD_CompilerType RawrXD_CompilerBridge_GetDefaultCompiler(const char* extension);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Format compiler command line */
bool RawrXD_CompilerBridge_FormatCommandLine(const RawrXD_CompilerOptions* options,
                                             char* cmd_line, size_t cmd_size);

/* Parse compiler output for errors */
int RawrXD_CompilerBridge_ParseErrors(const char* output,
                                      char** file_names,
                                      int** line_numbers,
                                      char** messages,
                                      int max_errors);

/* Get compiler capabilities */
bool RawrXD_CompilerBridge_GetCapabilities(RawrXD_CompilerType type,
                                           char** features,
                                           int* feature_count);

/* Check if compiler supports feature */
bool RawrXD_CompilerBridge_SupportsFeature(RawrXD_CompilerType type,
                                           const char* feature);

/* ============================================================================
 * Async Operations
 * ============================================================================ */

typedef void* RawrXD_CompileHandle;

/* Start async compilation */
RawrXD_CompileHandle RawrXD_CompilerBridge_CompileAsync(
    const RawrXD_CompilerOptions* options);

/* Check if async compilation is complete */
bool RawrXD_CompilerBridge_IsComplete(RawrXD_CompileHandle handle);

/* Get async compilation result */
bool RawrXD_CompilerBridge_GetResult(RawrXD_CompileHandle handle,
                                     RawrXD_CompileResult* result);

/* Cancel async compilation */
bool RawrXD_CompilerBridge_Cancel(RawrXD_CompileHandle handle);

/* Wait for compilation to complete */
bool RawrXD_CompilerBridge_Wait(RawrXD_CompileHandle handle, DWORD timeout_ms);

/* ============================================================================
 * GitHub Copilot Integration
 * ============================================================================ */

/* Register with Copilot for inline compilation */
bool RawrXD_CompilerBridge_RegisterCopilotIntegration(void);

/* Compile code from Copilot suggestion */
bool RawrXD_CompilerBridge_CompileCopilotSuggestion(const char* code,
                                                   const char* language,
                                                   char* output_file,
                                                   size_t output_size);

/* Get compilation context for Copilot */
bool RawrXD_CompilerBridge_GetCopilotContext(char* context, size_t context_size);

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_COMPILER_BRIDGE_H */
