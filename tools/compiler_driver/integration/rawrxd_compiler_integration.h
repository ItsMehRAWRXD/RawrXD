/*============================================================================
 * RAWRXD COMPILER DRIVER - IDE INTEGRATION HEADER
 * Full integration with RawrXD IDE (GUI + CLI)
 *
 * Provides:
 *   - Compiler service for IDE build system
 *   - Project compilation management
 *   - Error parsing and IDE problem matchers
 *   - Build task integration
 *   - GitHub Copilot parity features
 *
 * Version: 1.0.0
 *============================================================================*/

#ifndef RAWRXD_COMPILER_INTEGRATION_H
#define RAWRXD_COMPILER_INTEGRATION_H

#include <windows.h>
#include <cstdint>
#include <cstdbool>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * COMPILER SERVICE API
 *============================================================================*/

// Opaque handle to compiler service
typedef struct RawrxdCompilerService* RawrxdCompilerHandle;

// Build configuration
typedef struct RawrxdBuildConfig {
    const char* projectPath;      // Path to project root
    const char* outputPath;       // Build output directory
    const char* configName;       // "Debug" or "Release"
    const char* targetName;       // Target name
    bool verbose;                 // Verbose output
    bool parallel;                // Parallel compilation
    uint32_t jobs;                // Number of parallel jobs
} RawrxdBuildConfig;

// Build result
typedef struct RawrxdBuildResult {
    bool success;
    int exitCode;
    char* output;                 // Build output (caller frees)
    char* errors;                 // Error output (caller frees)
    uint32_t warningCount;
    uint32_t errorCount;
    uint64_t durationMs;          // Build duration in milliseconds
} RawrxdBuildResult;

// File compilation info
typedef struct RawrxdCompileInfo {
    const char* sourcePath;
    const char* outputPath;
    const char* language;         // "c", "asm", "csharp"
    const char** defines;         // Preprocessor defines
    uint32_t defineCount;
    const char** includePaths;   // Include paths
    uint32_t includeCount;
    bool optimize;               // Enable optimization
    bool debugInfo;               // Generate debug info
} RawrxdCompileInfo;

// Error/warning message
typedef struct RawrxdDiagnostic {
    char* file;
    uint32_t line;
    uint32_t column;
    char* severity;              // "error", "warning", "info"
    char* message;
    char* code;                  // Error code if available
} RawrxdDiagnostic;

/*============================================================================
 * SERVICE LIFECYCLE
 *============================================================================*/

// Initialize compiler service
RawrxdCompilerHandle rawrxd_compiler_init(void);

// Shutdown compiler service
void rawrxd_compiler_shutdown(RawrxdCompilerHandle handle);

// Get compiler version
const char* rawrxd_compiler_version(void);

/*============================================================================
 * BUILD OPERATIONS
 *============================================================================*/

// Build entire project
RawrxdBuildResult* rawrxd_build_project(RawrxdCompilerHandle handle,
                                        const RawrxdBuildConfig* config);

// Compile single file
RawrxdBuildResult* rawrxd_compile_file(RawrxdCompilerHandle handle,
                                       const RawrxdCompileInfo* info);

// Clean build output
bool rawrxd_clean_project(RawrxdCompilerHandle handle,
                          const char* outputPath);

// Free build result
void rawrxd_free_build_result(RawrxdBuildResult* result);

/*============================================================================
 * DIAGNOSTICS & ERROR PARSING
 *============================================================================*/

// Parse compiler output into diagnostics
RawrxdDiagnostic* rawrxd_parse_diagnostics(const char* compilerOutput,
                                          uint32_t* count);

// Free diagnostics array
void rawrxd_free_diagnostics(RawrxdDiagnostic* diagnostics, uint32_t count);

// Get diagnostics for VS Code problem matcher format
char* rawrxd_format_vscode_diagnostics(RawrxdDiagnostic* diagnostics,
                                        uint32_t count);

/*============================================================================
 * PROJECT MANAGEMENT
 *============================================================================*/

// Detect project type from directory
const char* rawrxd_detect_project_type(const char* projectPath);

// Create build tasks.json content for project
char* rawrxd_generate_tasks_json(const char* projectPath);

// Create launch.json content for debugging
char* rawrxd_generate_launch_json(const char* projectPath);

// Check if file needs recompilation (dependency checking)
bool rawrxd_needs_rebuild(const char* sourcePath, const char* outputPath);

/*============================================================================
 * IDE INTEGRATION HELPERS
 *============================================================================*/

// Get include paths for IntelliSense
char** rawrxd_get_intellisense_paths(const char* projectPath,
                                     uint32_t* count);

// Free path array
void rawrxd_free_paths(char** paths, uint32_t count);

// Get compiler flags for specific language
const char* rawrxd_get_compiler_flags(const char* language,
                                      bool debug,
                                      bool optimize);

/*============================================================================
 * GITHUB COPILOT PARITY FEATURES
 *============================================================================*/

// Inline compilation for Copilot suggestions
bool rawrxd_compile_inline(const char* code,
                           const char* language,
                           char** output,
                           char** errors);

// Quick compile for Copilot chat code blocks
RawrxdBuildResult* rawrxd_quick_compile_snippet(const char* code,
                                                const char* language);

// Get symbol information for Copilot context
char* rawrxd_get_symbol_info(const char* sourcePath,
                             uint32_t line,
                             uint32_t column);

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_COMPILER_INTEGRATION_H
