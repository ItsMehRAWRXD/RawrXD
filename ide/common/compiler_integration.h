/*============================================================================
 * RAWRXD Compiler Driver Integration Header
 * Shared between GUI IDE and CLI IDE
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
 * Compiler Driver API
 *============================================================================*/

// Language types
typedef enum {
    RAWRXD_LANG_C = 0,
    RAWRXD_LANG_ASSEMBLY = 1,
    RAWRXD_LANG_CSHARP = 2,
    RAWRXD_LANG_UNKNOWN = 3
} RawrxdLanguage;

// Compilation result
typedef struct {
    bool success;
    int exitCode;
    char output[4096];
    char error[4096];
    char outputPath[MAX_PATH];
    double compileTimeMs;
} RawrxdCompileResult;

// Build configuration
typedef struct {
    bool optimize;
    bool debug;
    bool verbose;
    char outputName[MAX_PATH];
    char includePaths[1024];
    char libraryPaths[1024];
    char defines[1024];
} RawrxdBuildConfig;

/*============================================================================
 * Core Functions
 *============================================================================*/

// Initialize compiler integration
bool RawrxdCompiler_Init(void);

// Shutdown compiler integration
void RawrxdCompiler_Shutdown(void);

// Detect language from file extension
RawrxdLanguage RawrxdCompiler_DetectLanguage(const char* filePath);

// Compile a single file
RawrxdCompileResult RawrxdCompiler_Compile(const char* sourcePath, const RawrxdBuildConfig* config);

// Build multiple files
RawrxdCompileResult RawrxdCompiler_Build(const char** sourcePaths, int count, const RawrxdBuildConfig* config);

// Clean build artifacts
bool RawrxdCompiler_Clean(const char* projectPath);

// Get compiler version
const char* RawrxdCompiler_GetVersion(void);

// Check if compiler is available
bool RawrxdCompiler_IsAvailable(void);

// Get last error message
const char* RawrxdCompiler_GetLastError(void);

/*============================================================================
 * Utility Functions
 *============================================================================*/

// Get language name as string
const char* RawrxdCompiler_LanguageName(RawrxdLanguage lang);

// Check if file is compilable
bool RawrxdCompiler_IsCompilable(const char* filePath);

// Get supported extensions
const char** RawrxdCompiler_GetExtensions(int* count);

// Format error message for display
void RawrxdCompiler_FormatError(const RawrxdCompileResult* result, char* buffer, size_t bufferSize);

/*============================================================================
 * IDE Integration Helpers
 *============================================================================*/

// Callback for compile progress
typedef void (*RawrxdCompileProgressCallback)(const char* file, int current, int total, void* userData);

// Compile with progress callback
RawrxdCompileResult RawrxdCompiler_CompileWithProgress(
    const char* sourcePath,
    const RawrxdBuildConfig* config,
    RawrxdCompileProgressCallback callback,
    void* userData
);

// Parse compiler output for error/warning extraction
int RawrxdCompiler_ParseErrors(
    const char* compilerOutput,
    char* errorFile,
    int* errorLine,
    char* errorMessage,
    size_t messageSize
);

// Get default build configuration for a project
void RawrxdCompiler_GetDefaultConfig(RawrxdBuildConfig* config, const char* projectPath);

#ifdef __cplusplus
}
#endif

#endif /* RAWRXD_COMPILER_INTEGRATION_H */
