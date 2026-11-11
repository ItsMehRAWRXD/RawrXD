//=============================================================================
// rawrxd_compiler_backend.h - RawrXD Compiler Native Backend Header
//=============================================================================

#ifndef RAWRXD_COMPILER_BACKEND_H
#define RAWRXD_COMPILER_BACKEND_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// Version
//=============================================================================

#define NATIVE_BACKEND_VERSION "1.0.0"
#define NATIVE_BACKEND_VERSION_MAJOR 1
#define NATIVE_BACKEND_VERSION_MINOR 0
#define NATIVE_BACKEND_VERSION_PATCH 0

//=============================================================================
// Constants
//=============================================================================

#define MAX_PATH_LENGTH 512
#define MAX_ERROR_LENGTH 4096

//=============================================================================
// Opaque Types
//=============================================================================

typedef struct NativeToolchain NativeToolchain;

//=============================================================================
// Statistics Structure
//=============================================================================

typedef struct {
    int files_assembled;
    int files_linked;
    int total_compile_time_ms;
} NativeToolchainStats;

//=============================================================================
// Lifecycle Functions
//=============================================================================

// Create a new native toolchain instance
NativeToolchain* native_toolchain_create(void);

// Destroy a native toolchain instance
void native_toolchain_destroy(NativeToolchain* tc);

// Set verbose mode
void native_toolchain_set_verbose(NativeToolchain* tc, int verbose);

// Get last error message
const char* native_toolchain_get_error(NativeToolchain* tc);

//=============================================================================
// Compilation Functions
//=============================================================================

// Compile ASM source code directly to executable
// Returns: 0 on success, -1 on error
int native_toolchain_compile_asm(NativeToolchain* tc,
                                  const char* asm_source,
                                  const char* output_exe);

// Compile ASM file to executable
// Returns: 0 on success, -1 on error
int native_toolchain_compile_asm_file(NativeToolchain* tc,
                                       const char* asm_file,
                                       const char* output_exe);

// Link multiple object files to executable
// Returns: 0 on success, -1 on error
int native_toolchain_link_objects(NativeToolchain* tc,
                                   const char** obj_files,
                                   int obj_count,
                                   const char* output_exe);

//=============================================================================
// Statistics Functions
//=============================================================================

// Get compilation statistics
void native_toolchain_get_stats(NativeToolchain* tc, NativeToolchainStats* stats);

// Reset statistics
void native_toolchain_reset_stats(NativeToolchain* tc);

//=============================================================================
// Utility Functions
//=============================================================================

// Print comparison table between native and external tools
void native_toolchain_print_comparison(void);

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_COMPILER_BACKEND_H
