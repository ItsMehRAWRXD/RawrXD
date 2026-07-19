# RAWRXD Compiler Driver - API Examples

**Version:** 1.0.0  
**Date:** 2026-07-19

---

## 📚 C API Examples

### Example 1: Basic Compilation

```c
#include "rawrxd_compiler.h"
#include <stdio.h>

int main() {
    // Initialize the driver
    rxd_driver_init();
    
    // Register backends
    rxd_register_c_backend();
    
    // Set up compile options
    rxd_compile_options_t options;
    rxd_options_init(&options);
    
    // Compile a file
    rxd_compile_result_t result;
    rxd_result_init(&result);
    
    rxd_compile_file("hello.c", "hello.exe", &options, &result);
    
    // Check result
    if (rxd_result_success(&result)) {
        printf("Compiled successfully!\n");
        printf("Output: %s\n", result.output_path);
    } else {
        printf("Compilation failed!\n");
        rxd_result_print_diagnostics(&result);
    }
    
    // Cleanup
    rxd_result_free(&result);
    rxd_driver_shutdown();
    
    return 0;
}
```

---

### Example 2: Using All Backends

```c
#include "rawrxd_compiler.h"
#include <stdio.h>

int main() {
    rxd_driver_init();
    
    // Register all backends
    rxd_register_c_backend();
    rxd_register_asm_backend();
    rxd_register_csharp_backend();
    
    // List available backends
    int count = rxd_driver_get_backend_count();
    printf("Available backends: %d\n\n", count);
    
    for (int i = 0; i < count; i++) {
        rxd_compiler_info_t info;
        rxd_driver_get_backend_info(i, &info);
        printf("[%d] %s v%s (%s)\n", 
               i + 1, info.name, info.version,
               info.is_available ? "available" : "unavailable");
    }
    
    rxd_driver_shutdown();
    return 0;
}
```

---

### Example 3: Language Detection

```c
#include "rawrxd_compiler.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file>\n", argv[0]);
        return 1;
    }
    
    const char* file = argv[1];
    
    // Auto-detect language
    rxd_language_t lang = rxd_detect_language(file);
    
    printf("File: %s\n", file);
    printf("Detected language: %s\n", rxd_language_to_string(lang));
    
    return 0;
}
```

---

### Example 4: Handling Diagnostics

```c
#include "rawrxd_compiler.h"
#include <stdio.h>

void print_detailed_diagnostics(const rxd_compile_result_t* result) {
    printf("=== Compilation Result ===\n");
    printf("Status: %s\n", rxd_result_success(result) ? "SUCCESS" : "FAILED");
    printf("Errors: %d\n", rxd_result_get_error_count(result));
    printf("Warnings: %d\n", rxd_result_get_warning_count(result));
    printf("Time: %llu ms\n", result->compile_time_ms);
    printf("\n");
    
    // Print each diagnostic
    for (int i = 0; i < result->diagnostics.count; i++) {
        const rxd_diagnostic_t* diag = &result->diagnostics.items[i];
        
        printf("[%s] %s\n", 
               rxd_severity_to_string(diag->severity),
               diag->code);
        printf("  File: %s\n", diag->file);
        printf("  Line: %d, Column: %d\n", diag->line, diag->column);
        printf("  Message: %s\n", diag->message);
        printf("\n");
    }
}

int main() {
    rxd_driver_init();
    rxd_register_c_backend();
    
    rxd_compile_options_t options;
    rxd_options_init(&options);
    
    rxd_compile_result_t result;
    rxd_compile_file("test.c", NULL, &options, &result);
    
    print_detailed_diagnostics(&result);
    
    rxd_result_free(&result);
    rxd_driver_shutdown();
    
    return 0;
}
```

---

### Example 5: Configuration System

```c
#include "rawrxd_compiler.h"
#include <stdio.h>

// Note: config.c functions need to be declared or included
extern int rxd_config_init(void);
extern void rxd_config_shutdown(void);
extern const char* rxd_config_get(const char* key, const char* default_value);
extern int rxd_config_set(const char* key, const char* value);
extern bool rxd_config_get_bool(const char* key, bool default_value);

int main() {
    // Initialize config
    rxd_config_init();
    
    // Set configuration values
    rxd_config_set("compiler.optimize", "true");
    rxd_config_set("compiler.debug", "true");
    rxd_config_set("output.directory", "build");
    
    // Read configuration
    bool optimize = rxd_config_get_bool("compiler.optimize", false);
    bool debug = rxd_config_get_bool("compiler.debug", false);
    const char* output_dir = rxd_config_get("output.directory", "output");
    
    printf("Configuration:\n");
    printf("  Optimize: %s\n", optimize ? "yes" : "no");
    printf("  Debug: %s\n", debug ? "yes" : "no");
    printf("  Output: %s\n", output_dir);
    
    // Use in compilation
    rxd_driver_init();
    rxd_register_c_backend();
    
    rxd_compile_options_t options;
    rxd_options_init(&options);
    rxd_options_set_optimize(&options, optimize);
    rxd_options_set_debug(&options, debug);
    
    // ... compile ...
    
    rxd_driver_shutdown();
    rxd_config_shutdown();
    
    return 0;
}
```

---

### Example 6: Custom Backend

```c
#include "rawrxd_compiler.h"
#include <stdio.h>
#include <string.h>

// Custom backend context
typedef struct {
    char name[64];
    int compile_count;
} custom_backend_context_t;

// Custom backend implementation
static int custom_init(void** context) {
    custom_backend_context_t* ctx = malloc(sizeof(*ctx));
    strcpy(ctx->name, "custom-backend");
    ctx->compile_count = 0;
    *context = ctx;
    return 0;
}

static void custom_shutdown(void* context) {
    custom_backend_context_t* ctx = context;
    printf("Custom backend compiled %d files\n", ctx->compile_count);
    free(ctx);
}

static bool custom_can_compile(const char* file_path) {
    // Only compile .custom files
    const char* ext = strrchr(file_path, '.');
    return ext && strcmp(ext, ".custom") == 0;
}

static rxd_result_t custom_compile(void* context, 
                                    const rxd_compile_options_t* options,
                                    rxd_compile_result_t* result) {
    custom_backend_context_t* ctx = context;
    
    printf("Custom backend compiling: %s\n", options->input_file);
    ctx->compile_count++;
    
    // Simulate compilation
    result->result = RXD_RESULT_OK;
    strcpy(result->output_path, "output.exe");
    
    return RXD_RESULT_OK;
}

// Register custom backend
static rxd_backend_vtable_t custom_backend = {
    .name = "rawrxd-custom",
    .version = "1.0.0",
    .language = RXD_LANG_UNKNOWN,  // Custom
    .init = custom_init,
    .shutdown = custom_shutdown,
    .can_compile = custom_can_compile,
    .compile = custom_compile
};

int main() {
    rxd_driver_init();
    
    // Register custom backend
    int backend_id = rxd_driver_register_backend(&custom_backend);
    printf("Registered custom backend: %d\n", backend_id);
    
    // Use it
    rxd_compile_options_t options;
    rxd_options_init(&options);
    
    rxd_compile_result_t result;
    rxd_compile_file("test.custom", NULL, &options, &result);
    
    rxd_result_free(&result);
    rxd_driver_shutdown();
    
    return 0;
}
```

---

## 🐍 Python Bindings (Example)

```python
# rawrxd.py - Python bindings for RAWRXD Compiler Driver

import ctypes
import os

# Load the library
if os.name == 'nt':
    lib = ctypes.CDLL('./rawrxd-compiler.dll')
else:
    lib = ctypes.CDLL('./librawrxd.so')

# Define types
class CompileOptions(ctypes.Structure):
    _fields_ = [
        ("input_file", ctypes.c_char * 260),
        ("output_file", ctypes.c_char * 260),
        ("language", ctypes.c_int),
        ("optimize", ctypes.c_bool),
        ("debug_info", ctypes.c_bool),
        ("verbose_level", ctypes.c_int)
    ]

class CompileResult(ctypes.Structure):
    _fields_ = [
        ("result", ctypes.c_int),
        ("output_path", ctypes.c_char * 260),
        ("compile_time_ms", ctypes.c_uint64)
    ]

# Define functions
lib.rxd_driver_init.restype = ctypes.c_int
lib.rxd_driver_shutdown.restype = None
lib.rxd_compile_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p, 
                                  ctypes.POINTER(CompileOptions),
                                  ctypes.POINTER(CompileResult)]
lib.rxd_compile_file.restype = ctypes.c_int

# Python wrapper
class RAWRXDCompiler:
    def __init__(self):
        lib.rxd_driver_init()
    
    def __del__(self):
        lib.rxd_driver_shutdown()
    
    def compile(self, source_file, output_file=None, optimize=False, debug=True):
        options = CompileOptions()
        options.input_file = source_file.encode()
        if output_file:
            options.output_file = output_file.encode()
        options.optimize = optimize
        options.debug_info = debug
        
        result = CompileResult()
        
        ret = lib.rxd_compile_file(
            source_file.encode(),
            output_file.encode() if output_file else None,
            ctypes.byref(options),
            ctypes.byref(result)
        )
        
        return {
            'success': ret == 0,
            'output': result.output_path.decode(),
            'time_ms': result.compile_time_ms
        }

# Usage
if __name__ == '__main__':
    compiler = RAWRXDCompiler()
    result = compiler.compile('hello.c', optimize=True)
    print(f"Success: {result['success']}")
    print(f"Output: {result['output']}")
    print(f"Time: {result['time_ms']}ms")
```

---

## 🔧 Advanced Usage

### Batch Compilation

```c
#include "rawrxd_compiler.h"
#include <stdio.h>

int compile_multiple(const char** files, int count) {
    rxd_driver_init();
    rxd_register_c_backend();
    
    int success_count = 0;
    
    for (int i = 0; i < count; i++) {
        printf("Compiling [%d/%d]: %s\n", i + 1, count, files[i]);
        
        rxd_compile_options_t options;
        rxd_options_init(&options);
        
        rxd_compile_result_t result;
        rxd_compile_file(files[i], NULL, &options, &result);
        
        if (rxd_result_success(&result)) {
            success_count++;
            printf("  ✓ Success\n");
        } else {
            printf("  ✗ Failed\n");
            rxd_result_print_diagnostics(&result);
        }
        
        rxd_result_free(&result);
    }
    
    printf("\nCompiled %d/%d files successfully\n", success_count, count);
    
    rxd_driver_shutdown();
    return success_count == count ? 0 : 1;
}

int main() {
    const char* files[] = {
        "file1.c",
        "file2.c",
        "file3.c"
    };
    
    return compile_multiple(files, 3);
}
```

---

## 📖 More Examples

See the `examples/` directory for complete working examples:
- `examples/hello_world/` - Simple compilation examples
- `examples/api_usage/` - API demonstration
- `examples/custom_backend/` - Custom backend example

---

*API Examples for RAWRXD Compiler Driver v1.0.0*
