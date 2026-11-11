//==============================================================================
// diagnose_kernel_loading.cpp
// Comprehensive diagnostic for kernel loading issues
//
// Checks:
// 1. Library file existence
// 2. Export table inspection
// 3. Function pointer loading
// 4. Direct kernel calls
//
// Date: July 10, 2026
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>
#include <vector>
#include <string>

// Kernel function types
typedef int (*pfn_rms_norm)(float*, float*, float*, size_t, float);
typedef int (*pfn_layer_norm)(float*, float*, float*, float*, size_t, float);
typedef int (*pfn_residual_add)(float*, float*, float*, size_t);
typedef int (*pfn_q4q8_matmul)(const void*, const void*, float*, size_t, size_t, size_t);
typedef int (*pfn_flash_attention)(float*, float*, float*, float*, size_t, size_t);

struct KernelInfo {
    const char* name;
    const char* library;
    void** ptr;
    bool required;
};

//==============================================================================
// Color output
//==============================================================================
void print_success(const char* msg) {
    printf("[\x1b[32mOK\x1b[0m] %s\n", msg);
}

void print_error(const char* msg) {
    printf("[\x1b[31mFAIL\x1b[0m] %s\n", msg);
}

void print_warning(const char* msg) {
    printf("[\x1b[33mWARN\x1b[0m] %s\n", msg);
}

void print_info(const char* msg) {
    printf("[INFO] %s\n", msg);
}

//==============================================================================
// Library Loading
//==============================================================================
HMODULE LoadKernelLibrary(const char* path) {
    HMODULE hMod = LoadLibraryA(path);
    if (!hMod) {
        DWORD err = GetLastError();
        printf("    LoadLibrary failed: %lu\n", err);
        return nullptr;
    }
    return hMod;
}

void* GetKernelProc(HMODULE hMod, const char* name) {
    if (!hMod) return nullptr;
    void* proc = GetProcAddress(hMod, name);
    return proc;
}

//==============================================================================
// Test 1: Check Library Files Exist
//==============================================================================
bool Test_LibraryFilesExist() {
    printf("\n=== Test 1: Library File Existence ===\n\n");
    
    const char* libraries[] = {
        "Sovereign_RMSNorm.lib",
        "Sovereign_LayerNorm.lib",
        "Sovereign_ResidualAdd.lib",
        "Sovereign_RoPE.lib",
        "Sovereign_Q4K_Dequant.lib",
        "Sovereign_Legacy_Kernels.lib",
        "Sovereign_Intrinsics.lib",
        "Sovereign_KernelDispatch.lib",
        nullptr
    };
    
    int found = 0;
    int total = 0;
    
    for (int i = 0; libraries[i]; i++) {
        total++;
        HANDLE hFile = CreateFileA(libraries[i], GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            print_success(libraries[i]);
            found++;
        } else {
            print_error(libraries[i]);
        }
    }
    
    printf("\n  Found: %d/%d libraries\n", found, total);
    return found > 0;
}

//==============================================================================
// Test 2: Load Libraries and Get Exports
//==============================================================================
bool Test_LoadLibrariesAndExports() {
    printf("\n=== Test 2: Library Loading and Exports ===\n\n");
    
    struct LibExport {
        const char* libName;
        const char* funcName;
        void** ptr;
    };
    
    void* ptr_rms_norm = nullptr;
    void* ptr_layer_norm = nullptr;
    void* ptr_residual_add = nullptr;
    void* ptr_q4q8_matmul = nullptr;
    void* ptr_flash_attention = nullptr;
    
    LibExport exports[] = {
        {"Sovereign_RMSNorm.dll", "rms_norm_f32", &ptr_rms_norm},
        {"Sovereign_LayerNorm.dll", "layer_norm_f32", &ptr_layer_norm},
        {"Sovereign_ResidualAdd.dll", "residual_add_f32", &ptr_residual_add},
        {"Sovereign_Intrinsics.dll", "Sovereign_Q4Q8_MatMul_Intrinsics", &ptr_q4q8_matmul},
        {"Sovereign_Legacy_Kernels.dll", "q4_0_q8_0_matmul", &ptr_q4q8_matmul},
        {"Sovereign_Legacy_Kernels.dll", "flash_attention_v2_f32", &ptr_flash_attention},
        {nullptr, nullptr, nullptr}
    };
    
    int loaded = 0;
    int found = 0;
    
    for (int i = 0; exports[i].libName; i++) {
        printf("  Loading %s...\n", exports[i].libName);
        
        HMODULE hMod = LoadKernelLibrary(exports[i].libName);
        if (hMod) {
            loaded++;
            void* proc = GetKernelProc(hMod, exports[i].funcName);
            if (proc) {
                printf("    -> %s @ %p\n", exports[i].funcName, proc);
                *exports[i].ptr = proc;
                found++;
            } else {
                print_warning("Export not found");
            }
        }
    }
    
    printf("\n  Libraries loaded: %d\n", loaded);
    printf("  Functions found: %d\n", found);
    
    return found > 0;
}

//==============================================================================
// Test 3: Direct Kernel Calls
//==============================================================================
bool Test_DirectKernelCalls() {
    printf("\n=== Test 3: Direct Kernel Calls ===\n\n");
    
    // Try to load the libraries directly
    HMODULE hRMSNorm = LoadKernelLibrary("Sovereign_RMSNorm.dll");
    HMODULE hResidual = LoadKernelLibrary("Sovereign_ResidualAdd.dll");
    
    if (!hRMSNorm && !hResidual) {
        print_error("Cannot load any kernel libraries");
        print_info("Make sure .dll files exist (not just .lib)");
        return false;
    }
    
    // Test RMSNorm
    if (hRMSNorm) {
        pfn_rms_norm rms_norm = (pfn_rms_norm)GetKernelProc(hRMSNorm, "rms_norm_f32");
        if (rms_norm) {
            print_success("rms_norm_f32 found");
            
            // Test call
            float input[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
            float output[8] = {0};
            float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
            
            printf("    Calling rms_norm_f32...\n");
            int result = rms_norm(input, output, weight, 8, 1e-6f);
            
            if (result == 0) {
                print_success("Kernel returned 0 (success)");
                printf("    Output[0] = %f (expected ~1.0)\n", output[0]);
                
                if (output[0] > 0.9f && output[0] < 1.1f) {
                    print_success("Output value is correct!");
                } else {
                    print_error("Output value is incorrect");
                }
            } else {
                print_error("Kernel returned error code");
            }
        } else {
            print_error("rms_norm_f32 not found in library");
        }
    }
    
    // Test ResidualAdd
    if (hResidual) {
        pfn_residual_add residual_add = (pfn_residual_add)GetKernelProc(hResidual, "residual_add_f32");
        if (residual_add) {
            print_success("residual_add_f32 found");
            
            float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
            float residual[8] = {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f};
            float output[8] = {0};
            
            printf("    Calling residual_add_f32...\n");
            int result = residual_add(input, residual, output, 8);
            
            if (result == 0) {
                print_success("Kernel returned 0 (success)");
                printf("    Output[0] = %f (expected 1.5)\n", output[0]);
                
                if (output[0] > 1.4f && output[0] < 1.6f) {
                    print_success("Output value is correct!");
                } else {
                    print_error("Output value is incorrect");
                }
            } else {
                print_error("Kernel returned error code");
            }
        } else {
            print_error("residual_add_f32 not found in library");
        }
    }
    
    return true;
}

//==============================================================================
// Test 4: Check for Static Libraries
//==============================================================================
bool Test_StaticLibraries() {
    printf("\n=== Test 4: Static Library Analysis ===\n\n");
    
    print_info("Static libraries (.lib) are linked at compile time");
    print_info("Dynamic libraries (.dll) are loaded at runtime");
    print_info("");
    print_info("If you only have .lib files:");
    print_info("  - They must be linked when building the executable");
    print_info("  - Function pointers should be resolved by linker");
    print_info("  - Check linker command line for /DEFAULTLIB: directives");
    print_info("");
    print_info("If you have .dll files:");
    print_info("  - They must be in PATH or same directory as .exe");
    print_info("  - LoadLibrary/GetProcAddress should work");
    print_info("");
    
    // Check for dumpbin
    FILE* pipe = _popen("where dumpbin 2>nul", "r");
    if (pipe) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), pipe)) {
            print_success("dumpbin.exe found (can inspect .lib exports)");
        } else {
            print_warning("dumpbin.exe not found (install Visual Studio tools)");
        }
        _pclose(pipe);
    }
    
    return true;
}

//==============================================================================
// Main
//==============================================================================
int main() {
    printf("==============================================================================\n");
    printf("Sovereign Kernel Loading Diagnostics\n");
    printf("==============================================================================\n");
    printf("\n");
    printf("This tool diagnoses why kernel function pointers are NULL\n");
    printf("\n");
    
    bool all_passed = true;
    
    all_passed &= Test_LibraryFilesExist();
    all_passed &= Test_LoadLibrariesAndExports();
    all_passed &= Test_DirectKernelCalls();
    all_passed &= Test_StaticLibraries();
    
    printf("\n==============================================================================\n");
    printf("SUMMARY\n");
    printf("==============================================================================\n\n");
    
    if (all_passed) {
        print_success("All diagnostics passed");
        printf("\nIf kernels still don't work, the issue is likely:\n");
        printf("  1. Calling convention mismatch (check __cdecl vs __stdcall)\n");
        printf("  2. Struct alignment issues (check #pragma pack)\n");
        printf("  3. Name mangling (use extern \"C\" in C++)\n");
    } else {
        print_error("Some diagnostics failed");
        printf("\nCommon fixes:\n");
        printf("  1. Ensure .lib files are in the linker's search path\n");
        printf("  2. Add /LIBPATH: directive for kernel libraries\n");
        printf("  3. Link against specific .lib files explicitly\n");
        printf("  4. Check that kernel functions are exported with __declspec(dllexport)\n");
    }
    
    printf("\n==============================================================================\n");
    
    return all_passed ? 0 : 1;
}
