//==============================================================================
// diagnose_simple.cpp
// Simple diagnostic - checks file existence without linking to kernels
//==============================================================================

#include <stdio.h>
#include <windows.h>

bool fileExists(const char* path) {
    DWORD attribs = GetFileAttributesA(path);
    return (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
}

int main() {
    printf("==============================================================================\n");
    printf("Phase 7 Simple Diagnostic\n");
    printf("==============================================================================\n\n");
    
    printf("Checking for kernel library files...\n\n");
    
    const char* files[] = {
        "bin/Sovereign_Legacy_Kernels.lib",
        "bin/Sovereign_Intrinsics.lib", 
        "bin/Titan_KernelIntegration.lib",
        "bin/Titan_KernelIntegration.obj",
        "src/asm/Sovereign_KernelDispatch.h",
        "src/asm/Sovereign_KernelRegistration.cpp",
        "src/asm/Sovereign_KernelRegistry.hpp"
    };
    
    int found = 0;
    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); i++) {
        bool exists = fileExists(files[i]);
        printf("  [%s] %s\n", exists ? "✓" : "✗", files[i]);
        if (exists) found++;
    }
    
    printf("\n");
    printf("Found: %d/%zu files\n", found, sizeof(files)/sizeof(files[0]));
    
    if (found == sizeof(files)/sizeof(files[0])) {
        printf("\n✅ All kernel files present\n");
        printf("\nNext step: Link kernel libraries and run full diagnostic\n");
        return 0;
    } else {
        printf("\n⚠️  Some files missing - check paths\n");
        return 1;
    }
}
