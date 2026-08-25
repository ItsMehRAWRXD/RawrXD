// minimal_gold_main.cpp - Minimal RawrXD Gold entry point
// This is a stripped-down version that builds quickly for testing

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Minimal implementations for missing symbols
extern "C" {
    void RawrXD_Native_Log(const char* msg) {
        OutputDebugStringA(msg);
        OutputDebugStringA("\n");
    }
    
    // Hotpatch stubs - REMOVED: now provided by gold_link_closure.cpp
    // int find_pattern_asm(const char* data, unsigned char* pattern, size_t len) { return -1; }
    // int asm_apply_memory_patch(void* addr, void* data, size_t len) { return 0; }
}

// Main entry point
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
    
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONIN$", "r", stdin);
    
    printf("========================================\n");
    printf("RawrXD Gold (Minimal Build)\n");
    printf("========================================\n\n");
    
    printf("Status: Running in minimal mode\n");
    printf("Features: Core runtime only\n\n");
    
    printf("Press Enter to exit...\n");
    getchar();
    
    return 0;
}
