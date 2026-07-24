// ============================================================================
// model_router_stubs.cpp - Stub implementations for universal model router
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

// Universal model router stubs
bool LoadModel(const char* modelPath) {
    (void)modelPath;
    OutputDebugStringA("[ModelRouter] LoadModel stub called\n");
    return false;
}

bool ModelLoaderInit() {
    OutputDebugStringA("[ModelRouter] ModelLoaderInit stub called\n");
    return true;
}

bool HotSwapModel(const char* modelPath) {
    (void)modelPath;
    OutputDebugStringA("[ModelRouter] HotSwapModel stub called\n");
    return false;
}

} // extern "C"
