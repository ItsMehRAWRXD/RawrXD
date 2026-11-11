// ============================================================================
// spengine_stubs.cpp - Stub implementations for self-patch engine functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

void asm_spengine_cpu_optimize() {
    OutputDebugStringA("[SPEngine] asm_spengine_cpu_optimize stub called\n");
}

void asm_apply_memory_patch() {
    OutputDebugStringA("[SPEngine] asm_apply_memory_patch stub called\n");
}

} // extern "C"
