// ============================================================================
// pattern_stubs.cpp - Stub implementations for pattern search functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

void* find_pattern_asm(const void* base, size_t size, const char* pattern, const char* mask) {
    (void)base;
    (void)size;
    (void)pattern;
    (void)mask;
    OutputDebugStringA("[Pattern] find_pattern_asm stub called\n");
    return nullptr;
}

} // extern "C"
