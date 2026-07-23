// asm_stubs_pattern.cpp - Stub implementations for pattern finder ASM exports

#include <cstdint>
#include <cstddef>

extern "C" {

// Pattern finder stub - returns first occurrence or nullptr
void* find_pattern_asm(void* startAddr, size_t size, const void* pattern, size_t patternSize) {
    (void)size; (void)patternSize;
    if (!startAddr || !pattern) return nullptr;
    // Stub: just return start address as "found" location
    return startAddr;
}

} // extern "C"
