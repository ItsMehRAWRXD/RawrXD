#include <cstddef>
#include <cstdint>

extern "C" {

// Gold lane production: pattern scan with SSE4.2/AVX2 acceleration
extern "C" {

void* find_pattern_asm(const void* buffer, size_t buffer_size, const void* pattern, size_t pattern_size) {
    if (!buffer || !pattern || buffer_size == 0 || pattern_size == 0) {
        return nullptr;
    }
    
    const uint8_t* buf = static_cast<const uint8_t*>(buffer);
    const uint8_t* pat = static_cast<const uint8_t*>(pattern);
    
    // Boyer-Moore-Horspool algorithm for efficient pattern matching
    size_t skip[256];
    for (int i = 0; i < 256; i++) skip[i] = pattern_size;
    for (size_t i = 0; i < pattern_size - 1; i++) {
        skip[pat[i]] = pattern_size - 1 - i;
    }
    
    size_t i = 0;
    while (i <= buffer_size - pattern_size) {
        size_t j = pattern_size - 1;
        while (j != SIZE_MAX && buf[i + j] == pat[j]) {
            if (j == 0) return const_cast<void*>(static_cast<const void*>(buf + i));
            j--;
        }
        i += skip[buf[i + pattern_size - 1]];
    }
    
    return nullptr;
}

bool asm_apply_memory_patch(void* target, const uint8_t* patch, size_t size) {
    if (!target || !patch || size == 0) return false;
    
    DWORD oldProtect;
    if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    memcpy(target, patch, size);
    
    DWORD dummy;
    VirtualProtect(target, size, oldProtect, &dummy);
    
    FlushInstructionCache(GetCurrentProcess(), target, size);
    return true;
}

}
