#include <cstddef>
#include <cstdint>

extern "C" {

// Gold lane stub: pattern scan is intentionally disabled in strict standalone profile.
void* find_pattern_asm(const void* /*buffer*/, size_t /*buffer_size*/, const void* /*pattern*/, size_t /*pattern_size*/) {
    return nullptr;
}

// Gold lane stub: memory patching is intentionally disabled in strict standalone profile.
bool asm_apply_memory_patch(void* /*target*/, const uint8_t* /*patch*/, size_t /*size*/) {
    return false;
}

}
