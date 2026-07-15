#include <cstdint>
#include <cstdio>

constexpr uint32_t FNV1aHash(const char* str, size_t len) noexcept {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(str[i]);
        hash *= 0x01000193;
    }
    return hash;
}

int main() {
    printf("file/changed (12): 0x%08X\n", FNV1aHash("file/changed", 12));
    printf("config/changed (14): 0x%08X\n", FNV1aHash("config/changed", 14));
    printf("model/loaded (12): 0x%08X\n", FNV1aHash("model/loaded", 12));
    printf("model/unloaded (14): 0x%08X\n", FNV1aHash("model/unloaded", 14));
    printf("workdir/changed (15): 0x%08X\n", FNV1aHash("workdir/changed", 15));
    printf("command/executed (16): 0x%08X\n", FNV1aHash("command/executed", 16));
    printf("system/shutdown (15): 0x%08X\n", FNV1aHash("system/shutdown", 15));
    return 0;
}
