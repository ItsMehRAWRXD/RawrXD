// ============================================================================
// memory_mapped_gguf_smoke.cpp — additive zero-copy shard access smoke test
// Creates a temporary file, memory-maps it, and verifies pointer-based reads.
// This proves the plumbing for 600 GB model streaming without materializing
// whole shards into process RAM.
// ============================================================================
#include "MemoryMappedFile.hpp"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static int fail(const char* m) {
    std::printf("  [FAIL] %s\n", m);
    return 1;
}
static void pass(const char* m) { std::printf("  [PASS] %s\n", m); }

static fs::path MakeTempFile(size_t size) {
    const fs::path tmp = fs::temp_directory_path() / "rawrxd_mm_gguf_smoke.bin";
    std::ofstream f(tmp.string(), std::ios::binary);
    std::vector<uint8_t> buf(size);
    for (size_t i = 0; i < size; ++i) buf[i] = static_cast<uint8_t>(i & 0xFF);
    f.write(reinterpret_cast<const char*>(buf.data()), size);
    return tmp;
}

int main() {
    std::printf("MEMORY_MAPPED_GGUF_001 smoke\n");

    const size_t kSize = 64 * 1024 * 1024; // 64 MiB
    const fs::path tmp = MakeTempFile(kSize);
    if (!fs::exists(tmp)) return fail("TEMP_FILE_CREATE");

    Deep2::MemoryMappedFile mm;
    if (!mm.Map(tmp.string().c_str())) {
        std::printf("  Map error: %s\n", mm.error.c_str());
        return fail("MAP_FILE");
    }
    pass("MAP_FILE");

    if (mm.fileSize != kSize) return fail("FILE_SIZE_MATCH");
    pass("FILE_SIZE_MATCH");

    const uint8_t* head = mm.At(0, 16);
    if (!head || head[0] != 0 || head[15] != 15) return fail("HEAD_BYTES");
    pass("HEAD_BYTES");

    const uint8_t* tail = mm.At(kSize - 16, 16);
    if (!tail || tail[0] != static_cast<uint8_t>((kSize - 16) & 0xFF)) return fail("TAIL_BYTES");
    pass("TAIL_BYTES");

    // Out-of-bounds read must return nullptr.
    if (mm.At(kSize - 8, 16) != nullptr) return fail("BOUNDS_CHECK");
    pass("BOUNDS_CHECK");

    mm.Unmap();
    if (mm.ok || mm.data) return fail("UNMAP_CLEAN");
    pass("UNMAP_CLEAN");

    fs::remove(tmp);

    std::printf("MEMORY_MAPPED_GGUF_001 PASS\n");
    return 0;
}
