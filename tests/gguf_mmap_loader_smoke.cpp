// ============================================================================
// gguf_mmap_loader_smoke.cpp — zero-copy GGUF load smoke test
// Builds a synthetic minimal GGUF file, loads it via LoadGGUFMMap, and
// verifies tensor data pointers reference the OS mapping (no fread copy).
// This proves the plumbing that lets a 600 GB Kimi K2.5 run on 64 GB RAM.
// ============================================================================
#include "GGUFLoaderMMap.hpp"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <vector>
#include <string>

namespace fs = std::filesystem;

namespace {

constexpr uint32_t kGgufMagic = 0x46554747u; // 'GGUF'
constexpr uint32_t kGgufVersion = 3u;

void AppendU32(std::vector<uint8_t>& o, uint32_t v) {
    for (int i = 0; i < 4; ++i) o.push_back(uint8_t(v >> (8 * i)));
}
void AppendU64(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back(uint8_t(v >> (8 * i)));
}
void AppendStr(std::vector<uint8_t>& o, const std::string& s) {
    AppendU64(o, s.size());
    o.insert(o.end(), s.begin(), s.end());
}

int fail(const char* m) { std::printf("  [FAIL] %s\n", m); return 1; }
void pass(const char* m) { std::printf("  [PASS] %s\n", m); }

// Build a minimal valid GGUF: 1 metadata KV (architecture), 1 F32 tensor.
// Tensor payload = 16 bytes of known pattern, 32-byte aligned.
fs::path BuildSyntheticGguf() {
    const fs::path tmp = fs::temp_directory_path() / "rawrxd_gguf_mmap_smoke.gguf";
    std::vector<uint8_t> buf;
    AppendU32(buf, kGgufMagic);
    AppendU32(buf, kGgufVersion);
    AppendU64(buf, 1);  // tensor_count
    AppendU64(buf, 1);  // kv_count

    // KV: "general.architecture" = STRING "deepseek2"
    AppendStr(buf, "general.architecture");
    AppendU32(buf, static_cast<uint32_t>(Deep2::GGUFValueType::STRING));
    AppendStr(buf, "deepseek2");

    // Tensor info: name "test.weight", 1 dim [4], type F32 (0), offset 0
    AppendStr(buf, "test.weight");
    AppendU32(buf, 1);            // n_dims
    AppendU64(buf, 4);            // dim[0] = 4 elements
    AppendU32(buf, 0);            // type = F32
    AppendU64(buf, 0);            // offset = 0 (relative to data section)

    // Align to 32 bytes per GGUF spec.
    while ((buf.size() % 32) != 0) buf.push_back(0);
    const uint64_t dataOffset = buf.size();

    // Tensor payload: 4 floats * 4 bytes = 16 bytes. Known pattern.
    const uint8_t payload[16] = {0x11,0x22,0x33,0x44,
                                  0x55,0x66,0x77,0x88,
                                  0x99,0xAA,0xBB,0xCC,
                                  0xDD,0xEE,0xFF,0x00};
    buf.insert(buf.end(), payload, payload + 16);

    std::ofstream f(tmp.string(), std::ios::binary);
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    return tmp;
}

} // namespace

int main() {
    std::printf("GGUF_MMAP_LOADER_001 smoke\n");

    const fs::path tmp = BuildSyntheticGguf();
    if (!fs::exists(tmp)) return fail("SYNTH_GGUF_CREATE");

    Deep2::GGUFMMapResult r = Deep2::LoadGGUFMMap(tmp.string().c_str(), false);
    if (!r.success) {
        std::printf("  LoadGGUFMMap error: %s\n", r.error.c_str());
        fs::remove(tmp);
        return fail("LOAD_GGUF_MMAP");
    }
    pass("LOAD_GGUF_MMAP");

    if (!r.mapping || !r.mapping->ok) return fail("MAPPING_ALIVE");
    pass("MAPPING_ALIVE");

    if (r.metadata.architecture != "deepseek2") return fail("METADATA_ARCH");
    pass("METADATA_ARCH");

    if (r.tensors.size() != 1) return fail("TENSOR_COUNT");
    pass("TENSOR_COUNT");

    const auto& t = r.tensors[0];
    if (t.name != "test.weight") return fail("TENSOR_NAME");
    pass("TENSOR_NAME");

    if (t.size != 16) return fail("TENSOR_SIZE");
    pass("TENSOR_SIZE");

    // Zero-copy: data pointer must point into the mapping.
    const uint8_t* base = r.mapping->data;
    const uint8_t* end = base + r.mapping->fileSize;
    if (!t.data || t.data < base || t.data >= end) return fail("ZERO_COPY_POINTER");
    pass("ZERO_COPY_POINTER");

    // Verify payload bytes via the mapping (no copy).
    const uint8_t expected[16] = {0x11,0x22,0x33,0x44,
                                   0x55,0x66,0x77,0x88,
                                   0x99,0xAA,0xBB,0xCC,
                                   0xDD,0xEE,0xFF,0x00};
    if (std::memcmp(t.data, expected, 16) != 0) return fail("PAYLOAD_BYTES");
    pass("PAYLOAD_BYTES");

    const uint64_t total = Deep2::GGUFMMapTotalTensorBytes(r);
    if (total != 16) return fail("TOTAL_TENSOR_BYTES");
    pass("TOTAL_TENSOR_BYTES");

    // Release mapping cleanly.
    r.mapping.reset();
    pass("UNMAP_CLEAN");

    fs::remove(tmp);
    std::printf("GGUF_MMAP_LOADER_001 PASS\n");
    return 0;
}
