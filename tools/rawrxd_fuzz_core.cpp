// ============================================================================
// rawrxd_fuzz_core.cpp -- RawrXD fuzzing core for GGUF v3 + REAP validation.
// Standalone C++17 harness with two bounded validation adapters.
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>

namespace rawrxd {
namespace fuzz {

struct GGUFHeader {
    char magic[4];
    uint32_t version;
    uint64_t n_tensors;
    uint64_t n_kv;
};

bool validate_ggu_header(const uint8_t* data, size_t len, std::string& err) {
    if (len < 24) { err = "GGUF: input too small"; return false; }
    if (data[0] != 'G' || data[1] != 'G' || data[2] != 'U' || data[3] != 'F') {
        err = "GGUF: invalid magic"; return false;
    }
    uint32_t version;
    std::memcpy(&version, data + 4, 4);
    if (version != 3) { err = "GGUF: unsupported version"; return false; }
    uint64_t n_tensors;
    std::memcpy(&n_tensors, data + 8, 8);
    if (n_tensors > 1000000) { err = "GGUF: tensor count too large"; return false; }
    uint64_t n_kv;
    std::memcpy(&n_kv, data + 16, 8);
    if (n_kv > 100000) { err = "GGUF: KV count too large"; return false; }
    return true;
}

bool validate_reap_expert_indices(const uint8_t* data, size_t len, std::string& err) {
    if (len < 12) { err = "REAP: input too small"; return false; }
    uint32_t numLayers, numExperts, topK;
    std::memcpy(&numLayers, data + 0, 4);
    std::memcpy(&numExperts, data + 4, 4);
    std::memcpy(&topK, data + 8, 4);
    if (numLayers == 0 || numLayers > 1000) { err = "REAP: invalid layer count"; return false; }
    if (numExperts == 0 || numExperts > 512) { err = "REAP: invalid expert count"; return false; }
    if (topK == 0 || topK > numExperts) { err = "REAP: topK > numExperts"; return false; }
    size_t expected = 12 + numLayers * topK * 4;
    if (len < expected) { err = "REAP: truncated expert data"; return false; }
    for (uint32_t layer = 0; layer < numLayers; ++layer) {
        for (uint32_t slot = 0; slot < topK; ++slot) {
            uint32_t expertId;
            size_t off = 12 + (layer * topK + slot) * 4;
            std::memcpy(&expertId, data + off, 4);
            if (expertId >= numExperts) {
                err = "REAP: expert index OOB";
                return false;
            }
        }
    }
    return true;
}

int fuzz_one(const uint8_t* data, size_t len) {
    std::string err;
    if (validate_ggu_header(data, len, err)) {
        std::printf("[FUZZ] GGUF v3 header OK (%zu bytes)\n", len);
        return 0;
    }
    if (validate_reap_expert_indices(data, len, err)) {
        std::printf("[FUZZ] REAP expert indices OK (%zu bytes)\n", len);
        return 0;
    }
    std::printf("[FUZZ] REJECTED: %s\n", err.c_str());
    return 1;
}

int self_test() {
    uint8_t gguf[] = {'G','G','U','F', 3,0,0,0, 1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0};
    std::string err;
    if (!validate_ggu_header(gguf, sizeof(gguf), err)) { std::printf("FAIL: %s\n", err.c_str()); return 1; }
    std::printf("[SELFTEST] GGUF header: PASS\n");

    uint8_t reap[] = {2,0,0,0, 4,0,0,0, 2,0,0,0, 0,0,0,0,1,0,0,0, 2,0,0,0,3,0,0,0};
    if (!validate_reap_expert_indices(reap, sizeof(reap), err)) { std::printf("FAIL: %s\n", err.c_str()); return 1; }
    std::printf("[SELFTEST] REAP indices: PASS\n");

    uint8_t bad_reap[] = {1,0,0,0, 2,0,0,0, 1,0,0,0, 5,0,0,0};
    if (validate_reap_expert_indices(bad_reap, sizeof(bad_reap), err)) { std::printf("FAIL: expected OOB rejection\n"); return 1; }
    std::printf("[SELFTEST] REAP OOB rejection: PASS\n");

    std::printf("[SELFTEST] ALL TESTS PASS\n");
    return 0;
}

} // namespace fuzz
} // namespace rawrxd

#ifdef RAWRXD_STANDALONE
int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "Usage: rawrxd_fuzz_core <file>|--self-test\n"); return 1; }
    if (std::strcmp(argv[1], "--self-test") == 0) return rawrxd::fuzz::self_test();
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) { std::fprintf(stderr, "Cannot open: %s\n", argv[1]); return 1; }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return rawrxd::fuzz::fuzz_one(buf.data(), buf.size());
}
#endif