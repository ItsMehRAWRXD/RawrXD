// REAP writer/reference byte-parity comparison test.
// Links against GGUFLoader, applies the production writer's exact extraction
// logic, and compares output bytes against the independent reference extractor.
//
// Usage: reap_cert_parity <shard.gguf> <tensor_name> <expert_index> <ref_slice.bin>
// Compares: production_writer_slice vs ref_slice.bin for the given expert.

#include "deep2/GGUFLoader.hpp"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

using namespace Deep2;

static bool readFileAll(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    out.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return true;
}

static bool writeFileAll(const std::string& path, const uint8_t* data, uint64_t n) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
    return out.good();
}

static std::string sha256_hex(const uint8_t* data, uint64_t n) {
    // Simple placeholder: return length-based identifier for comparison
    // Real SHA-256 would use a crypto library; we compare byte-for-byte instead
    return std::to_string(n) + ":" + std::to_string(data ? data[0] : 0);
}

int main(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "usage: reap_cert_parity <shard.gguf> <tensor_name> <expert_index> <ref_slice.bin>\n";
        return 2;
    }

    const char* shardPath = argv[1];
    const char* tensorName = argv[2];
    uint32_t expertIndex = static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10));
    const char* refPath = argv[4];

    GGUFLoader loader;
    if (!loader.load(shardPath)) {
        std::cerr << "LOAD_FAILED: " << loader.error() << "\n";
        return 2;
    }

    const GGUFTensor* t = loader.getTensor(tensorName);
    if (!t) {
        std::cerr << "tensor not found: " << tensorName << "\n";
        return 2;
    }

    // Production writer's exact extraction logic:
    // stride = tensor.bytes / tensor.dims.back()
    // offset = tensor_offset + stride * expert
    if (t->shape.empty()) {
        std::cerr << "tensor has no dims\n"; return 2;
    }
    uint64_t expertDim = static_cast<uint64_t>(t->shape.back());
    if (expertDim == 0) { std::cerr << "zero expert dim\n"; return 2; }
    if (expertIndex >= expertDim) {
        std::cerr << "expert " << expertIndex << " >= expertDim " << expertDim << "\n"; return 2;
    }
    if (t->sizeBytes % expertDim != 0) {
        std::cerr << "tensor bytes not divisible by expertDim\n"; return 2;
    }
    uint64_t stride = t->sizeBytes / expertDim;
    uint64_t srcOffset = static_cast<uint64_t>(t->fileOffset) + stride * expertIndex;
    uint64_t expectedBytes = stride;

    // Overflow guard
    if (stride > 0 && expertIndex > 0 && stride > UINT64_MAX / expertIndex) {
        std::cerr << "overflow\n"; return 2;
    }
    if (srcOffset + expectedBytes > static_cast<uint64_t>(t->fileOffset) + t->sizeBytes) {
        std::cerr << "slice exceeds tensor bounds\n"; return 2;
    }

    // Read production slice
    const uint8_t* prodData = t->data + (srcOffset - static_cast<uint64_t>(t->fileOffset));
    std::vector<uint8_t> prodSlice(prodData, prodData + expectedBytes);

    // Read reference slice
    std::vector<uint8_t> refSlice;
    if (!readFileAll(refPath, refSlice)) {
        std::cerr << "cannot read reference file: " << refPath << "\n"; return 2;
    }

    // Compare
    bool match = (prodSlice.size() == refSlice.size()) &&
                 std::memcmp(prodSlice.data(), refSlice.data(), prodSlice.size()) == 0;

    std::cout << "tensor=" << tensorName << "\n";
    std::cout << "  type=" << static_cast<uint32_t>(t->type) << "\n";
    std::cout << "  dims=["; for (size_t i = 0; i < t->shape.size(); ++i) { if (i) std::cout << ","; std::cout << t->shape[i]; } std::cout << "]\n";
    std::cout << "  expertDim=" << expertDim << " expertIndex=" << expertIndex << "\n";
    std::cout << "  stride=" << stride << " srcOffset=" << srcOffset << "\n";
    std::cout << "  expectedBytes=" << expectedBytes << "\n";
    std::cout << "  prodSliceBytes=" << prodSlice.size() << "\n";
    std::cout << "  refSliceBytes=" << refSlice.size() << "\n";
    std::cout << "  BYTE_PARITY=" << (match ? "PASS" : "FAIL") << "\n";

    if (!match) {
        // Find first differing byte
        size_t minSize = std::min(prodSlice.size(), refSlice.size());
        for (size_t i = 0; i < minSize; ++i) {
            if (prodSlice[i] != refSlice[i]) {
                std::cout << "  FIRST_DIFF_BYTE=" << i
                          << " prod=0x" << std::hex << (int)prodSlice[i] << std::dec
                          << " ref=0x" << std::hex << (int)refSlice[i] << std::dec << "\n";
                break;
            }
        }
        return 1;
    }

    return 0;
}
