// ============================================================================
// reap_tile_probe.cpp — P2 lossless Q4_0 tile-reconstruction probe.
//
// Modes:
//   --list [substr]         list tensor names
//   --info <tensor>         print type, shape, block math, derived strides
//   --tensor <name>         flat whole-tensor stream vs whole-tensor reference
//   --tensor <name> --expert E --rows R0:R1
//                           expert-slice addressing: stream only that slice
//
// Q4_0 blocks are 18 bytes (fp16 scale + 16 packed nibble bytes = 32 values).
// A tile is N *blocks*, never N bytes, so a scale is never split from its
// nibbles. Slices are addressed in block space using checked 64-bit math and
// are validated against the tensor's byte range before any read.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <string>
#include <vector>

#include "deep2/GGUFLoader.hpp"
#include "ggml.h"

namespace {

constexpr int      QK4_0 = 32;   // values per block
constexpr uint64_t BK4_0 = 18;   // bytes per block

uint64_t fnv1a(const void* p, size_t n) {
    const unsigned char* b = static_cast<const unsigned char*>(p);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

bool mulOverflows(uint64_t a, uint64_t b) {
    return a != 0 && b > (UINT64_MAX / a);
}

void usage(const char* argv0) {
    std::fprintf(stderr,
        "Usage: %s --model <gguf> [--list [substr]] | [--info <tensor>] |\n"
        "          --tensor <name> [--expert E --rows R0:R1]\n"
        "          [--tile-blocks N] [--scratch-bytes N] [--dump <path>]\n",
        argv0);
}

struct Slice {
    uint64_t startBlock = 0;
    uint64_t blockCount = 0;
    uint64_t elementCount = 0;
    uint64_t startByte = 0;
    uint64_t byteCount = 0;
};

} // namespace

int main(int argc, char** argv) {
    std::string modelPath, tensorName, listSubstr, dumpPath, rowsSpec, infoName;
    int tileBlocks = 64;
    uint64_t scratchCap = 0;
    int64_t expert = -1;
    bool listMode = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) modelPath = argv[++i];
        else if (a == "--tensor" && i + 1 < argc) tensorName = argv[++i];
        else if (a == "--info" && i + 1 < argc) infoName = argv[++i];
        else if (a == "--expert" && i + 1 < argc) expert = std::atoll(argv[++i]);
        else if (a == "--rows" && i + 1 < argc) rowsSpec = argv[++i];
        else if (a == "--list") {
            listMode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') listSubstr = argv[++i];
        }
        else if (a == "--tile-blocks" && i + 1 < argc) tileBlocks = std::atoi(argv[++i]);
        else if (a == "--scratch-bytes" && i + 1 < argc)
            scratchCap = std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--dump" && i + 1 < argc) dumpPath = argv[++i];
        else if (a == "--help" || a == "-h") { usage(argv[0]); return 0; }
        else { std::fprintf(stderr, "Unknown argument: %s\n", a.c_str()); usage(argv[0]); return 2; }
    }
    if (modelPath.empty()) { usage(argv[0]); return 2; }

    Deep2::GGUFLoader loader;
    if (!loader.load(modelPath)) {
        std::fprintf(stderr, "TILE_PROBE_FAIL load model: %s\n", modelPath.c_str());
        return 3;
    }

    if (listMode) {
        for (const auto& n : loader.listTensors())
            if (listSubstr.empty() || n.find(listSubstr) != std::string::npos)
                std::printf("%s\n", n.c_str());
        return 0;
    }

    // ---- --info ----
    if (!infoName.empty()) {
        const Deep2::GGUFTensor* t = loader.getTensor(infoName);
        if (!t) { std::fprintf(stderr, "TILE_PROBE_FAIL tensor not found: %s\n", infoName.c_str()); return 3; }
        std::printf("TILE_INFO name=%s type=%d sizeBytes=%zu shard=%u fileOffset=%llu ndims=%zu shape=",
                    t->name.c_str(), static_cast<int>(t->type), t->sizeBytes, t->shardId,
                    (unsigned long long)t->fileOffset, t->shape.size());
        for (size_t i = 0; i < t->shape.size(); ++i)
            std::printf("%s%lld", i ? "," : "", (long long)t->shape[i]);
        std::printf("\n");
        if (t->shape.size() == 3 && t->shape[0] > 0) {
            const uint64_t n0 = static_cast<uint64_t>(t->shape[0]);
            const uint64_t n1 = static_cast<uint64_t>(t->shape[1]);
            const uint64_t n2 = static_cast<uint64_t>(t->shape[2]);
            if (n0 % QK4_0 == 0) {
                const uint64_t bpr = n0 / QK4_0;
                std::printf("TILE_INFO_DERIVED blocksPerRow=%llu blocksPerExpert=%llu "
                            "totalBlocks=%llu expectBytes=%llu\n",
                            (unsigned long long)bpr, (unsigned long long)(n1 * bpr),
                            (unsigned long long)(n2 * n1 * bpr),
                            (unsigned long long)(n2 * n1 * bpr * BK4_0));
            } else {
                std::printf("TILE_INFO_DERIVED unsupported: n0=%llu not block aligned\n",
                            (unsigned long long)n0);
            }
        }
        return 0;
    }

    if (tensorName.empty()) { usage(argv[0]); return 2; }
    const Deep2::GGUFTensor* t = loader.getTensor(tensorName);
    if (!t || !t->data) {
        std::fprintf(stderr, "TILE_PROBE_FAIL tensor not found: %s\n", tensorName.c_str());
        return 3;
    }
    const int typeId = static_cast<int>(t->type);
    if (typeId != 2) {
        std::fprintf(stderr, "TILE_PROBE_FAIL tensor=%s type=%d (probe supports Q4_0=2 only)\n",
                     tensorName.c_str(), typeId);
        return 4;
    }
    if (tileBlocks <= 0) tileBlocks = 64;

    // ---- Determine the slice to test ----
    Slice s{};
    const bool sliceMode = (expert >= 0 || !rowsSpec.empty());
    if (sliceMode) {
        if (t->shape.size() != 3) {
            std::fprintf(stderr, "TILE_PROBE_FAIL unsupported layout: %s has %zu dims, expected 3\n",
                         tensorName.c_str(), t->shape.size());
            return 4;
        }
        if (t->shape[0] <= 0 || t->shape[1] <= 0 || t->shape[2] <= 0) {
            std::fprintf(stderr, "TILE_PROBE_FAIL malformed dims\n");
            return 4;
        }
        const uint64_t n0 = static_cast<uint64_t>(t->shape[0]);
        const uint64_t n1 = static_cast<uint64_t>(t->shape[1]);
        const uint64_t n2 = static_cast<uint64_t>(t->shape[2]);
        if (n0 % QK4_0 != 0) {
            std::fprintf(stderr, "TILE_PROBE_FAIL quantized axis n0=%llu not block aligned\n",
                         (unsigned long long)n0);
            return 4;
        }
        const uint64_t bpr = n0 / QK4_0;
        if (mulOverflows(n1, bpr) || mulOverflows(n2, n1 * bpr)) {
            std::fprintf(stderr, "TILE_PROBE_FAIL block-count overflow\n");
            return 4;
        }
        const uint64_t bpe = n1 * bpr;
        const uint64_t totalBlocks = n2 * bpe;
        if (mulOverflows(totalBlocks, BK4_0) || totalBlocks * BK4_0 != t->sizeBytes) {
            std::fprintf(stderr, "TILE_PROBE_FAIL sizeBytes=%zu != derived=%llu\n",
                         t->sizeBytes, (unsigned long long)(totalBlocks * BK4_0));
            return 4;
        }
        if (expert < 0) expert = 0;
        if (static_cast<uint64_t>(expert) >= n2) {
            std::fprintf(stderr, "TILE_PROBE_FAIL expert=%lld out of range (n2=%llu)\n",
                         (long long)expert, (unsigned long long)n2);
            return 4;
        }
        uint64_t r0 = 0, r1 = n1;
        if (!rowsSpec.empty()) {
            const size_t c = rowsSpec.find(':');
            if (c == std::string::npos) {
                std::fprintf(stderr, "TILE_PROBE_FAIL --rows expects R0:R1\n");
                return 2;
            }
            r0 = std::strtoull(rowsSpec.substr(0, c).c_str(), nullptr, 10);
            r1 = std::strtoull(rowsSpec.substr(c + 1).c_str(), nullptr, 10);
        }
        if (r1 <= r0 || r1 > n1) {
            std::fprintf(stderr, "TILE_PROBE_FAIL rows=%llu:%llu out of range (n1=%llu)\n",
                         (unsigned long long)r0, (unsigned long long)r1, (unsigned long long)n1);
            return 4;
        }
        s.startBlock   = static_cast<uint64_t>(expert) * bpe + r0 * bpr;
        s.blockCount   = (r1 - r0) * bpr;
        s.elementCount = s.blockCount * QK4_0;
        if (mulOverflows(s.startBlock, BK4_0) || mulOverflows(s.blockCount, BK4_0)) {
            std::fprintf(stderr, "TILE_PROBE_FAIL byte-offset overflow\n");
            return 4;
        }
        s.startByte  = t->fileOffset + s.startBlock * BK4_0;
        s.byteCount  = s.blockCount * BK4_0;
        const uint64_t tensorEnd = t->fileOffset + t->sizeBytes;
        if (s.startByte < t->fileOffset || s.byteCount > tensorEnd ||
            s.startByte > tensorEnd - s.byteCount) {
            std::fprintf(stderr, "TILE_PROBE_FAIL slice outside tensor byte range\n");
            return 4;
        }
    } else {
        const uint64_t elements = static_cast<uint64_t>(t->numElements());
        if (elements == 0 || (elements % QK4_0) != 0) {
            std::fprintf(stderr, "TILE_PROBE_FAIL elements=%llu not a multiple of %d\n",
                         (unsigned long long)elements, QK4_0);
            return 4;
        }
        s.startBlock   = 0;
        s.blockCount   = elements / QK4_0;
        s.elementCount = elements;
        s.startByte    = t->fileOffset;
        s.byteCount    = s.blockCount * BK4_0;
        if (s.byteCount != t->sizeBytes) {
            std::fprintf(stderr, "TILE_PROBE_FAIL sizeBytes=%zu expected=%llu\n",
                         t->sizeBytes, (unsigned long long)s.byteCount);
            return 4;
        }
    }

    std::printf("TILE_PROBE tensor=%s type=Q4_0 mode=%s startBlock=%llu blocks=%llu "
                "elements=%llu bytes=%llu startByte=%llu tileBlocks=%d\n",
                tensorName.c_str(), sliceMode ? "expert-slice" : "flat",
                (unsigned long long)s.startBlock, (unsigned long long)s.blockCount,
                (unsigned long long)s.elementCount, (unsigned long long)s.byteCount,
                (unsigned long long)s.startByte, tileBlocks);

    // ---- Reference: the same slice from the mapped tensor ----
    const ggml_type_traits* tr = ggml_get_type_traits(static_cast<ggml_type>(typeId));
    if (!tr || !tr->to_float) {
        std::fprintf(stderr, "TILE_PROBE_FAIL no ggml type traits for Q4_0\n");
        return 4;
    }
    std::vector<float> ref(static_cast<size_t>(s.elementCount));
    tr->to_float(t->data + s.startBlock * BK4_0, ref.data(),
                 static_cast<int64_t>(s.elementCount));
    const uint64_t refHash = fnv1a(ref.data(), ref.size() * sizeof(float));

    // ---- Streamed: block-aligned file reads into bounded scratch ----
    const uint64_t rawTileBytes = static_cast<uint64_t>(tileBlocks) * BK4_0;
    const uint64_t f32TileBytes = static_cast<uint64_t>(tileBlocks) * QK4_0 * sizeof(float);
    const uint64_t scratchNeed  = rawTileBytes + f32TileBytes;
    if (scratchCap && scratchNeed > scratchCap) {
        std::fprintf(stderr, "TILE_PROBE_FAIL scratch limit: need=%llu cap=%llu\n",
                     (unsigned long long)scratchNeed, (unsigned long long)scratchCap);
        return 5;
    }

    FILE* f = std::fopen(modelPath.c_str(), "rb");
    if (!f) { std::fprintf(stderr, "TILE_PROBE_FAIL reopen model\n"); return 3; }

    std::vector<unsigned char> raw(static_cast<size_t>(rawTileBytes));
    std::vector<float> out(ref.size());

    uint64_t tiles = 0, bytesStreamed = 0, reconFailures = 0;
    for (uint64_t b0 = 0; b0 < s.blockCount; b0 += static_cast<uint64_t>(tileBlocks)) {
        const uint64_t nb = std::min<uint64_t>(static_cast<uint64_t>(tileBlocks),
                                               s.blockCount - b0);
        const uint64_t inBytes = nb * BK4_0;
        const uint64_t offset = s.startByte + b0 * BK4_0;

        if (_fseeki64(f, static_cast<__int64>(offset), SEEK_SET) != 0) {
            std::fprintf(stderr, "TILE_PROBE_FAIL seek offset=%llu\n", (unsigned long long)offset);
            std::fclose(f); return 6;
        }
        if (std::fread(raw.data(), 1, static_cast<size_t>(inBytes), f) != inBytes) {
            std::fprintf(stderr, "TILE_PROBE_FAIL read %llu bytes at %llu\n",
                         (unsigned long long)inBytes, (unsigned long long)offset);
            std::fclose(f); return 6;
        }
        tr->to_float(raw.data(), out.data() + b0 * QK4_0, static_cast<int64_t>(nb * QK4_0));

        const size_t cmpBytes = static_cast<size_t>(nb * QK4_0 * sizeof(float));
        if (std::memcmp(out.data() + b0 * QK4_0, ref.data() + b0 * QK4_0, cmpBytes) != 0)
            ++reconFailures;

        bytesStreamed += inBytes;
        ++tiles;
    }
    std::fclose(f);

    const uint64_t outHash = fnv1a(out.data(), out.size() * sizeof(float));
    const int memEqual = (std::memcmp(out.data(), ref.data(), ref.size() * sizeof(float)) == 0) ? 1 : 0;

    double dotRef = 0.0, dotOut = 0.0;
    for (uint64_t i = 0; i < s.elementCount; ++i) {
        const double x = (static_cast<double>(i % 1024) * 0.0009765625) - 0.5;
        dotRef += static_cast<double>(ref[i]) * x;
        dotOut += static_cast<double>(out[i]) * x;
    }

    if (!dumpPath.empty()) {
        FILE* d = std::fopen(dumpPath.c_str(), "wb");
        if (d) { std::fwrite(out.data(), sizeof(float), out.size(), d); std::fclose(d); }
    }

    std::printf("TILE_PROBE_RESULT tiles=%llu bytes_streamed=%llu scratch_high_water=%llu "
                "reference_buffer_bytes=%llu recon_failures=%llu\n",
                (unsigned long long)tiles, (unsigned long long)bytesStreamed,
                (unsigned long long)scratchNeed,
                (unsigned long long)(ref.size() * sizeof(float)),
                (unsigned long long)reconFailures);
    std::printf("TILE_PROBE_COMPARE memcmp_equal=%d ref_fnv=0x%016llX out_fnv=0x%016llX "
                "dot_ref=%.17g dot_out=%.17g dot_equal=%d\n",
                memEqual, (unsigned long long)refHash, (unsigned long long)outHash,
                dotRef, dotOut, (dotRef == dotOut) ? 1 : 0);

    const bool pass = memEqual == 1 && reconFailures == 0 &&
                      refHash == outHash && dotRef == dotOut;
    std::printf("TILE_PROBE_VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 7;
}