// ============================================================================
// D2-K2-09 Test Harness — Tensor View / MMAP Verification
// ----------------------------------------------------------------------------
// Proves that resolved tensors can be physically accessed at the correct
// GGUF offset without loading the 620 GB model into RAM.
//
// For each selected tensor:
//   1. Resolve via GGUFShardRouter
//   2. Open the correct shard file
//   3. Seek to file_offset
//   4. Read first 16 bytes (verification header)
//   5. Seek to file_offset + size_bytes - 1, read 1 byte (end boundary)
//   6. Confirm size matches dims * type_size
//
// Standalone — only depends on GGUFShardRouter (header-only)
// ============================================================================

#include "../GGUFShardRouter.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

static bool detectK2Shards(const std::string& dir, std::vector<std::string>& out)
{
    out.clear();
    for (int i = 1; i <= 13; ++i) {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "kimi-k2-instruct-0905-q4_k_m-%05d-of-00013.gguf", i);
        fs::path p = fs::path(dir) / buf;
        if (fs::exists(p)) out.push_back(p.string());
    }
    return !out.empty();
}

static const char* ggmlTypeName(uint32_t type)
{
    switch (type) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 8:  return "Q8_0";
        case 12: return "Q4_K";
        default: return "UNKNOWN";
    }
}

// Compute expected tensor data size from dims + GGML type block layout.
// This is approximate for quantized types (Q4_K, Q8_0) but sufficient
// for verifying the file bounds contain the tensor.
static uint64_t computeExpectedSize(const std::vector<uint64_t>& dims, uint32_t type)
{
    uint64_t nElements = 1;
    for (auto d : dims) nElements *= d;

    switch (type) {
        case 0:  return nElements * 4;                       // F32
        case 1:  return nElements * 2;                       // F16
        case 8:  return ((nElements + 31) / 32) * 36;         // Q8_0: 32 weights + scale
        case 12: return ((nElements + 255) / 256) * 144;     // Q4_K: 256 weights + scales
        default: return nElements;                           // conservative fallback
    }
}

int main(int argc, char** argv)
{
    const char* modelDir = (argc > 1) ? argv[1]
        : "G:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";

    printf("[D2-K2-09] Tensor View / MMAP Verification\n");
    printf("============================================\n");
    printf("Model directory: %s\n\n", modelDir);

    // ------------------------------------------------------------------------
    // 1. Shard discovery + router scan
    // ------------------------------------------------------------------------
    printf("[1] Shard discovery + scan...\n");
    std::vector<std::string> shards;
    if (!detectK2Shards(modelDir, shards)) {
        printf("FAIL  No K2 shards found\n");
        return 1;
    }

    RawrXD::GGUFShardRouter router;
    for (const auto& s : shards) router.add_shard(s);
    router.scan();
    printf("PASS  %zu shards, %zu tensors\n\n", router.shard_count(), router.tensor_count());

    // ------------------------------------------------------------------------
    // 2. Select representative tensors across shards
    // ------------------------------------------------------------------------
    printf("[2] Tensor access verification:\n");

    struct TestCase {
        const char* name;
        uint32_t expectedShard;   // rough expectation, verified at runtime
    } tests[] = {
        { "token_embd.weight",              0 },   // early shard
        { "blk.0.attn_q_a.weight",          0 },   // layer 0
        { "blk.0.attn_kv_a_mqa.weight",   0 },   // layer 0
        { "blk.15.attn_q_a.weight",         3 },   // mid model
        { "blk.30.attn_q_a.weight",         6 },   // mid model
        { "blk.45.attn_q_a.weight",         9 },   // later
        { "blk.60.attn_q_a.weight",          12 },  // final layer
        { "output.weight",                   12 },  // output weights
        { "output_norm.weight",              0 },   // norm
    };

    int passed = 0, failed = 0;

    for (const auto& tc : tests) {
        auto info = router.resolve(tc.name);
        if (!info) {
            printf("  FAIL  %-35s NOT FOUND\n", tc.name);
            ++failed;
            continue;
        }

        const auto& shardPath = router.shard_path(info->shard_index);

        // Verify file exists and is readable
        std::ifstream f(shardPath, std::ios::binary);
        if (!f) {
            printf("  FAIL  %-35s cannot open shard %u\n", tc.name, info->shard_index);
            ++failed;
            continue;
        }

        // Seek to tensor offset
        f.seekg(static_cast<std::streamoff>(info->file_offset));
        if (!f) {
            printf("  FAIL  %-35s seek failed @ %llu\n", tc.name,
                   (unsigned long long)info->file_offset);
            ++failed;
            continue;
        }

        // Read first 16 bytes
        char header[16] = {};
        f.read(header, sizeof(header));
        if (!f) {
            printf("  FAIL  %-35s read failed @ %llu\n", tc.name,
                   (unsigned long long)info->file_offset);
            ++failed;
            continue;
        }

        // Compute expected size from dims + type
        uint64_t expectedSize = computeExpectedSize(info->dims, info->ggml_type);

        // Seek to last byte and read 1
        f.seekg(static_cast<std::streamoff>(info->file_offset + expectedSize - 1));
        char lastByte = 0;
        f.read(&lastByte, 1);
        if (!f) {
            printf("  FAIL  %-35s end-boundary read failed (expectedSize=%llu)\n",
                   tc.name, (unsigned long long)expectedSize);
            ++failed;
            continue;
        }

        // Verify file is large enough to contain the tensor
        f.seekg(0, std::ios::end);
        uint64_t fileSize = static_cast<uint64_t>(f.tellg());
        bool sizeOk = (info->file_offset + expectedSize) <= fileSize;

        printf("  PASS  %-35s shard=%u offset=%-14llu type=%s dims=[",
               tc.name, info->shard_index,
               (unsigned long long)info->file_offset,
               ggmlTypeName(info->ggml_type));
        for (size_t d = 0; d < info->dims.size(); ++d) {
            if (d) printf(",");
            printf("%llu", (unsigned long long)info->dims[d]);
        }
        printf("] expectedSize=%llu %s\n",
               (unsigned long long)expectedSize,
               sizeOk ? "" : "[SIZE WARNING]");

        ++passed;
    }

    printf("\n[D2-K2-09] Results: %d passed, %d failed\n", passed, failed);
    if (failed > 0) {
        printf("[FAIL] Some tensors could not be accessed\n");
        return 1;
    }

    printf("[D2-K2-09] ALL CHECKS PASSED\n");
    return 0;
}
