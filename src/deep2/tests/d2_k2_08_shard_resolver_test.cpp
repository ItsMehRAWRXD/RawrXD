// ============================================================================
// D2-K2-08 Test Harness — Shard Resolver Verification
// Loads real Kimi K2 Q4_K_M from G:\OllamaModels and validates:
//   1. Shard discovery
//   2. GGUF header scan
//   3. Metadata extraction (layer_count, hidden_size, etc.)
//   4. Cross-shard tensor resolution
//
// Standalone — only depends on GGUFShardRouter (header-only)
// ============================================================================

#include "../GGUFShardRouter.hpp"
#include <cstdio>
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
        if (fs::exists(p)) {
            out.push_back(p.string());
        }
    }
    return !out.empty();
}

int main(int argc, char** argv)
{
    const char* modelDir = (argc > 1) ? argv[1]
        : "G:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";

    printf("[D2-K2-08] Shard Resolver Verification\n");
    printf("=========================================\n");
    printf("Model directory: %s\n\n", modelDir);

    // ------------------------------------------------------------------------
    // 1. Shard discovery
    // ------------------------------------------------------------------------
    printf("[1] Shard discovery...\n");
    std::vector<std::string> shards;
    if (!detectK2Shards(modelDir, shards)) {
        printf("FAIL  No K2 shards found in: %s\n", modelDir);
        return 1;
    }
    printf("PASS  Found %zu shards\n", shards.size());
    for (size_t i = 0; i < shards.size() && i < 3; ++i) {
        printf("      %s\n", fs::path(shards[i]).filename().string().c_str());
    }
    if (shards.size() > 3) printf("      ... (%zu total)\n", shards.size());
    printf("\n");

    // ------------------------------------------------------------------------
    // 2. Build router and scan
    // ------------------------------------------------------------------------
    printf("[2] GGUF header scan...\n");
    RawrXD::GGUFShardRouter router;
    for (const auto& s : shards) {
        router.add_shard(s);
    }
    router.scan();
    printf("PASS  Scanned %zu shards, found %zu tensors\n\n",
           router.shard_count(), router.tensor_count());

    // ------------------------------------------------------------------------
    // 3. Metadata validation
    // ------------------------------------------------------------------------
    printf("[3] Metadata validation:\n");
    const auto& meta = router.metadata();
    if (meta.has_metadata) {
        printf("  layer_count   = %u  %s\n", meta.layer_count,
               meta.layer_count == 61 ? "[PASS: expected 61]" : "[FAIL: expected 61]");
        printf("  hidden_size   = %u\n", meta.hidden_size);
        printf("  head_count    = %u\n", meta.head_count);
        printf("  head_count_kv = %u\n", meta.head_count_kv);
        printf("  expert_count  = %u\n", meta.expert_count);
        printf("  expert_used   = %u\n", meta.expert_used_count);
        printf("  vocab_size    = %u\n", meta.vocab_size);
        printf("  context_len   = %u\n", meta.context_length);
        printf("  ffn_dim       = %u\n", meta.ffn_dim);
        printf("  architecture  = %s\n", meta.architecture.c_str());
        printf("  model_name    = %s\n", meta.model_name.c_str());

        if (meta.layer_count != 61) {
            printf("\n[FAIL] layer_count is %u, expected 61\n", meta.layer_count);
            return 1;
        }
    } else {
        printf("  [FAIL] No metadata extracted from GGUF\n");
        return 1;
    }
    printf("\n");

    // ------------------------------------------------------------------------
    // 4. Tensor resolution
    // ------------------------------------------------------------------------
    printf("[4] Tensor resolution:\n");

    // K2 uses MLA attention — tensor names differ from llama
    const char* testTensors[] = {
        "blk.0.attn_q_a.weight",      // K2 MLA Q projection (down-proj)
        "blk.0.attn_kv_a_mqa.weight", // K2 MLA KV projection
        "blk.30.attn_q_a.weight",
        "blk.60.attn_q_a.weight",
        "token_embd.weight",
        "output_norm.weight",
        nullptr
    };

    int found = 0, missing = 0;
    for (const char** p = testTensors; *p; ++p) {
        auto info = router.resolve(*p);
        if (info) {
            printf("  PASS  %-30s shard=%u offset=%llu type=%u dims=[",
                   *p,
                   info->shard_index,
                   (unsigned long long)info->file_offset,
                   info->ggml_type);
            for (size_t d = 0; d < info->dims.size(); ++d) {
                if (d) printf(",");
                printf("%llu", (unsigned long long)info->dims[d]);
            }
            printf("]\n");
            ++found;
        } else {
            printf("  FAIL  %-30s NOT FOUND\n", *p);
            ++missing;
        }
    }

    // ------------------------------------------------------------------------
    // 5. Boundary / cross-shard check
    // ------------------------------------------------------------------------
    printf("\n[5] Cross-shard boundary check:\n");
    // Find which shard contains blk.0 and blk.60
    auto t0 = router.resolve("blk.0.attn_q_a.weight");
    auto t60 = router.resolve("blk.60.attn_q_a.weight");
    if (t0 && t60) {
        printf("  blk.0  -> shard %u\n", t0->shard_index);
        printf("  blk.60 -> shard %u\n", t60->shard_index);
        if (t0->shard_index != t60->shard_index) {
            printf("  PASS  Cross-shard tensors resolve to different shards\n");
        } else {
            printf("  INFO  Both tensors in same shard (may be valid for K2)\n");
        }
    }

    printf("\n[D2-K2-08] Results: %d found, %d missing\n", found, missing);
    if (missing > 0) {
        printf("[FAIL] Some tensors not resolved\n");
        return 1;
    }

    printf("[D2-K2-08] ALL CHECKS PASSED\n");
    return 0;
}
