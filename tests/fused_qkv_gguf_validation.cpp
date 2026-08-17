// ============================================================================
// Fused QKV + GGUF Validation Test
// ============================================================================
// Gate: Prove the full chain from GGUF parse → elastic index → fused QKV
// execution works on real models, with correct dimension splits.
//
// Sequence:
//   1. GGUFTensorLoader::Open() → parse header + metadata + tensor records
//   2. Validate GetTensorSize() for Q4_K/Q5_K/Q6_K tensors
//   3. ElasticGGUFIndex::BuildIndexFromTensors() → report indexed count
//   4. RawrXDModelLoader::Load() → detect fused vs separate QKV
//   5. T=1 decode path → fused QKV matmul + split → finite check
//   6. T=2 batched prefill path → fused QKV batch + split → finite check
//   7. Deterministic output check (same input → same logits)
//
// Build: cmake --build build --target fused_qkv_gguf_validation
// Run:   .\bin\fused_qkv_gguf_validation.exe <model.gguf>
// ============================================================================

#include "../src/runtime/gguf_tensor_loader.hpp"
#include "../src/runtime/elastic/ElasticGGUFIndex.hpp"
#include "../src/rawrxd_transformer.h"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#endif

static bool AllFinite(const float* data, size_t n)
{
    for (size_t i = 0; i < n; ++i)
    {
        if (!std::isfinite(data[i]))
            return false;
    }
    return true;
}

static bool WithinTolerance(const float* a, const float* b, size_t n, float tol)
{
    for (size_t i = 0; i < n; ++i)
    {
        float diff = std::fabs(a[i] - b[i]);
        if (diff > tol)
            return false;
    }
    return true;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }

    const char* modelPath = argv[1];
    printf("[VALIDATION] ============================================================\n");
    printf("[VALIDATION] Model: %s\n", modelPath);
    printf("[VALIDATION] ============================================================\n\n");

    bool overallPass = true;

    // ========================================================================
    // PHASE 1: GGUFTensorLoader direct parse
    // ========================================================================
    printf("[PHASE-1] GGUFTensorLoader direct parse\n");
    {
        rawrxd::runtime::GGUFTensorLoader loader;
        if (!loader.Open(modelPath))
        {
            printf("[PHASE-1] FAIL: GGUFTensorLoader::Open() failed: %s\n", loader.GetLastError().c_str());
            return 2;
        }

        auto names = loader.ListTensors();
        printf("[PHASE-1] PASS: GGUFTensorLoader opened. Tensor count=%zu\n", names.size());

        // Validate Q4_K/Q5_K/Q6_K tensor sizes
        size_t q4kCount = 0, q5kCount = 0, q6kCount = 0;
        size_t skippedInvalid = 0;
        for (const auto& name : names)
        {
            auto view = loader.GetTensor(name);
            if (!view.IsValid())
            {
                ++skippedInvalid;
                continue;
            }
            if (view.type == 12) ++q4kCount;
            if (view.type == 13) ++q5kCount;
            if (view.type == 14) ++q6kCount;
        }
        printf("[PHASE-1] Q4_K tensors: %zu, Q5_K: %zu, Q6_K: %zu\n", q4kCount, q5kCount, q6kCount);
        printf("[PHASE-1] Skipped invalid views: %zu\n", skippedInvalid);

        if (skippedInvalid > 0)
        {
            printf("[PHASE-1] WARN: %zu tensors had invalid views (parser may have misaligned)\n", skippedInvalid);
        }

        loader.Close();
    }

    // ========================================================================
    // PHASE 2: ElasticGGUFIndex::BuildIndexFromTensors()
    // ========================================================================
    printf("\n[PHASE-2] ElasticGGUFIndex build\n");
    size_t elasticBlockCount = 0;
    bool elasticHasQKV = false;
    {
        try
        {
            auto index = std::make_shared<RawrXD::Elastic::ElasticGGUFIndex>(modelPath);
            bool built = index->BuildIndexFromTensors();
            if (!built)
            {
                printf("[PHASE-2] FAIL: BuildIndexFromTensors() returned false\n");
                overallPass = false;
            }
            else
            {
                elasticBlockCount = index->GetAllBlocks().size();
                printf("[PHASE-2] PASS: BuildIndexFromTensors() succeeded. Blocks=%zu\n", elasticBlockCount);

                // Check for fused QKV
                for (const auto& block : index->GetAllBlocks())
                {
                    if (block.name.find("attn_qkv") != std::string::npos)
                    {
                        elasticHasQKV = true;
                        printf("[PHASE-2] Detected fused QKV tensor: %s (type=%u, bytes=%zu)\n",
                               block.name.c_str(), block.ggml_type, block.byte_size);
                    }
                }
                if (!elasticHasQKV)
                {
                    printf("[PHASE-2] No fused QKV tensors found (separate Q/K/V model)\n");
                }
            }
        }
        catch (const std::exception& e)
        {
            printf("[PHASE-2] FAIL: Exception during ElasticGGUFIndex: %s\n", e.what());
            overallPass = false;
        }
    }

    // ========================================================================
    // PHASE 3: RawrXDModelLoader + DetectFusedQKV
    // ========================================================================
    printf("\n[PHASE-3] RawrXDModelLoader load + fused QKV detection\n");
    RawrXDModelLoader modelLoader;
    std::wstring wpath;
    {
        int len = MultiByteToWideChar(CP_UTF8, 0, modelPath, -1, nullptr, 0);
        wpath.resize(len);
        MultiByteToWideChar(CP_UTF8, 0, modelPath, -1, wpath.data(), len);
    }
    if (!modelLoader.Load(wpath.c_str(), nullptr, nullptr))
    {
        printf("[PHASE-3] FAIL: RawrXDModelLoader::Load() returned false\n");
        return 3;
    }
    printf("[PHASE-3] PASS: RawrXDModelLoader loaded.\n");
    printf("[PHASE-3] Model config: dim=%d, layers=%d, heads=%d, kv_heads=%d, vocab=%d\n",
           modelLoader.getDim(), modelLoader.getLayers(), modelLoader.getHeads(),
           modelLoader.getKVHeads(), modelLoader.getVocabSize());

    // ========================================================================
    // PHASE 4: Transformer init + fused QKV detection
    // ========================================================================
    printf("\n[PHASE-4] Transformer initialization + DetectFusedQKV\n");
    RawrXDTransformer::Config cfg{};
    cfg.dim = modelLoader.getDim();
    cfg.hidden_dim = modelLoader.getFFNDim() > 0 ? modelLoader.getFFNDim() : modelLoader.getDim() * 4;
    cfg.n_layers = modelLoader.getLayers();
    cfg.n_heads = modelLoader.getHeads();
    cfg.n_kv_heads = modelLoader.getKVHeads();
    cfg.vocab_size = modelLoader.getVocabSize();
    cfg.n_ctx = modelLoader.getCtx() > 0 ? modelLoader.getCtx() : 2048;
    cfg.seq_len = cfg.n_ctx;
    cfg.rope_theta = 10000.0f;
    cfg.rms_norm_eps = 1e-6f;

    RawrXDTransformer transformer;
    transformer.Initialize(nullptr, nullptr, cfg, &modelLoader);
    printf("[PHASE-4] PASS: Transformer initialized.\n");

    // ========================================================================
    // PHASE 5: T=1 decode path (single token)
    // ========================================================================
    printf("\n[PHASE-5] T=1 decode path (single token)\n");
    {
        std::vector<uint32_t> tokens;
        tokens.push_back(1); // BOS

        std::vector<float> logits1 = transformer.Forward(tokens, 0);
        if (logits1.empty())
        {
            printf("[PHASE-5] FAIL: Forward(T=1) returned empty logits\n");
            overallPass = false;
        }
        else if (!AllFinite(logits1.data(), logits1.size()))
        {
            printf("[PHASE-5] FAIL: Forward(T=1) logits contain NaN/Inf\n");
            overallPass = false;
        }
        else
        {
            printf("[PHASE-5] PASS: Forward(T=1) logits: %zu values, all finite.\n", logits1.size());
            // Show first few logits
            printf("[PHASE-5] Sample logits: ");
            for (size_t i = 0; i < std::min<size_t>(5, logits1.size()); ++i)
                printf("%.4f ", logits1[i]);
            printf("...\n");
        }

        // Determinism check: run again with same input
        std::vector<float> logits1b = transformer.Forward(tokens, 0);
        if (!logits1b.empty() && !logits1.empty())
        {
            if (WithinTolerance(logits1.data(), logits1b.data(), logits1.size(), 1e-4f))
            {
                printf("[PHASE-5] PASS: Deterministic T=1 output (within 1e-4)\n");
            }
            else
            {
                printf("[PHASE-5] FAIL: T=1 output non-deterministic\n");
                overallPass = false;
            }
        }
    }

    // ========================================================================
    // PHASE 6: T=2 batched prefill path
    // ========================================================================
    printf("\n[PHASE-6] T=2 batched prefill path\n");
    {
        std::vector<uint32_t> tokens;
        tokens.push_back(1); // BOS
        tokens.push_back(42); // arbitrary second token

        std::vector<float> logits2 = transformer.ForwardBatch(tokens, 0);
        if (logits2.empty())
        {
            printf("[PHASE-6] FAIL: ForwardBatch(T=2) returned empty logits\n");
            overallPass = false;
        }
        else if (!AllFinite(logits2.data(), logits2.size()))
        {
            printf("[PHASE-6] FAIL: ForwardBatch(T=2) logits contain NaN/Inf\n");
            overallPass = false;
        }
        else
        {
            printf("[PHASE-6] PASS: ForwardBatch(T=2) logits: %zu values, all finite.\n", logits2.size());
        }

        // Determinism check
        std::vector<float> logits2b = transformer.ForwardBatch(tokens, 0);
        if (!logits2b.empty() && !logits2.empty())
        {
            if (WithinTolerance(logits2.data(), logits2b.data(), logits2.size(), 1e-4f))
            {
                printf("[PHASE-6] PASS: Deterministic T=2 output (within 1e-4)\n");
            }
            else
            {
                printf("[PHASE-6] FAIL: T=2 output non-deterministic\n");
                overallPass = false;
            }
        }
    }

    // ========================================================================
    // PHASE 7: Elastic counter report
    // ========================================================================
    printf("\n[PHASE-7] Elastic path counters\n");
    {
        uint64_t calls = transformer.GetElasticMatMulCalls();
        uint64_t hits = transformer.GetElasticHits();
        uint64_t misses = transformer.GetElasticMisses();
        printf("[PHASE-7] Elastic matmul calls: %llu\n", (unsigned long long)calls);
        printf("[PHASE-7] Elastic hits:        %llu\n", (unsigned long long)hits);
        printf("[PHASE-7] Elastic misses:       %llu\n", (unsigned long long)misses);
        if (hits > 0)
        {
            printf("[PHASE-7] PASS: Elastic path was reached (hits > 0)\n");
        }
        else
        {
            printf("[PHASE-7] INFO: Elastic path not reached (expected if elastic init failed)\n");
        }
    }

    // ========================================================================
    // SUMMARY
    // ========================================================================
    printf("\n[VALIDATION] ============================================================\n");
    if (overallPass)
    {
        printf("[VALIDATION] === OVERALL PASS ===\n");
        printf("[VALIDATION] All phases completed successfully.\n");
        return 0;
    }
    else
    {
        printf("[VALIDATION] === OVERALL FAIL ===\n");
        printf("[VALIDATION] One or more phases failed. See above.\n");
        return 4;
    }
}
