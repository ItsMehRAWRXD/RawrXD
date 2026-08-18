// ============================================================================
// Deep2Engine_RouterSmokeTest.cpp
// Standalone router injection regression for DeepSeek2/K2 MoE.
//
// Loads actual K2 GGUF tensors (metadata + selective tensor data),
// resolves blk.N.ffn_gate_inp.weight per MoE layer, injects into
// per-layer MoERouter, and validates:
//   1. Tensor exists and is FP32 (FAIL on quantized/missing)
//   2. Router weights are nonzero
//   3. Routing is deterministic (same input → same experts)
//   4. Adjacent layers have distinct router weights (checksum)
//
// This is the highest-value validation step before wiring generation.
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <math>
#include <vector>
#include <string>
#include "GGUFLoader.hpp"
#include "MoERouter.hpp"

using namespace Deep2;

static bool g_verbose = true;

// ---------------------------------------------------------------------------
// Simple checksum: sum of absolute values (sufficient to detect identical
// vs distinct weight tensors, and detect all-zero tensors)
// ---------------------------------------------------------------------------
static double ComputeChecksum(const float* data, size_t n) {
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) {
        sum += std::fabs(data[i]);
    }
    return sum;
}

static bool IsAllZero(const float* data, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (data[i] != 0.0f) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Resolve a tensor by exact name from the GGUF load result.
// Returns nullptr if not found.
// ---------------------------------------------------------------------------
static const TensorInfo* ResolveTensor(const GGUFLoadResult& result, const std::string& name) {
    for (const auto& t : result.tensors) {
        if (t.name == name) return &t;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Build a deterministic test hidden-state vector.
// Using a fixed seed pattern so repeated runs are comparable.
// ---------------------------------------------------------------------------
static std::vector<float> BuildTestHiddenState(size_t hiddenDim) {
    std::vector<float> vec(hiddenDim);
    for (size_t i = 0; i < hiddenDim; ++i) {
        // Simple deterministic pattern: sine wave + small offset
        vec[i] = std::sinf((float)i * 0.1f) + 0.01f * (float)(i % 7);
    }
    return vec;
}

// ---------------------------------------------------------------------------
// Run the router smoke test.
// ---------------------------------------------------------------------------
static bool RunRouterSmokeTest(const char* ggufPath) {
    printf("\n========================================\n");
    printf("K2 Router Injection Smoke Test\n");
    printf("File: %s\n", ggufPath);
    printf("========================================\n\n");

    // Load metadata + tensor info (no tensor data needed for index)
    GGUFLoadOptions opts;
    opts.loadTensors = true;   // We need the actual router weight bytes
    opts.verbose     = false;

    GGUFLoadResult result = GGUFLoader::Load(ggufPath, opts);
    if (!result.success) {
        printf("FAIL: Could not load GGUF: %s\n", result.error);
        return false;
    }

    const ModelMetadata& meta = result.metadata;

    // Sanity: must be DeepSeek2 with MoE
    if (meta.architecture != "deepseek2") {
        printf("FAIL: Expected architecture 'deepseek2', got '%s'\n", meta.architecture.c_str());
        return false;
    }
    if (meta.numExperts == 0) {
        printf("FAIL: Model has zero experts (not MoE)\n");
        return false;
    }
    if (meta.leadingDenseBlockCount == 0) {
        printf("FAIL: leadingDenseBlockCount is zero (expected >= 1)\n");
        return false;
    }

    size_t firstMoELayer = meta.leadingDenseBlockCount;
    size_t numLayers     = meta.numLayers;
    size_t hiddenDim     = meta.hiddenSize;
    size_t numExperts    = meta.numExperts;

    printf("Model: %s\n", meta.architecture.c_str());
    printf("Layers: %zu, Hidden: %zu, Experts: %zu\n", numLayers, hiddenDim, numExperts);
    printf("Dense layers: 0..%zu, MoE layers: %zu..%zu\n\n",
           firstMoELayer - 1, firstMoELayer, numLayers - 1);

    // Build test hidden state once
    std::vector<float> testHidden = BuildTestHiddenState(hiddenDim);

    // Track checksums per layer for distinctness check
    std::vector<double> layerChecksums;
    std::vector<std::string> layerTensorNames;

    bool allPassed = true;

    // -----------------------------------------------------------------------
    // Test every MoE layer
    // -----------------------------------------------------------------------
    for (size_t layerIdx = firstMoELayer; layerIdx < numLayers; ++layerIdx) {
        char tensorName[256];
        snprintf(tensorName, sizeof(tensorName), "blk.%zu.ffn_gate_inp.weight", layerIdx);

        const TensorInfo* t = ResolveTensor(result, tensorName);
        if (!t) {
            printf("[L%zu] FAIL: tensor '%s' not found in GGUF\n", layerIdx, tensorName);
            allPassed = false;
            continue;
        }

        // --- Type check: must be FP32 for router weights ---
        if (t->type != GGMLType::GGML_TYPE_F32) {
            printf("[L%zu] FAIL: '%s' type=%d (expected F32=%d). "
                   "Quantized router weights require dequantization.\n",
                   layerIdx, tensorName, (int)t->type, (int)GGMLType::GGML_TYPE_F32);
            allPassed = false;
            continue;
        }

        // --- Dimension check: [numExperts, hiddenDim] ---
        if (t->dimensions.size() != 2) {
            printf("[L%zu] FAIL: '%s' has %zu dims (expected 2)\n",
                   layerIdx, tensorName, t->dimensions.size());
            allPassed = false;
            continue;
        }
        size_t rows = t->dimensions[0];
        size_t cols = t->dimensions[1];
        if (rows != numExperts || cols != hiddenDim) {
            printf("[L%zu] FAIL: '%s' shape [%zu, %zu] (expected [%zu, %zu])\n",
                   layerIdx, tensorName, rows, cols, numExperts, hiddenDim);
            allPassed = false;
            continue;
        }

        // --- Data presence check ---
        if (!t->data) {
            printf("[L%zu] FAIL: '%s' has no data pointer\n", layerIdx, tensorName);
            allPassed = false;
            continue;
        }

        const float* weights = (const float*)t->data;
        size_t numElements = rows * cols;

        // --- Nonzero check ---
        if (IsAllZero(weights, numElements)) {
            printf("[L%zu] FAIL: '%s' contains all zeros\n", layerIdx, tensorName);
            allPassed = false;
            continue;
        }

        double checksum = ComputeChecksum(weights, numElements);
        layerChecksums.push_back(checksum);
        layerTensorNames.push_back(tensorName);

        if (g_verbose) {
            printf("[L%zu] tensor='%s' type=F32 shape=[%zu,%zu] nonzero=YES checksum=%.6f\n",
                   layerIdx, tensorName, rows, cols, checksum);
        }

        // --- Inject into router and test determinism ---
        MoEConfig moeConfig;
        moeConfig.numExperts       = numExperts;
        moeConfig.numActiveExperts = meta.numExpertsPerToken > 0 ? meta.numExpertsPerToken : 8;
        moeConfig.hiddenDim        = hiddenDim;
        moeConfig.expertDim        = meta.moeIntermediateSize > 0 ? meta.moeIntermediateSize : 2048;
        moeConfig.useSharedExpert  = meta.numSharedExperts > 0;

        MoERouter router;
        router.Initialize(moeConfig);
        router.SetRouterWeights(weights, rows, cols);

        // Run twice with identical input
        TokenRoute route1 = router.Route(testHidden.data());
        TokenRoute route2 = router.Route(testHidden.data());

        // --- Determinism check ---
        bool deterministic = true;
        if (route1.topExperts.size() != route2.topExperts.size()) {
            deterministic = false;
        } else {
            for (size_t k = 0; k < route1.topExperts.size(); ++k) {
                if (route1.topExperts[k].expertId != route2.topExperts[k].expertId) {
                    deterministic = false;
                    break;
                }
            }
        }

        if (!deterministic) {
            printf("[L%zu] FAIL: routing is NON-DETERMINISTIC\n", layerIdx);
            allPassed = false;
            continue;
        }

        if (g_verbose) {
            printf("[L%zu] deterministic: PASS  top-k=[", layerIdx);
            for (size_t k = 0; k < route1.topExperts.size(); ++k) {
                if (k > 0) printf(", ");
                printf("%d", route1.topExperts[k].expertId);
            }
            printf("]\n");
        }
    }

    // -----------------------------------------------------------------------
    // Distinctness check: adjacent layers must have different checksums
    // -----------------------------------------------------------------------
    if (layerChecksums.size() >= 2) {
        bool distinct = true;
        for (size_t i = 1; i < layerChecksums.size(); ++i) {
            if (layerChecksums[i] == layerChecksums[i - 1]) {
                printf("\n[DISTINCT] FAIL: layer %zu and layer %zu have IDENTICAL checksums (%.6f)\n",
                       firstMoELayer + i - 1, firstMoELayer + i, layerChecksums[i]);
                distinct = false;
                allPassed = false;
            }
        }
        if (distinct && g_verbose) {
            printf("\n[DISTINCT] PASS: all %zu MoE layer routers have distinct weights\n",
                   layerChecksums.size());
        }
    } else {
        printf("\n[DISTINCT] SKIP: only %zu MoE layer(s) resolved (need >=2 for distinctness)\n",
               layerChecksums.size());
    }

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------
    printf("\n========================================\n");
    if (allPassed) {
        printf("ALL ROUTER ASSERTIONS PASSED\n");
    } else {
        printf("SOME ROUTER ASSERTIONS FAILED\n");
    }
    printf("========================================\n\n");

    return allPassed;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    const char* ggufPath = nullptr;

    if (argc > 1) {
        ggufPath = argv[1];
    } else {
        // Try common K2 model locations
        const char* candidates[] = {
            "F:\\OllamaModels\\qwen25coder14b-local\\qwen2.5-coder-14b-instruct-q4_k_m.gguf",
            "F:\\OllamaModels\\qwen3.5-q4k-m-local\\qwen3.5-14b-instruct-q4_k_m.gguf",
            nullptr
        };
        for (int i = 0; candidates[i]; ++i) {
            FILE* fp = fopen(candidates[i], "rb");
            if (fp) {
                fclose(fp);
                ggufPath = candidates[i];
                break;
            }
        }
    }

    if (!ggufPath) {
        printf("Usage: %s <path-to-k2.gguf>\n", argv[0]);
        printf("Or place a K2 GGUF at a known location.\n");
        return 1;
    }

    bool ok = RunRouterSmokeTest(ggufPath);
    return ok ? 0 : 1;
}
