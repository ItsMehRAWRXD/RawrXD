// ============================================================================
// Deep2Engine_RouterSmokeTest.cpp
// Standalone router injection regression for DeepSeek2/K2 MoE.
//
// Discovers multi-shard K2 GGUF layout, builds a global tensor index,
// resolves blk.N.ffn_gate_inp.weight per MoE layer across all shards,
// injects into per-layer MoERouter, and validates:
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
#include <cmath>
#include <vector>
#include <string>
#include <filesystem>
#include "GGUFLoader.hpp"
#include "MoERouter.hpp"

using namespace Deep2;

static bool g_verbose = true;

// ---------------------------------------------------------------------------
// Shard discovery: given a path like "...-00001-of-00013.gguf",
// find all sibling shards and return them sorted.
// ---------------------------------------------------------------------------
static std::vector<std::string> DiscoverShards(const std::string& firstShardPath) {
    std::vector<std::string> shards;
    std::filesystem::path p(firstShardPath);
    std::filesystem::path dir = p.parent_path();
    std::string stem = p.stem().string();

    // Extract the shard pattern: everything before "-00001-of-00013"
    size_t shardPos = stem.rfind("-000");
    if (shardPos == std::string::npos) {
        // Single-file model
        shards.push_back(firstShardPath);
        return shards;
    }

    std::string prefix = stem.substr(0, shardPos);
    std::string ext = p.extension().string();

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        std::string name = entry.path().filename().string();
        if (name.find(prefix) == 0 && name.find(".gguf") != std::string::npos) {
            shards.push_back(entry.path().string());
        }
    }

    std::sort(shards.begin(), shards.end());
    return shards;
}

// ---------------------------------------------------------------------------
// Global tensor index entry
// ---------------------------------------------------------------------------
struct TensorLocation {
    std::string name;
    std::string shardPath;
    uint64_t    fileOffset = 0;   // offset within shard's tensor data section
    uint64_t    byteSize   = 0;
    GGMLType    type       = GGMLType::GGML_TYPE_F32;
    std::vector<uint64_t> shape;
};

// ---------------------------------------------------------------------------
// Build global tensor index across all shards (metadata only, no tensor data)
// ---------------------------------------------------------------------------
static bool BuildGlobalTensorIndex(
    const std::vector<std::string>& shards,
    std::vector<TensorLocation>& outIndex,
    ModelMetadata& outMeta)
{
    outIndex.clear();
    bool metaLoaded = false;

    for (const auto& shardPath : shards) {
        GGUFLoadOptions opts;
        opts.loadTensors = false;  // metadata + tensor info only
        opts.verbose = false;

        GGUFLoadResult result = GGUFLoader::Load(shardPath.c_str(), opts);
        if (!result.success) {
            printf("WARN: Failed to load shard metadata: %s (%s)\n", shardPath.c_str(), result.error);
            continue;
        }

        if (!metaLoaded) {
            outMeta = result.metadata;
            metaLoaded = true;
        }

        for (const auto& t : result.tensors) {
            TensorLocation loc;
            loc.name       = t.name;
            loc.shardPath  = shardPath;
            loc.fileOffset = result.dataOffset + t.offset;
            loc.byteSize   = t.size;
            loc.type       = t.type;
            loc.shape      = t.dimensions;
            outIndex.push_back(std::move(loc));
        }
    }

    return metaLoaded && !outIndex.empty();
}

// ---------------------------------------------------------------------------
// Load a single tensor's bytes from its shard, given the global index entry.
// Returns an aligned buffer that the caller must free with free().
// ---------------------------------------------------------------------------
static void* LoadTensorBytes(const TensorLocation& loc, size_t& outSize) {
    FILE* fp = fopen(loc.shardPath.c_str(), "rb");
    if (!fp) {
        printf("ERROR: Cannot open shard: %s\n", loc.shardPath.c_str());
        return nullptr;
    }

    if (_fseeki64(fp, (long long)loc.fileOffset, SEEK_SET) != 0) {
        printf("ERROR: Cannot seek to offset %llu in %s\n",
               (unsigned long long)loc.fileOffset, loc.shardPath.c_str());
        fclose(fp);
        return nullptr;
    }

    void* buf = _aligned_malloc(loc.byteSize, 64);
    if (!buf) {
        printf("ERROR: Cannot allocate %llu bytes for tensor '%s'\n",
               (unsigned long long)loc.byteSize, loc.name.c_str());
        fclose(fp);
        return nullptr;
    }

    size_t read = fread(buf, 1, loc.byteSize, fp);
    fclose(fp);

    if (read != loc.byteSize) {
        printf("ERROR: Short read for '%s': expected %llu, got %zu\n",
               loc.name.c_str(), (unsigned long long)loc.byteSize, read);
        _aligned_free(buf);
        return nullptr;
    }

    outSize = loc.byteSize;
    return buf;
}

// ---------------------------------------------------------------------------
// Find a tensor in the global index by exact name.
// ---------------------------------------------------------------------------
static const TensorLocation* FindTensor(const std::vector<TensorLocation>& index,
                                          const std::string& name) {
    for (const auto& loc : index) {
        if (loc.name == name) return &loc;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Simple checksum: sum of absolute values
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
// Build a deterministic test hidden-state vector.
// ---------------------------------------------------------------------------
static std::vector<float> BuildTestHiddenState(size_t hiddenDim) {
    std::vector<float> vec(hiddenDim);
    for (size_t i = 0; i < hiddenDim; ++i) {
        vec[i] = std::sinf((float)i * 0.1f) + 0.01f * (float)(i % 7);
    }
    return vec;
}

// ---------------------------------------------------------------------------
// Run the router smoke test.
// ---------------------------------------------------------------------------
static bool RunRouterSmokeTest(const char* firstShardPath) {
    printf("\n========================================\n");
    printf("K2 Router Injection Smoke Test (Multi-Shard)\n");
    printf("First shard: %s\n", firstShardPath);
    printf("========================================\n\n");

    // --- Discover all shards ---
    std::vector<std::string> shards = DiscoverShards(firstShardPath);
    printf("Discovered %zu shard(s):\n", shards.size());
    for (const auto& s : shards) {
        printf("  %s\n", std::filesystem::path(s).filename().string().c_str());
    }
    printf("\n");

    // --- Build global tensor index ---
    std::vector<TensorLocation> globalIndex;
    ModelMetadata meta;
    if (!BuildGlobalTensorIndex(shards, globalIndex, meta)) {
        printf("FAIL: Could not build global tensor index from shards\n");
        return false;
    }
    printf("Global tensor index: %zu tensors across %zu shard(s)\n\n",
           globalIndex.size(), shards.size());

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

    std::vector<float> testHidden = BuildTestHiddenState(hiddenDim);
    std::vector<double> layerChecksums;
    std::vector<std::string> layerTensorNames;
    bool allPassed = true;

    // -----------------------------------------------------------------------
    // Test every MoE layer
    // -----------------------------------------------------------------------
    for (size_t layerIdx = firstMoELayer; layerIdx < numLayers; ++layerIdx) {
        char tensorName[256];
        snprintf(tensorName, sizeof(tensorName), "blk.%zu.ffn_gate_inp.weight", layerIdx);

        const TensorLocation* loc = FindTensor(globalIndex, tensorName);
        if (!loc) {
            printf("[L%zu] FAIL: tensor '%s' not found in global index\n", layerIdx, tensorName);
            allPassed = false;
            continue;
        }

        // --- Type check: must be FP32 ---
        if (loc->type != GGMLType::GGML_TYPE_F32) {
            printf("[L%zu] FAIL: '%s' type=%d (expected F32=%d). "
                   "Quantized router weights require dequantization.\n",
                   layerIdx, tensorName, (int)loc->type, (int)GGMLType::GGML_TYPE_F32);
            allPassed = false;
            continue;
        }

        // --- Dimension check: accept both [numExperts, hiddenDim] and [hiddenDim, numExperts] ---
        if (loc->shape.size() != 2) {
            printf("[L%zu] FAIL: '%s' has %zu dims (expected 2)\n",
                   layerIdx, tensorName, loc->shape.size());
            allPassed = false;
            continue;
        }

        size_t dim0 = loc->shape[0];
        size_t dim1 = loc->shape[1];
        bool shapeOk = false;
        size_t routerRows = 0;  // numExperts (output dim)
        size_t routerCols = 0;  // hiddenDim (input dim)

        if (dim0 == numExperts && dim1 == hiddenDim) {
            shapeOk = true;
            routerRows = dim0;
            routerCols = dim1;
        } else if (dim0 == hiddenDim && dim1 == numExperts) {
            shapeOk = true;
            routerRows = dim1;  // swapped: logical rows = numExperts
            routerCols = dim0;  // logical cols = hiddenDim
        }

        if (!shapeOk) {
            printf("[L%zu] FAIL: '%s' shape [%zu, %zu] (expected [%zu, %zu] or [%zu, %zu])\n",
                   layerIdx, tensorName, dim0, dim1,
                   numExperts, hiddenDim, hiddenDim, numExperts);
            allPassed = false;
            continue;
        }

        // --- Load tensor bytes selectively ---
        size_t loadedSize = 0;
        void* tensorBuf = LoadTensorBytes(*loc, loadedSize);
        if (!tensorBuf) {
            printf("[L%zu] FAIL: could not load bytes for '%s'\n", layerIdx, tensorName);
            allPassed = false;
            continue;
        }

        const float* weights = (const float*)tensorBuf;
        size_t numElements = routerRows * routerCols;

        if (loadedSize != numElements * sizeof(float)) {
            printf("[L%zu] FAIL: '%s' byte size mismatch: loaded %zu, expected %zu\n",
                   layerIdx, tensorName, loadedSize, numElements * sizeof(float));
            _aligned_free(tensorBuf);
            allPassed = false;
            continue;
        }

        // --- Nonzero check ---
        if (IsAllZero(weights, numElements)) {
            printf("[L%zu] FAIL: '%s' contains all zeros\n", layerIdx, tensorName);
            _aligned_free(tensorBuf);
            allPassed = false;
            continue;
        }

        double checksum = ComputeChecksum(weights, numElements);
        layerChecksums.push_back(checksum);
        layerTensorNames.push_back(tensorName);

        if (g_verbose) {
            printf("[L%zu] tensor='%s' shard='%s' type=F32\n",
                   layerIdx, tensorName,
                   std::filesystem::path(loc->shardPath).filename().string().c_str());
            printf("       GGUF shape=[%zu,%zu]  logical router=[%zu,%zu]  checksum=%.6f\n",
                   dim0, dim1, routerRows, routerCols, checksum);
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
        router.SetRouterWeights(weights, routerRows, routerCols);

        TokenRoute route1 = router.Route(testHidden.data());
        TokenRoute route2 = router.Route(testHidden.data());

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

        _aligned_free(tensorBuf);  // release after routing test

        if (!deterministic) {
            printf("[L%zu] FAIL: routing is NON-DETERMINISTIC\n", layerIdx);
            allPassed = false;
            continue;
        }

        if (g_verbose) {
            printf("       deterministic: PASS  top-k=[");
            for (size_t k = 0; k < route1.topExperts.size(); ++k) {
                if (k > 0) printf(", ");
                printf("%d", route1.topExperts[k].expertId);
            }
            printf("]\n");
        }
    }

    // -----------------------------------------------------------------------
    // Distinctness check
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
        printf("ALL ROUTER ASSERTIONS PASSED (%zu/%zu layers)\n",
               layerChecksums.size(), numLayers - firstMoELayer);
    } else {
        printf("SOME ROUTER ASSERTIONS FAILED (%zu/%zu layers passed)\n",
               layerChecksums.size(), numLayers - firstMoELayer);
    }
    printf("========================================\n\n");

    return allPassed;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    const char* firstShardPath = nullptr;

    if (argc > 1) {
        firstShardPath = argv[1];
    } else {
        // Try common K2 model locations
        const char* candidates[] = {
            "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf",
            nullptr
        };
        for (int i = 0; candidates[i]; ++i) {
            FILE* fp = fopen(candidates[i], "rb");
            if (fp) {
                fclose(fp);
                firstShardPath = candidates[i];
                break;
            }
        }
    }

    if (!firstShardPath) {
        printf("Usage: %s <path-to-first-k2-shard.gguf>\n", argv[0]);
        printf("Example: %s \"F:\\OllamaModels\\Kimi-K2\\...-00001-of-00013.gguf\"\n", argv[0]);
        return 1;
    }

    bool ok = RunRouterSmokeTest(firstShardPath);
    return ok ? 0 : 1;
}
