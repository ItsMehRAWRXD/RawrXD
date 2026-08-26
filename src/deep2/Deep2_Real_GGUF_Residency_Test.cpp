// ============================================================================
// Deep2_Real_GGUF_Residency_Test.cpp
// Phase 1: Load a real GGUF, register tensors with ElasticResidencyManager,
// simulate forward pass with residency-managed tensor acquisition.
//
// Usage: Deep2_Real_GGUF_Residency_Test.exe [path_to.gguf]
// ============================================================================

#include "ElasticResidencyManager.hpp"
#include "GGUFLoader.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <vector>
#include <atomic>
#include <string>

using namespace Deep2;

// Stub ResidencyTrace C interface (no ASM dependency)
extern "C" {
    int TraceInit(const char*) { return 1; }
    void TraceShutdown(void) {}
    struct ResidencyEvent { uint32_t dummy; };
    ResidencyEvent* TraceBegin(uint32_t, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t) { return nullptr; }
    void TraceSetDestination(ResidencyEvent*, uint32_t, uint64_t, uint64_t, uint64_t, uint32_t, uint32_t) {}
    void TraceComplete(ResidencyEvent*, uint64_t, uint64_t, int) {}
    void TraceFlush(void) {}
}

// ============================================================================
// Map GGML type to TensorFormat
// ============================================================================
TensorFormat GGMLTypeToFormat(GGMLType type) {
    switch (type) {
        case GGMLType::GGML_TYPE_F32:  return TensorFormat::FP32;
        case GGMLType::GGML_TYPE_F16:  return TensorFormat::FP16;
        case GGMLType::GGML_TYPE_Q4_0: return TensorFormat::Q4_0;
        case GGMLType::GGML_TYPE_Q4_1: return TensorFormat::Q4_1;
        case GGMLType::GGML_TYPE_Q5_0: return TensorFormat::Q5_0;
        case GGMLType::GGML_TYPE_Q5_1: return TensorFormat::Q5_1;
        case GGMLType::GGML_TYPE_Q8_0: return TensorFormat::Q8_0;
        case GGMLType::GGML_TYPE_Q2_K: return TensorFormat::Q2_K;
        case GGMLType::GGML_TYPE_Q3_K: return TensorFormat::Q3_K;
        case GGMLType::GGML_TYPE_Q4_K: return TensorFormat::Q4_K;
        case GGMLType::GGML_TYPE_Q5_K: return TensorFormat::Q5_K;
        case GGMLType::GGML_TYPE_Q6_K: return TensorFormat::Q6_K;
        default: return TensorFormat::Unknown;
    }
}

// ============================================================================
// Extract layer index from tensor name
// e.g. "blk.3.attn_q.weight" -> layer=3
// ============================================================================
uint32_t ExtractLayerIndex(const std::string& name) {
    size_t pos = name.find("blk.");
    if (pos == std::string::npos) return ~0u;
    pos += 4;
    size_t end = name.find('.', pos);
    if (end == std::string::npos) return ~0u;
    try {
        return static_cast<uint32_t>(std::stoul(name.substr(pos, end - pos)));
    } catch (...) {
        return ~0u;
    }
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1] : "G:\\OllamaModels\\Codestral-22B-v0.1-Q4_K_M.gguf";

    printf("=================================================================\n");
    printf(" Deep2 Real GGUF + ElasticResidencyManager Integration Test\n");
    printf("=================================================================\n");
    printf("Model: %s\n\n", modelPath);

    // --- Step 1: Parse GGUF metadata (lightweight, no tensor data yet) ---
    printf("[Step 1] Parsing GGUF metadata...\n");
    GGUFLoadOptions options;
    options.loadTensors = false;  // Metadata only for now

    GGUFLoadResult result = GGUFLoader::Load(modelPath, options);
    if (!result.success) {
        printf("[FAIL] GGUF parse failed: %s\n", result.error);
        return 1;
    }

    printf("[PASS] GGUF parsed: tensors=%zu\n", result.tensors.size());
    if (result.tensors.size() == 0 || result.tensors.size() > 1000000) {
        printf("[FAIL] Invalid tensor count: %zu (expected 1..1000000)\n", result.tensors.size());
        return 1;
    }
    result.metadata.Print();

    uint32_t numLayers = result.metadata.numLayers;
    uint32_t hiddenDim = result.metadata.hiddenSize;
    uint32_t vocabSize = result.metadata.vocabSize;
    printf("  Architecture: layers=%u, hidden_dim=%u, vocab_size=%u\n", numLayers, hiddenDim, vocabSize);

    // --- Step 2: Initialize ElasticResidencyManager ---
    printf("\n[Step 2] Initializing ElasticResidencyManager...\n");

    // Compute total model size from tensor infos
    size_t totalModelBytes = 0;
    for (auto& ti : result.tensors) {
        totalModelBytes += ti.size;
    }
    printf("  Total model size: %.1f MB\n", totalModelBytes / (1024.0 * 1024.0));

    // Pressure mode: 50% budget to force eviction
    size_t pressureBudget = totalModelBytes / 2;

    ElasticResidencyConfig config;
    config.maxWarmCompressedBytes = pressureBudget;
    config.maxWarmStagedBytes = 256ULL * 1024 * 1024;
    config.maxHotBytes = 512ULL * 1024 * 1024;
    config.useGhostCache = true;
    config.ghostCacheCapacity = 16384;

    printf("  RAM budget: %.1f MB (pressure mode)\n", pressureBudget / (1024.0 * 1024.0));

    ElasticResidencyManager mgr;
    if (!mgr.Initialize(config)) {
        printf("[FAIL] ElasticResidencyManager init failed\n");
        return 1;
    }
    printf("[PASS] ElasticResidencyManager initialized\n");

    // --- Step 3: Register all GGUF tensors with residency manager ---
    printf("\n[Step 3] Registering %zu tensors...\n", result.tensors.size());

    // We need actual tensor data pointers. For this test, we'll memory-map the GGUF
    // and point each tensor at its offset within the file.
    FILE* fp = fopen(modelPath, "rb");
    if (!fp) {
        printf("[FAIL] Cannot open GGUF file for reading\n");
        return 1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Read entire file into memory (simpler than mmap for this test)
    std::vector<uint8_t> fileData(fileSize);
    if (fread(fileData.data(), 1, fileSize, fp) != fileSize) {
        printf("[FAIL] Failed to read GGUF file\n");
        fclose(fp);
        return 1;
    }
    fclose(fp);
    printf("  File loaded: %.1f MB\n", fileSize / (1024.0 * 1024.0));

    // Register tensors
    size_t registered = 0;
    for (auto& ti : result.tensors) {
        const std::string& name = ti.name;

        uint32_t layerIdx = ExtractLayerIndex(name);
        uint32_t expertIdx = ~0u;  // Dense for now

        // Compute pointer to tensor data within fileData
        const void* tensorPtr = fileData.data() + result.dataOffset + ti.offset;

        TensorFormat fmt = GGMLTypeToFormat(ti.type);
        if (fmt == TensorFormat::Unknown) {
            printf("  [WARN] Unknown format for '%s', skipping registration\n", name.c_str());
            continue;
        }

        mgr.RegisterTensor(name, layerIdx, expertIdx,
                           result.dataOffset + ti.offset, ti.size, fmt, tensorPtr);
        registered++;
    }
    printf("[PASS] Registered %zu tensors\n", registered);

    // --- Step 4: Simulate forward pass through layers ---
    printf("\n[Step 4] Simulating forward pass (2 passes to trigger GhostCache)...\n");

    std::atomic<uint64_t> hits{0}, misses{0};

    auto forwardPass = [&](const std::string& label) {
        auto t0 = std::chrono::steady_clock::now();

        // Acquire embedding
        ElasticResidencyManager::ResidencyHandle h;
        auto status = mgr.AcquireTensor("token_embd.weight", 0, 0, h);
        if (status == ElasticResidencyManager::AcquireStatus::Ready) hits.fetch_add(1);
        else misses.fetch_add(1);
        mgr.ReleaseTensor("token_embd.weight");

        // Acquire each layer's weights
        for (uint32_t L = 0; L < numLayers; ++L) {
            std::string prefix = "blk." + std::to_string(L) + ".";
            std::vector<std::string> names = {
                prefix + "attn_norm.weight",
                prefix + "attn_q.weight",
                prefix + "attn_k.weight",
                prefix + "attn_v.weight",
                prefix + "attn_output.weight",
                prefix + "ffn_norm.weight",
                prefix + "ffn_gate.weight",
                prefix + "ffn_up.weight",
                prefix + "ffn_down.weight",
            };
            for (auto& n : names) {
                ElasticResidencyManager::ResidencyHandle hh;
                auto s = mgr.AcquireTensor(n, 0, 0, hh);
                if (s == ElasticResidencyManager::AcquireStatus::Ready) hits.fetch_add(1);
                else misses.fetch_add(1);
                mgr.ReleaseTensor(n);
            }
        }

        // Acquire output
        status = mgr.AcquireTensor("output.weight", 0, 0, h);
        if (status == ElasticResidencyManager::AcquireStatus::Ready) hits.fetch_add(1);
        else misses.fetch_add(1);
        mgr.ReleaseTensor("output.weight");

        status = mgr.AcquireTensor("norm.weight", 0, 0, h);
        if (status == ElasticResidencyManager::AcquireStatus::Ready) hits.fetch_add(1);
        else misses.fetch_add(1);
        mgr.ReleaseTensor("norm.weight");

        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        printf("  %s: %.2f ms\n", label.c_str(), ms);
    };

    // Pass 1: cold load (will evict as budget is exceeded)
    forwardPass("Pass 1 (cold)");

    // Pass 2: some tensors should be ghost hits
    forwardPass("Pass 2 (warm)");

    // --- Step 5: Report telemetry ---
    printf("\n[Step 5] Telemetry:\n");
    auto& telem = mgr.GetTelemetry();
    printf("  Acquire hits:   %llu\n", (unsigned long long)hits.load());
    printf("  Acquire misses: %llu\n", (unsigned long long)misses.load());
    printf("  Ghost hits:     %llu\n", (unsigned long long)telem.ghostHits.load());
    printf("  Ghost misses:   %llu\n", (unsigned long long)telem.ghostMisses.load());
    printf("  Hit rate:       %.1f%%\n",
           (hits.load() + misses.load() > 0)
               ? (double)hits.load() / (double)(hits.load() + misses.load()) * 100.0
               : 0.0);

    bool pass = (telem.ghostHits.load() > 0);

    mgr.Shutdown();

    if (pass) {
        printf("\n=================================================================\n");
        printf(" PASS: Real GGUF tensors successfully managed by ElasticResidency\n");
        printf(" GhostCache hits: %llu\n", (unsigned long long)telem.ghostHits.load());
        printf(" Hit rate: %.1f%%\n",
               (hits.load() + misses.load() > 0)
                   ? (double)hits.load() / (double)(hits.load() + misses.load()) * 100.0
                   : 0.0);
        printf("=================================================================\n");
        return 0;
    } else {
        printf("\n[FAIL] No GhostCache hits occurred\n");
        return 1;
    }
}
