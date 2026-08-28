// dump_qwen35_meta.cpp - Dump full Qwen3.5 GGUF metadata + tensor topology
// Establishes the exact architecture before any forward-pass changes.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include "GGUFLoader.hpp"

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\OllamaModels\\blobs\\sha256-9be227448d319e6a7acca8056b71bf7d9a2c6b2811986e6658a9dedc208d0ada";

    printf("=== Qwen3.5 GGUF Metadata Dump ===\n");
    printf("Model: %s\n\n", modelPath);

    // Use LoadMetadata to get raw metadata keys
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = false;
    opts.mmap = true;

    GGUFLoadResult res = GGUFLoader::Load(modelPath, opts);
    if (!res.success) {
        printf("[FAIL] Load failed: %s\n", res.error);
        return 1;
    }

    printf("=== Architecture ===\n");
    printf("architecture = '%s'\n", res.metadata.architecture.c_str());
    printf("vocabSize    = %u\n", res.metadata.vocabSize);
    printf("hiddenSize   = %u\n", res.metadata.hiddenSize);
    printf("numLayers    = %u\n", res.metadata.numLayers);
    printf("numHeads     = %u\n", res.metadata.numHeads);
    printf("numKVHeads   = %u\n", res.metadata.numKeyValueHeads);
    printf("intermediate = %u\n", res.metadata.intermediateSize);
    printf("rmsNormEps   = %f\n", res.metadata.rmsNormEps);
    printf("ropeTheta    = %f\n", res.metadata.ropeTheta);
    printf("maxPosEmb    = %u\n", res.metadata.maxPositionEmbeddings);
    printf("numExperts   = %u\n", res.metadata.numExperts);
    printf("numExpertsPerToken = %u\n", res.metadata.numExpertsPerToken);
    printf("numSharedExperts   = %u\n", res.metadata.numSharedExperts);
    printf("moeInter     = %u\n", res.metadata.moeIntermediateSize);
    printf("leadingDense = %u\n", res.metadata.leadingDenseBlockCount);
    printf("qLoraRank    = %u\n", res.metadata.qLoraRank);
    printf("kvLoraRank   = %u\n", res.metadata.kvLoraRank);
    printf("keyLength    = %u\n", res.metadata.keyLength);
    printf("valueLength  = %u\n", res.metadata.valueLength);
    printf("keyLengthMla = %u\n", res.metadata.keyLengthMla);
    printf("valueLengthMla = %u\n", res.metadata.valueLengthMla);
    printf("ropeDimCount = %u\n", res.metadata.ropeDimensionCount);
    printf("ropeScaling  = %f\n", res.metadata.ropeScaling);

    printf("\n=== Tensor Topology (layer 0 and layer 3) ===\n");
    for (const auto& t : res.tensors) {
        bool isL0 = t.name.find("blk.0.") == 0;
        bool isL3 = t.name.find("blk.3.") == 0;
        bool isGlobal = t.name.find("blk.") != 0;
        if (isL0 || isL3 || isGlobal) {
            printf("  %-40s dims=[", t.name.c_str());
            for (size_t i = 0; i < t.dimensions.size(); ++i) {
                if (i) printf(",");
                printf("%llu", (unsigned long long)t.dimensions[i]);
            }
            printf("] type=%d size=%llu\n", (int)t.type, (unsigned long long)t.size);
        }
    }

    printf("\n=== All SSM tensor names (unique) ===\n");
    std::vector<std::string> ssmNames;
    for (const auto& t : res.tensors) {
        if (t.name.find("ssm") != std::string::npos) {
            // Extract the suffix after blk.N.
            size_t dot = t.name.find('.');
            size_t dot2 = t.name.find('.', dot + 1);
            std::string suffix = t.name.substr(dot2 + 1);
            bool found = false;
            for (auto& s : ssmNames) if (s == suffix) { found = true; break; }
            if (!found) ssmNames.push_back(suffix);
        }
    }
    for (auto& s : ssmNames) printf("  %s\n", s.c_str());

    printf("\n=== All attention tensor names (unique) ===\n");
    std::vector<std::string> attnNames;
    for (const auto& t : res.tensors) {
        if (t.name.find("attn") != std::string::npos) {
            size_t dot = t.name.find('.');
            size_t dot2 = t.name.find('.', dot + 1);
            std::string suffix = t.name.substr(dot2 + 1);
            bool found = false;
            for (auto& s : attnNames) if (s == suffix) { found = true; break; }
            if (!found) attnNames.push_back(suffix);
        }
    }
    for (auto& s : attnNames) printf("  %s\n", s.c_str());

    printf("\n=== All FFN tensor names (unique) ===\n");
    std::vector<std::string> ffnNames;
    for (const auto& t : res.tensors) {
        if (t.name.find("ffn") != std::string::npos) {
            size_t dot = t.name.find('.');
            size_t dot2 = t.name.find('.', dot + 1);
            std::string suffix = t.name.substr(dot2 + 1);
            bool found = false;
            for (auto& s : ffnNames) if (s == suffix) { found = true; break; }
            if (!found) ffnNames.push_back(suffix);
        }
    }
    for (auto& s : ffnNames) printf("  %s\n", s.c_str());

    printf("\n=== Layer-by-layer topology ===\n");
    for (int l = 0; l < (int)res.metadata.numLayers; ++l) {
        std::string prefix = "blk." + std::to_string(l) + ".";
        bool hasSsm = false, hasQkv = false, hasQ = false, hasK = false, hasV = false;
        bool hasGate = false, hasOut = false, hasFfn = false;
        for (const auto& t : res.tensors) {
            if (t.name.find(prefix) != 0) continue;
            if (t.name.find("ssm_") != std::string::npos) hasSsm = true;
            if (t.name.find("attn_qkv") != std::string::npos) hasQkv = true;
            if (t.name.find("attn_q.") != std::string::npos) hasQ = true;
            if (t.name.find("attn_k.") != std::string::npos) hasK = true;
            if (t.name.find("attn_v.") != std::string::npos) hasV = true;
            if (t.name.find("attn_gate") != std::string::npos) hasGate = true;
            if (t.name.find("attn_output") != std::string::npos) hasOut = true;
            if (t.name.find("ffn_") != std::string::npos) hasFfn = true;
        }
        printf("  Layer %2d: ssm=%d qkv=%d q=%d k=%d v=%d gate=%d out=%d ffn=%d\n",
               l, hasSsm?1:0, hasQkv?1:0, hasQ?1:0, hasK?1:0, hasV?1:0,
               hasGate?1:0, hasOut?1:0, hasFfn?1:0);
    }

    printf("\n=== DONE ===\n");
    return 0;
}
