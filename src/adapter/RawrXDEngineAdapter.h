// =============================================================================
// RawrXDEngineAdapter.h — Adapter for generation control plane
// =============================================================================

#pragma once
#include <memory>
#include <string>
#include <vector>

struct EngineConfig {
    size_t hiddenDim;
    size_t numLayers;
    size_t numHeads;
    size_t vocabSize;
    size_t maxSeqLen;
    bool useKVCache;
    bool useRoPE;
    std::string modelPath;
};

class RawrXDEngineAdapter {
public:
    RawrXDEngineAdapter();
    ~RawrXDEngineAdapter();

    bool initialize(const EngineConfig& cfg);
    std::vector<int> tokenize(const std::string& text);
    std::string detokenize(const std::vector<int>& tokens);
    void prefill(const std::vector<int>& tokens);
    int decode();
    void clearCache();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};