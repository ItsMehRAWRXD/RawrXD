// ============================================================================
// ProductionProfiler.hpp — Stub header for per-token production profiling
// ============================================================================

#ifndef PRODUCTION_PROFILER_HPP
#define PRODUCTION_PROFILER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

struct TokenProfile {
    uint32_t tokenId = 0;
    uint32_t position = 0;
    double embedUs = 0.0;
    double attnNormUs = 0.0;
    double qkvProjUs = 0.0;
    double attnOutProjUs = 0.0;
    double attnResidualUs = 0.0;
    double ffnNormUs = 0.0;
    double ffnGateUs = 0.0;
    double ffnUpUs = 0.0;
    double ffnSwiGLUUs = 0.0;
    double ffnDownUs = 0.0;
    double ffnResidualUs = 0.0;
    double finalNormUs = 0.0;
    double logitsUs = 0.0;
    double samplingUs = 0.0;
    double ropeUs = 0.0;
    double kvStoreUs = 0.0;
    double attnComputeUs = 0.0;
    double totalUs = 0.0;
};

class ProductionProfiler {
public:
    ProductionProfiler() = default;

    void beginToken(uint32_t tokenId, uint32_t position);
    void setModelInfo(const char* modelName, int quantBits,
                      size_t hiddenDim, size_t numLayers, size_t numHeads);

    void beginEmbed();
    void endEmbed();

    void beginAttnNorm();
    void endAttnNorm();

    void beginQKVProj();
    void endAttnOutProj();

    void beginAttnResidual();
    void endAttnResidual();

    void beginFFNNorm();
    void endFFNNorm();

    void beginFFNGate();
    void endFFNGate();

    void beginFFNUp();
    void endFFNUp();

    void beginFFNSwiGLU();
    void endFFNSwiGLU();

    void beginFFNDown();
    void endFFNDown();

    void beginFFNResidual();
    void endFFNResidual();

    void beginFinalNorm();
    void endFinalNorm();

    void beginLogits();
    void endLogits();

    void beginSampling();
    void endSampling();

    void beginRoPE();
    void endRoPE();

    void beginKVStore();
    void endKVStore();

    void beginAttnCompute();
    void endAttnCompute();

    void recordQuantTime(int type, double microseconds);

    TokenProfile endToken();

    static std::string toJSONSummary(const TokenProfile* profiles, size_t count);

private:
    TokenProfile current_;
    bool active_ = false;
};

#endif // PRODUCTION_PROFILER_HPP
