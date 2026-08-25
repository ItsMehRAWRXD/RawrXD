// ============================================================================
// ProductionProfiler.cpp — Stub implementation
// ============================================================================

#include "ProductionProfiler.hpp"
#include <chrono>

static double nowUs() {
    auto t = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::micro>(t.time_since_epoch()).count();
}

void ProductionProfiler::beginToken(uint32_t tokenId, uint32_t position) {
    current_ = TokenProfile{};
    current_.tokenId = tokenId;
    current_.position = position;
    active_ = true;
}

void ProductionProfiler::setModelInfo(const char* /*modelName*/, int /*quantBits*/,
                                      size_t /*hiddenDim*/, size_t /*numLayers*/,
                                      size_t /*numHeads*/) {
    // stub
}

void ProductionProfiler::beginEmbed()    { /* stub */ }
void ProductionProfiler::endEmbed()      { /* stub */ }
void ProductionProfiler::beginAttnNorm() { /* stub */ }
void ProductionProfiler::endAttnNorm()   { /* stub */ }
void ProductionProfiler::beginQKVProj()  { /* stub */ }
void ProductionProfiler::endQKVProj()   { /* stub */ }
void ProductionProfiler::beginAttnOutProj() { /* stub */ }
void ProductionProfiler::endAttnOutProj()   { /* stub */ }
void ProductionProfiler::beginAttnResidual() { /* stub */ }
void ProductionProfiler::endAttnResidual()     { /* stub */ }
void ProductionProfiler::beginFFNNorm()    { /* stub */ }
void ProductionProfiler::endFFNNorm()      { /* stub */ }
void ProductionProfiler::beginFFNGate()    { /* stub */ }
void ProductionProfiler::endFFNGate()      { /* stub */ }
void ProductionProfiler::beginFFNUp()      { /* stub */ }
void ProductionProfiler::endFFNUp()        { /* stub */ }
void ProductionProfiler::beginFFNSwiGLU()  { /* stub */ }
void ProductionProfiler::endFFNSwiGLU()    { /* stub */ }
void ProductionProfiler::beginFFNDown()    { /* stub */ }
void ProductionProfiler::endFFNDown()      { /* stub */ }
void ProductionProfiler::beginFFNResidual() { /* stub */ }
void ProductionProfiler::endFFNResidual()   { /* stub */ }
void ProductionProfiler::beginFinalNorm()  { /* stub */ }
void ProductionProfiler::endFinalNorm()    { /* stub */ }
void ProductionProfiler::beginLogits()   { /* stub */ }
void ProductionProfiler::endLogits()       { /* stub */ }
void ProductionProfiler::beginSampling()   { /* stub */ }
void ProductionProfiler::endSampling()     { /* stub */ }
void ProductionProfiler::beginRoPE()       { /* stub */ }
void ProductionProfiler::endRoPE()         { /* stub */ }
void ProductionProfiler::beginKVStore()  { /* stub */ }
void ProductionProfiler::endKVStore()    { /* stub */ }
void ProductionProfiler::beginAttnCompute() { /* stub */ }
void ProductionProfiler::endAttnCompute()  { /* stub */ }

void ProductionProfiler::recordQuantTime(int /*type*/, double /*microseconds*/) {
    // stub
}

TokenProfile ProductionProfiler::endToken() {
    active_ = false;
    return current_;
}

std::string ProductionProfiler::toJSONSummary(const TokenProfile* /*profiles*/, size_t /*count*/) {
    return "{}";
}
