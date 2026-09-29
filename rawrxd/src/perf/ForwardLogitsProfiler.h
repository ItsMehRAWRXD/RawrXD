// ForwardLogitsProfiler.h — RAWRXD_FORWARD_LOGITS_SPEED_001
#pragma once
#include <string>
#include <cstdint>
#include <chrono>
namespace rawrxd { namespace perf {
enum class Stage : uint8_t {
    Embed, AttnQ, AttnK, AttnV, AttnOut, FfnGate, FfnUp, FfnAct, FfnDown,
    FinalNorm, LmHead, Logits, Sampler, Callback, Render
};
void beginToken();
void recordStage(Stage s, uint64_t elapsedNs);
void writeForwardLogitsReceipt(const std::string& path);
const char* stageName(Stage s);
}} // namespace rawrxd::perf