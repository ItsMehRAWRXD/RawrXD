#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

enum class DecodeOp : uint8_t {
    RMSNorm, QKV, RoPE, Attention, OProj, FFNNorm,
    GateUp, ActivationMul, DownProj, Residual, ExpertCombine
};

struct LaunchBatch {
    std::vector<DecodeOp> ops;
    bool oneSubmit = true;
    bool oneFence = true;
};

class LaunchAmortizer {
public:
    static std::vector<LaunchBatch> build(bool useMLA, bool useMoE) noexcept;
};

} // namespace Deep2
