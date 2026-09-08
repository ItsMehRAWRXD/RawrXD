// TensorScoreboard.hpp — READY(tensor) without per-layer join stalls
#pragma once
#include "ChoreographyResidencyLaw.hpp"
#include <cstdint>

namespace Deep2 {
namespace choreo {

enum class OpKind : uint8_t { Gemv = 0, Attn = 1, Norm = 2, Logits = 3 };

struct ScoreOp {
    uint32_t tensorId = 0;
    uint32_t layer = 0;
    OpKind kind = OpKind::Gemv;
    int deviceId = -1;
    uint64_t lastUseGen = 0;
    int ready = 0;
};

// Scoreboard tip only — production fill binds to VWA ranges later.
struct TensorScoreboard {
    ScoreOp ops[8]{};
    uint32_t n = 0;
    uint32_t cursor = 0;

    const ScoreOp* nextReady() {
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t j = (cursor + i) % (n ? n : 1);
            if (ops[j].ready) {
                cursor = (j + 1) % n;
                return &ops[j];
            }
        }
        return nullptr;
    }

    const ScoreOp* nextMissing() {
        for (uint32_t i = 0; i < n; ++i) {
            if (!ops[i].ready) return &ops[i];
        }
        return nullptr;
    }

    void retireLastUse(uint32_t tensorId, uint64_t gen) {
        for (uint32_t i = 0; i < n; ++i) {
            if (ops[i].tensorId == tensorId && ops[i].lastUseGen <= gen)
                ops[i].ready = 0;
        }
    }
};

} // namespace choreo
} // namespace Deep2
