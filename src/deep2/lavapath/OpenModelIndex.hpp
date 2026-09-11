#pragma once
/* OpenModelIndex — loadModel demoted: metadata/namespace only. LIVE=0. ≤99.
   MODEL_SIZE_NE_RESIDENCY: no model-shaped residency created here. */
#include "ScoreboardInvariants.hpp"
#include "TensorScoreboard.hpp"
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct VirtualTensorDesc {
    TensorId id = 0;
    uint64_t backingOffset = 0;
    uint64_t backingBytes = 0;
    uint32_t firstUse = 0;
    uint32_t lastUse = 0;
    uint32_t consumers = 0;
    DeviceId preferredDevice = -1;
};

struct OpenModelIndex {
    static constexpr uint32_t kMax = 4096;
    char path[512]{};
    VirtualTensorDesc tensors[kMax]{};
    uint32_t nTensors = 0;
    uint64_t totalBackingBytes = 0; /* namespace property ≠ residency */

    int openPath(const char* ggufPath) {
        if (!ggufPath || !ggufPath[0] || !MODEL_SIZE_NE_RESIDENCY)
            return 0;
        uint32_t i = 0;
        for (; ggufPath[i] && i + 1u < sizeof(path); ++i)
            path[i] = ggufPath[i];
        path[i] = 0;
        nTensors = 0;
        totalBackingBytes = 0;
        return 1;
    }

    int addTensor(const VirtualTensorDesc& d) {
        if (nTensors >= kMax || d.backingBytes == 0)
            return 0;
        tensors[nTensors++] = d;
        totalBackingBytes += d.backingBytes;
        return 1;
    }

    /* Bind descriptors into scoreboard — still no weight residency alloc. */
    int primeScoreboard(TensorScoreboard& sb, WindowPool* ram) const {
        if (!nTensors || !ram || !sb.bind(nTensors, ram))
            return 0;
        for (uint32_t i = 0; i < nTensors; ++i) {
            const VirtualTensorDesc& d = tensors[i];
            if (!sb.initTensor(d.id, d.backingOffset, d.backingBytes, d.firstUse,
                               d.lastUse, d.consumers, d.preferredDevice))
                return 0;
        }
        return 1;
    }
};

} /* namespace scoreboard */
} /* namespace Deep2 */
