#pragma once
/* F-1: one model → one owned execution instance. No static model geometry. */
#include <cstdint>

#define RAWR_F1_MODEL_EXEC 1
#define RAWR_NO_STATIC_MODEL_STATE 1
#define RAWR_BASE_FORWARD_NEVER_SKIPPABLE 1

namespace rawr {

struct Activation {
    float* ptr = nullptr;
    uint64_t elements = 0;
    uint64_t modelGeneration = 0;
    uint64_t writeGeneration = 0;
};

struct ModelFacts {
    uint32_t hidden = 0;
    uint32_t layers = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t ffn = 0;
    uint32_t vocab = 0; // independent of hidden — never seeded from hidden
};

struct ModelExec {
    uint64_t generation = 0;
    uint64_t modelHandle = 0;
    ModelFacts facts{};
    uint32_t position = 0;
    uint32_t token = 0;
    Activation hiddenA{};
    Activation hiddenB{};
    uint64_t expectedFinalWrite = 0;
    uint64_t kvCache = 0;
    uint64_t tensorIndex = 0;
    uint32_t flags = 0; // enhancements optional; base forward always run
};

inline void NoteWrite(Activation& a, uint64_t modelGen) noexcept {
    a.modelGeneration = modelGen;
    ++a.writeGeneration;
}

inline bool FinalHiddenReady(const ModelExec& e, const Activation& h) noexcept {
    return h.ptr && h.writeGeneration != 0 &&
           h.modelGeneration == e.generation &&
           (e.expectedFinalWrite == 0 ||
            h.writeGeneration == e.expectedFinalWrite);
}

} // namespace rawr
