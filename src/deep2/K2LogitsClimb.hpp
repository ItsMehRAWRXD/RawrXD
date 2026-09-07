// K2LogitsClimb.hpp — packed Q6_K argmax (no full logits / dequant buffer)
#pragma once
#include <cstdint>
#include <cstdio>

namespace Deep2 {

struct LogitsClimbSnap {
    uint64_t calls = 0;
    uint64_t rowsVisited = 0;
    uint64_t q6Blocks = 0;
    uint64_t allocCount = 0;
    uint64_t tempBytes = 0;
    uint64_t threads = 0;
    uint64_t fullMaterialize = 0;
    uint64_t fullDequant = 0;
    uint64_t rowAccessUs = 0;
    uint64_t q6DecodeUs = 0; // fused into dot — stays 0 on packed path
    uint64_t dotUs = 0;
    uint64_t reduceUs = 0;
    uint64_t miscUs = 0;
    int32_t lastToken = -1;
    float lastValue = 0.f;
};

void LogitsClimb_Reset();
LogitsClimbSnap LogitsClimb_Snapshot();
void LogitsClimb_Emit(FILE* f);

// Packed Q6_K row · hidden → score (no F32 expand).
float LogitsClimb_DotQ6KRow(const uint8_t* rowPtr, size_t blocksPerRow,
                            size_t cols, const float* hidden);

// Persistent-pool parallel argmax over packed vocab. allocCount stays 0.
bool LogitsClimb_ArgmaxPacked(const uint8_t* base, size_t baseBytes,
                              size_t vocabSize, size_t hiddenDim,
                              const float* hidden, int32_t& bestTok,
                              float* bestValOut);

// Single-thread reference (parity).
bool LogitsClimb_ArgmaxPackedSerial(const uint8_t* base, size_t baseBytes,
                                    size_t vocabSize, size_t hiddenDim,
                                    const float* hidden, int32_t& bestTok,
                                    float* bestValOut);

} // namespace Deep2
