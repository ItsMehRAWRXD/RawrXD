// K2LogitsArgmaxContract.hpp — first-false fault enum + geometry (no deps).
#pragma once
#include "K2GlobalTensorIndex.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>

namespace Deep2 {

enum LogitsBoundaryFault : unsigned {
    LOGITS_OK = 0,
    LOGITS_NULL_HIDDEN,
    LOGITS_NULL_HEAD,
    LOGITS_NULL_OUTPUT,
    LOGITS_HIDDEN_ZERO,
    LOGITS_VOCAB_ZERO,
    LOGITS_HEAD_INPUT_ZERO,
    LOGITS_HIDDEN_NE_HEAD_INPUT,
    LOGITS_HIDDEN_NE_MODEL_HIDDEN,
    LOGITS_VOCAB_NE_MODEL_VOCAB,
    LOGITS_HEAD_BYTES_UNDERSIZED,
    LOGITS_SIZE_OVERFLOW,
    LOGITS_STORAGE_NOT_RESIDENT,
    LOGITS_PRODUCER_NOT_COMPLETE,
    LOGITS_PROJECT_FAILED,
    LOGITS_ARGMAX_OOB,
    LOGITS_TYPE_NOT_Q6_K
};

inline const char* LogitsFaultName(LogitsBoundaryFault f) {
    switch (f) {
    case LOGITS_OK: return "LOGITS_OK";
    case LOGITS_NULL_HIDDEN: return "LOGITS_NULL_HIDDEN";
    case LOGITS_NULL_HEAD: return "LOGITS_NULL_HEAD";
    case LOGITS_NULL_OUTPUT: return "LOGITS_NULL_OUTPUT";
    case LOGITS_HIDDEN_ZERO: return "LOGITS_HIDDEN_ZERO";
    case LOGITS_VOCAB_ZERO: return "LOGITS_VOCAB_ZERO";
    case LOGITS_HEAD_INPUT_ZERO: return "LOGITS_HEAD_INPUT_ZERO";
    case LOGITS_HIDDEN_NE_HEAD_INPUT: return "LOGITS_HIDDEN_NE_HEAD_INPUT";
    case LOGITS_HIDDEN_NE_MODEL_HIDDEN: return "LOGITS_HIDDEN_NE_MODEL_HIDDEN";
    case LOGITS_VOCAB_NE_MODEL_VOCAB: return "LOGITS_VOCAB_NE_MODEL_VOCAB";
    case LOGITS_HEAD_BYTES_UNDERSIZED: return "LOGITS_HEAD_BYTES_UNDERSIZED";
    case LOGITS_SIZE_OVERFLOW: return "LOGITS_SIZE_OVERFLOW";
    case LOGITS_STORAGE_NOT_RESIDENT: return "LOGITS_STORAGE_NOT_RESIDENT";
    case LOGITS_PRODUCER_NOT_COMPLETE: return "LOGITS_PRODUCER_NOT_COMPLETE";
    case LOGITS_PROJECT_FAILED: return "LOGITS_PROJECT_FAILED";
    case LOGITS_ARGMAX_OOB: return "LOGITS_ARGMAX_OOB";
    case LOGITS_TYPE_NOT_Q6_K: return "LOGITS_TYPE_NOT_Q6_K";
    default: return "LOGITS_UNKNOWN";
    }
}

inline void LogLogitsFault(uint32_t step, uint32_t steps,
                           LogitsBoundaryFault f) {
    std::fprintf(stderr, "%s STEP=%u/%u FAULT=%u\n", LogitsFaultName(f), step,
                 steps, (unsigned)f);
    std::fflush(stderr);
}

inline void LogLogitsFault(uint32_t step, LogitsBoundaryFault f) {
    LogLogitsFault(step, 0, f);
}

#define LOGITS_REQUIRE(expr, fault)                                         \
    do {                                                                    \
        if (!(expr)) {                                                      \
            LogLogitsFault(logitsStep, logitsSteps, (fault));               \
            error = LogitsFaultName((fault));                               \
            bestTok = -1;                                                   \
            return false;                                                   \
        }                                                                   \
    } while (0)

namespace detail {

// Q6_K needBytes / row geometry. Sets error to LogitsFaultName-compatible tag.
inline bool LogitsArgmaxContract(const float* /*hidden*/, size_t hiddenDim,
                                 size_t vocabSize,
                                 const GlobalTensorRef& outRef,
                                 size_t& blocksPerRowOut, size_t& rowBytesOut,
                                 size_t& needBytesOut, std::string& error) {
    constexpr size_t kBlockElems = 256;
    constexpr size_t kBlockBytes = 210;
    const size_t kMax = (std::numeric_limits<size_t>::max)();

    if (hiddenDim == 0) {
        error = "LOGITS_HIDDEN_ZERO";
        return false;
    }
    if (vocabSize == 0) {
        error = "LOGITS_VOCAB_ZERO";
        return false;
    }
    if (outRef.ggmlType != 14) {
        error = "LOGITS_TYPE_NOT_Q6_K";
        return false;
    }
    if (outRef.byteSize == 0) {
        error = "LOGITS_HEAD_BYTES_UNDERSIZED";
        return false;
    }
    if (hiddenDim > kMax - (kBlockElems - 1)) {
        error = "LOGITS_SIZE_OVERFLOW";
        return false;
    }
    const size_t blocksPerRow = (hiddenDim + kBlockElems - 1) / kBlockElems;
    if (blocksPerRow == 0 || blocksPerRow > kMax / kBlockBytes) {
        error = "LOGITS_SIZE_OVERFLOW";
        return false;
    }
    const size_t rowBytes = blocksPerRow * kBlockBytes;
    if (vocabSize > kMax / rowBytes) {
        error = "LOGITS_SIZE_OVERFLOW";
        return false;
    }
    const size_t needBytes = vocabSize * rowBytes;
    if (needBytes > outRef.byteSize) {
        error = "LOGITS_HEAD_BYTES_UNDERSIZED";
        return false;
    }
    blocksPerRowOut = blocksPerRow;
    rowBytesOut = rowBytes;
    needBytesOut = needBytes;
    return true;
}

} // namespace detail
} // namespace Deep2
