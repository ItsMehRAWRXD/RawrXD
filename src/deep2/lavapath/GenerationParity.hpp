#pragma once
/*
    RAWRXD_GENERATION_PARITY_001

    Product-path parity only.
    No kernel microtests.
    No synthetic promotion.
*/

#include <cstdint>

namespace rawrxd::deep2::parity {

struct Input {
    uint32_t tokensRequested = 0;
    uint32_t tokensCommitted = 0;

    bool productionDecodePath = false;
    bool modelOutputProduced = false;
    bool streamOutputPresent = false;
    bool completionReceiptPresent = false;
    bool receiptAtomic = false;
    bool streamHashMatch = false;

    bool finiteNumerics = false;
    bool cpuF32ExpandsZero = false;
    bool hostForwardCallsZero = false;

    // Deterministic champion comparison.
    bool requireExactTokenParity = true;
    uint64_t baselineTokenHash = 0;
    uint64_t candidateTokenHash = 0;
};

struct Result {
    bool pass = false;
    const char* blockedAt = "UNKNOWN";
};

inline Result Evaluate(const Input& in) noexcept {
    if (!in.productionDecodePath)
        return {false, "PRODUCTION_DECODE_PATH"};

    if (in.tokensRequested == 0 ||
        in.tokensCommitted != in.tokensRequested)
        return {false, "TOKENS_COMMITTED"};

    if (!in.modelOutputProduced)
        return {false, "MODEL_OUTPUT_PRODUCED"};

    if (!in.streamOutputPresent)
        return {false, "STREAM_OUTPUT"};

    if (!in.completionReceiptPresent || !in.receiptAtomic)
        return {false, "COMPLETION_RECEIPT"};

    if (!in.streamHashMatch)
        return {false, "STREAM_HASH"};

    if (!in.finiteNumerics)
        return {false, "FINITE_NUMERICS"};

    if (!in.cpuF32ExpandsZero)
        return {false, "CPU_F32_EXPANDS"};

    if (!in.hostForwardCallsZero)
        return {false, "HOST_FORWARD_LAYER_CALLS"};

    if (in.requireExactTokenParity &&
        in.baselineTokenHash != 0 &&
        in.baselineTokenHash != in.candidateTokenHash)
        return {false, "TOKEN_PARITY"};

    return {true, "NONE"};
}

} // namespace rawrxd::deep2::parity
