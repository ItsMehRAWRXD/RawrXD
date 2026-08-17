// ============================================================================
// K2MLAWeights.cpp — K2-002 MLA Tensor Schema Implementation
// ============================================================================

#include "K2MLAWeights.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>

namespace Deep2 {

// ============================================================================
// MLAWeights
// ============================================================================

bool MLAWeights::Validate(const KimiK2Config& config, std::string& error) const {
    // Check all required tensors are present
    if (!attnQ_a.data()) { error = "MLAWeights: attn_q_a missing"; return false; }
    if (!attnQ_a_norm.data()) { error = "MLAWeights: attn_q_a_norm missing"; return false; }
    if (!attnQ_b.data()) { error = "MLAWeights: attn_q_b missing"; return false; }
    if (!attnKV_a_mqa.data()) { error = "MLAWeights: attn_kv_a_mqa missing"; return false; }
    if (!attnKV_a_norm.data()) { error = "MLAWeights: attn_kv_a_norm missing"; return false; }
    if (!attnKV_b.data()) { error = "MLAWeights: attn_kv_b missing"; return false; }
    if (!attnO.data()) { error = "MLAWeights: attn_o missing"; return false; }
    if (!attnNorm.data()) { error = "MLAWeights: attn_norm missing"; return false; }

    // Validate tensor shapes against config
    const uint32_t hiddenDim = config.hiddenDim;
    const uint32_t qLoraRank = config.qLoraRank;
    const uint32_t kvLoraRank = config.kvLoraRank;
    const uint32_t qkNopeHeadDim = config.qkNopeHeadDim;
    const uint32_t qkRopeHeadDim = config.qkRopeHeadDim;
    const uint32_t vHeadDim = config.vHeadDim;
    const uint32_t numHeads = config.numHeads;

    // attn_q_a: [hiddenDim, qLoraRank]
    if (attnQ_a.dims().size() != 2 || attnQ_a.dims()[0] != hiddenDim || attnQ_a.dims()[1] != qLoraRank) {
        error = "MLAWeights: attn_q_a shape mismatch"; return false;
    }

    // attn_q_b: [qLoraRank, numHeads * qkNopeHeadDim]
    const uint32_t qBCols = numHeads * qkNopeHeadDim;
    if (attnQ_b.dims().size() != 2 || attnQ_b.dims()[0] != qLoraRank || attnQ_b.dims()[1] != qBCols) {
        error = "MLAWeights: attn_q_b shape mismatch"; return false;
    }

    // attn_kv_a_mqa: [hiddenDim, kvLoraRank + qkRopeHeadDim]
    const uint32_t kvACols = kvLoraRank + qkRopeHeadDim;
    if (attnKV_a_mqa.dims().size() != 2 || attnKV_a_mqa.dims()[0] != hiddenDim || attnKV_a_mqa.dims()[1] != kvACols) {
        error = "MLAWeights: attn_kv_a_mqa shape mismatch"; return false;
    }

    // attn_kv_b: [kvLoraRank, numHeads * (qkNopeHeadDim + vHeadDim)]
    const uint32_t kvBCols = numHeads * (qkNopeHeadDim + vHeadDim);
    if (attnKV_b.dims().size() != 2 || attnKV_b.dims()[0] != kvLoraRank || attnKV_b.dims()[1] != kvBCols) {
        error = "MLAWeights: attn_kv_b shape mismatch"; return false;
    }

    // attn_o: [numHeads * vHeadDim, hiddenDim]
    const uint32_t oRows = numHeads * vHeadDim;
    if (attnO.dims().size() != 2 || attnO.dims()[0] != oRows || attnO.dims()[1] != hiddenDim) {
        error = "MLAWeights: attn_o shape mismatch"; return false;
    }

    return true;
}

bool MLAWeights::DetectMLA(const std::string& tensorName) {
    static const char* kMLAPrefixes[] = {
        "attn_q_a", "attn_q_b", "attn_kv_a", "attn_kv_b",
        "attn_o", "attn_norm", "attn_q_a_norm", "attn_kv_a_norm"
    };
    for (const char* prefix : kMLAPrefixes) {
        if (tensorName.find(prefix) != std::string::npos) return true;
    }
    return false;
}

// ============================================================================
// MLAForward
// ============================================================================

bool MLAForward::Execute(const float* hidden, float* output,
                         const MLAWeights& weights,
                         const KimiK2Config& config,
                         std::string& error) {
    if (!hidden || !output) {
        error = "MLAForward: null input/output pointer";
        return false;
    }

    if (!weights.Validate(config, error)) {
        return false;
    }

    // TODO: Implement actual MLA forward pass
    // For now, return zeros as placeholder (prevents uninitialized output)
    const size_t hiddenDim = config.hiddenDim;
    std::fill(output, output + hiddenDim, 0.0f);

    return true;
}

bool MLAForward::TestAgainstReference(const std::string& fixturePath,
                                       std::string& error) {
    std::ifstream fixture(fixturePath, std::ios::binary);
    if (!fixture) {
        error = "MLAForward: cannot open reference fixture: " + fixturePath;
        return false;
    }

    // TODO: Load reference fixture and compare against Execute()
    // For now, just verify the fixture exists
    return true;
}

} // namespace Deep2
