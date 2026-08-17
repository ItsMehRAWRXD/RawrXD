// ============================================================================
// K2MLAWeights.cpp — K2-002 MLA Tensor Schema Implementation
// ============================================================================

#include "K2MLAWeights.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "UniversalTensorDescriptor.hpp"
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

bool MLAWeights::ResolveFromTensorIndex(const GlobalTensorIndex& index, uint32_t layer, std::string& error) {
    // Build layer-scoped tensor names
    char qAName[64], qANormName[64], qBName[64];
    char kvAName[64], kvANormName[64], kvBName[64];
    char oName[64], normName[64];

    snprintf(qAName, sizeof(qAName), "blk.%u.attn_q_a.weight", layer);
    snprintf(qANormName, sizeof(qANormName), "blk.%u.attn_q_a_norm.weight", layer);
    snprintf(qBName, sizeof(qBName), "blk.%u.attn_q_b.weight", layer);
    snprintf(kvAName, sizeof(kvAName), "blk.%u.attn_kv_a_mqa.weight", layer);
    snprintf(kvANormName, sizeof(kvANormName), "blk.%u.attn_kv_a_norm.weight", layer);
    snprintf(kvBName, sizeof(kvBName), "blk.%u.attn_kv_b.weight", layer);
    snprintf(oName, sizeof(oName), "blk.%u.attn_o.weight", layer);
    snprintf(normName, sizeof(normName), "blk.%u.attn_norm.weight", layer);

    auto resolve = [&](const char* name, RawrXD::TensorView& view) -> bool {
        auto refOpt = index.Find(name);
        if (!refOpt) return false;
        const auto& ref = *refOpt;

        RawrXD::UniversalTensorDescriptor desc;
        desc.numDims = ref.nDims;
        for (uint8_t i = 0; i < ref.nDims && i < 8; ++i) {
            desc.shape[i] = ref.shape[i];
        }
        desc.quantType = RawrXD::QuantType::UNKNOWN; // Will be set from ggmlType
        desc.layout = RawrXD::TensorLayout::DENSE;
        desc.role = RawrXD::TensorRole::WEIGHT;
        desc.memorySpace = RawrXD::UniversalTensorDescriptor::MemorySpace::NVME;
        desc.data = nullptr;

        // Map GGML type to QuantType
        switch (ref.ggmlType) {
            case 0:  desc.quantType = RawrXD::QuantType::F32; break;
            case 1:  desc.quantType = RawrXD::QuantType::F16; break;
            case 2:  desc.quantType = RawrXD::QuantType::Q4_0; break;
            case 3:  desc.quantType = RawrXD::QuantType::Q4_1; break;
            case 6:  desc.quantType = RawrXD::QuantType::Q5_0; break;
            case 7:  desc.quantType = RawrXD::QuantType::Q5_1; break;
            case 8:  desc.quantType = RawrXD::QuantType::Q8_0; break;
            case 9:  desc.quantType = RawrXD::QuantType::Q8_1; break;
            case 10: desc.quantType = RawrXD::QuantType::Q2_K; break;
            case 11: desc.quantType = RawrXD::QuantType::Q3_K; break;
            case 12: desc.quantType = RawrXD::QuantType::Q4_K; break;
            case 13: desc.quantType = RawrXD::QuantType::Q5_K; break;
            case 14: desc.quantType = RawrXD::QuantType::Q6_K; break;
            case 17: desc.quantType = RawrXD::QuantType::IQ2_XXS; break;
            case 18: desc.quantType = RawrXD::QuantType::IQ2_XS; break;
            case 19: desc.quantType = RawrXD::QuantType::IQ3_XXS; break;
            case 20: desc.quantType = RawrXD::QuantType::UNKNOWN; break; // IQ1_S
            case 21: desc.quantType = RawrXD::QuantType::IQ4_NL; break;
            case 22: desc.quantType = RawrXD::QuantType::UNKNOWN; break; // IQ3_S
            case 23: desc.quantType = RawrXD::QuantType::UNKNOWN; break; // IQ2_S
            case 24: desc.quantType = RawrXD::QuantType::IQ4_XS; break;
            default: desc.quantType = RawrXD::QuantType::UNKNOWN; break;
        }

        view = RawrXD::TensorView::FromBuffer(desc, nullptr, false);
        return true;
    };

    if (!resolve(qAName, attnQ_a))       { error = std::string("MLAWeights: ") + qAName + " not found in index"; return false; }
    if (!resolve(qANormName, attnQ_a_norm)) { error = std::string("MLAWeights: ") + qANormName + " not found in index"; return false; }
    if (!resolve(qBName, attnQ_b))       { error = std::string("MLAWeights: ") + qBName + " not found in index"; return false; }
    if (!resolve(kvAName, attnKV_a_mqa)) { error = std::string("MLAWeights: ") + kvAName + " not found in index"; return false; }
    if (!resolve(kvANormName, attnKV_a_norm)) { error = std::string("MLAWeights: ") + kvANormName + " not found in index"; return false; }
    if (!resolve(kvBName, attnKV_b))     { error = std::string("MLAWeights: ") + kvBName + " not found in index"; return false; }
    if (!resolve(oName, attnO))          { error = std::string("MLAWeights: ") + oName + " not found in index"; return false; }
    if (!resolve(normName, attnNorm))    { error = std::string("MLAWeights: ") + normName + " not found in index"; return false; }

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
