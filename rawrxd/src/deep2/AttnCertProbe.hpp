#pragma once
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <mutex>
#include <chrono>

namespace rawrxd::deep2 {

// ───────────────────────────────────────────────────────────────
// Attention certification probe result
// ───────────────────────────────────────────────────────────────
struct AttnCertResult {
    uint64_t layer_id = 0;
    uint64_t head_id = 0;
    float max_attention = 0.0f;
    float mean_attention = 0.0f;
    bool anomalous = false;
    std::string anomaly_type;
    std::chrono::steady_clock::time_point timestamp;
};

// ───────────────────────────────────────────────────────────────
// Attention certification probe — validates attention patterns
// ───────────────────────────────────────────────────────────────
class AttnCertProbe {
public:
    AttnCertProbe();
    ~AttnCertProbe();

    // Configuration
    bool Configure(float max_threshold, float mean_threshold);
    void SetLayerRange(uint64_t start_layer, uint64_t end_layer);

    // Analysis
    AttnCertResult ProbeLayer(uint64_t layer_id, uint64_t head_id,
                                std::span<const float> attention_weights);
    std::vector<AttnCertResult> ProbeAllLayers(std::span<const float> attention_tensor,
                                                   uint64_t num_layers, uint64_t num_heads,
                                                   uint64_t seq_len);

    // Stats
    uint64_t GetTotalProbed() const;
    uint64_t GetAnomalyCount() const;
    void ResetStats();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::deep2
