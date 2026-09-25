#include "AttnCertProbe.hpp"
#include <algorithm>
#include <numeric>
#include <math>

namespace rawrxd::deep2 {

class AttnCertProbe::Impl {
public:
    mutable std::mutex mutex_;
    float max_threshold_ = 0.95f;
    float mean_threshold_ = 0.8f;
    uint64_t start_layer_ = 0;
    uint64_t end_layer_ = UINT64_MAX;
    uint64_t total_probed_ = 0;
    uint64_t anomaly_count_ = 0;
};

AttnCertProbe::AttnCertProbe() : impl_(std::make_unique<Impl>()) {}
AttnCertProbe::~AttnCertProbe() = default;

bool AttnCertProbe::Configure(float max_threshold, float mean_threshold) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->max_threshold_ = max_threshold;
    impl_->mean_threshold_ = mean_threshold;
    return true;
}

void AttnCertProbe::SetLayerRange(uint64_t start_layer, uint64_t end_layer) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->start_layer_ = start_layer;
    impl_->end_layer_ = end_layer;
}

AttnCertResult AttnCertProbe::ProbeLayer(uint64_t layer_id, uint64_t head_id,
                                            std::span<const float> attention_weights) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    AttnCertResult result;
    result.layer_id = layer_id;
    result.head_id = head_id;
    result.timestamp = std::chrono::steady_clock::now();

    if (attention_weights.empty()) return result;

    float max_val = *std::max_element(attention_weights.begin(), attention_weights.end());
    float mean_val = std::accumulate(attention_weights.begin(), attention_weights.end(), 0.0f) / attention_weights.size();

    result.max_attention = max_val;
    result.mean_attention = mean_val;

    if (max_val > impl_->max_threshold_ || mean_val > impl_->mean_threshold_) {
        result.anomalous = true;
        result.anomaly_type = max_val > impl_->max_threshold_ ? "max_attention_exceeded" : "mean_attention_exceeded";
        impl_->anomaly_count_++;
    }
    impl_->total_probed_++;
    return result;
}

std::vector<AttnCertResult> AttnCertProbe::ProbeAllLayers(std::span<const float> attention_tensor,
                                                           uint64_t num_layers, uint64_t num_heads,
                                                           uint64_t seq_len) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<AttnCertResult> results;
    size_t weights_per_head = seq_len * seq_len;
    size_t total_heads = num_layers * num_heads;
    if (attention_tensor.size() < total_heads * weights_per_head) return results;

    for (uint64_t layer = 0; layer < num_layers; ++layer) {
        if (layer < impl_->start_layer_ || layer > impl_->end_layer_) continue;
        for (uint64_t head = 0; head < num_heads; ++head) {
            size_t offset = (layer * num_heads + head) * weights_per_head;
            auto span = std::span<const float>(attention_tensor.data() + offset, weights_per_head);
            results.push_back(ProbeLayer(layer, head, span));
        }
    }
    return results;
}

uint64_t AttnCertProbe::GetTotalProbed() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->total_probed_;
}

uint64_t AttnCertProbe::GetAnomalyCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->anomaly_count_;
}

void AttnCertProbe::ResetStats() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->total_probed_ = 0;
    impl_->anomaly_count_ = 0;
}

} // namespace rawrxd::deep2
