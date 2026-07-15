#pragma once

#include <vector>
#include <cstddef>
#include <string>

namespace rawrxd {
namespace validation {

/**
 * Captured state from a single transformer layer
 */
struct LayerSnapshot {
    int layer_index;
    std::vector<float> hidden_state;
    std::vector<float> attention_scores;
    std::vector<float> ffn_output;
    
    size_t hidden_dim;
    size_t num_heads;
    size_t seq_len;
    
    std::string toString() const {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "Layer %d: hidden=%zux%zu, attn=%zux%zux%zu",
            layer_index,
            seq_len, hidden_dim,
            num_heads, seq_len, seq_len);
        return std::string(buf);
    }
};

/**
 * Collection of snapshots from all layers
 */
class HiddenStateCapture {
public:
    void captureLayer(int layer_idx, 
                      const float* hidden, size_t hidden_size,
                      const float* attn, size_t attn_size,
                      const float* ffn, size_t ffn_size);
    
    const std::vector<LayerSnapshot>& getSnapshots() const { return snapshots_; }
    
    void clear() { snapshots_.clear(); }
    
    bool saveToFile(const char* path) const;
    bool loadFromFile(const char* path);

private:
    std::vector<LayerSnapshot> snapshots_;
};

} // namespace validation
} // namespace rawrxd
