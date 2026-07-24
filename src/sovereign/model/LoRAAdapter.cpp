// ============================================================================
// LoRAAdapter.cpp - LoRA/QLoRA Adapter Inference Implementation
// ============================================================================

#include "LoRAAdapter.hpp"
#include <fstream>
#include <cstring>
#include <iostream>

namespace Sovereign {

LoRAAdapter::LoRAAdapter() = default;
LoRAAdapter::~LoRAAdapter() { Unload(); }

bool LoRAAdapter::Load(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    
    uint64_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    for (uint64_t i = 0; i < count; ++i) {
        LoRAWeight w;
        uint32_t nameLen;
        file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        w.name.resize(nameLen);
        file.read(w.name.data(), nameLen);
        file.read(reinterpret_cast<char*>(&w.inDim), sizeof(w.inDim));
        file.read(reinterpret_cast<char*>(&w.outDim), sizeof(w.outDim));
        file.read(reinterpret_cast<char*>(&w.r), sizeof(w.r));
        file.read(reinterpret_cast<char*>(&w.alpha), sizeof(w.alpha));
        
        w.loraA.resize(w.inDim * w.r);
        w.loraB.resize(w.r * w.outDim);
        file.read(reinterpret_cast<char*>(w.loraA.data()), w.loraA.size() * sizeof(float));
        file.read(reinterpret_cast<char*>(w.loraB.data()), w.loraB.size() * sizeof(float));
        
        weights_.push_back(w);
    }
    return true;
}

bool LoRAAdapter::Apply(const std::string& layerName, const float* input, float* output, uint64_t dim) {
    for (const auto& w : weights_) {
        if (w.name != layerName) continue;
        
        float lrScale = w.alpha / w.r * scale_;
        
        // h = x + (x @ A) @ B * scale
        std::vector<float> intermediate(w.r, 0);
        for (uint64_t i = 0; i < w.r; ++i) {
            for (uint64_t j = 0; j < dim; ++j) {
                intermediate[i] += input[j] * w.loraA[j * w.r + i];
            }
        }
        
        for (uint64_t i = 0; i < dim; ++i) {
            float sum = 0;
            for (uint64_t j = 0; j < w.r; ++j) {
                sum += intermediate[j] * w.loraB[j * dim + i];
            }
            output[i] += sum * lrScale;
        }
        return true;
    }
    return false;
}

bool LoRAAdapter::ApplyToAll(std::vector<float>& hiddenStates, uint64_t dim) {
    for (size_t i = 0; i < hiddenStates.size() / dim; ++i) {
        for (const auto& w : weights_) {
            Apply(w.name, hiddenStates.data() + i * dim, hiddenStates.data() + i * dim, dim);
        }
    }
    return true;
}

void LoRAAdapter::Unload() {
    weights_.clear();
}

} // namespace Sovereign
