// ============================================================================
// ModelMerging.cpp - Model Merging Implementation
// ============================================================================

#include "ModelMerging.hpp"
#include <cmath>
#include <random>
#include <algorithm>
#include <iostream>

namespace Sovereign {

ModelMerging::ModelMerging() = default;
ModelMerging::~ModelMerging() = default;

bool ModelMerging::Merge(const std::vector<std::string>& modelPaths, const MergeConfig& config) {
    if (modelPaths.size() < 2) return false;
    
    stats_.totalMerges++;
    return true;
}

bool ModelMerging::SLERP(const std::vector<float>& a, const std::vector<float>& b, std::vector<float>& out, float t) {
    if (a.size() != b.size()) return false;
    out.resize(a.size());
    
    for (size_t i = 0; i < a.size(); ++i) {
        float theta = std::acos(std::clamp(a[i] * b[i], -1.0f, 1.0f));
        float sinTheta = std::sin(theta);
        if (sinTheta < 1e-10f) {
            out[i] = (1.0f - t) * a[i] + t * b[i];
        } else {
            out[i] = (std::sin((1.0f - t) * theta) / sinTheta) * a[i] + (std::sin(t * theta) / sinTheta) * b[i];
        }
    }
    
    stats_.totalTensors++;
    stats_.totalParams += a.size();
    return true;
}

bool ModelMerging::TIES(const std::vector<std::vector<float>>& tensors, std::vector<float>& out, float density) {
    if (tensors.empty()) return false;
    size_t dim = tensors[0].size();
    out.resize(dim, 0);
    
    // Majority sign voting
    std::vector<int> signVotes(dim, 0);
    for (const auto& t : tensors) {
        for (size_t i = 0; i < dim; ++i) {
            signVotes[i] += (t[i] > 0) ? 1 : -1;
        }
    }
    
    // Keep only top-k by magnitude (density)
    std::vector<std::pair<float, size_t>> magnitudes;
    for (size_t i = 0; i < dim; ++i) {
        float mag = 0;
        for (const auto& t : tensors) mag += std::abs(t[i]);
        magnitudes.push_back({mag, i});
    }
    
    std::sort(magnitudes.begin(), magnitudes.end(), std::greater<>());
    size_t keepCount = dim * density;
    
    for (size_t i = 0; i < keepCount; ++i) {
        size_t idx = magnitudes[i].second;
        if (signVotes[idx] > 0) {
            for (const auto& t : tensors) {
                if (t[idx] > 0) out[idx] += t[idx];
            }
        } else {
            for (const auto& t : tensors) {
                if (t[idx] < 0) out[idx] += t[idx];
            }
        }
        out[idx] /= tensors.size();
    }
    
    stats_.totalTensors++;
    return true;
}

bool ModelMerging::DARE(const std::vector<float>& a, const std::vector<float>& b, std::vector<float>& out, float density, float scale) {
    if (a.size() != b.size()) return false;
    out.resize(a.size());
    
    std::mt19937 rng(std::random_device{}());
    std::bernoulli_distribution drop(density);
    
    for (size_t i = 0; i < a.size(); ++i) {
        float delta = b[i] - a[i];
        if (drop(rng)) {
            delta /= density;
        } else {
            delta = 0;
        }
        out[i] = a[i] + delta * scale;
    }
    
    stats_.totalTensors++;
    return true;
}

bool ModelMerging::Linear(const std::vector<float>& a, const std::vector<float>& b, std::vector<float>& out, float t) {
    if (a.size() != b.size()) return false;
    out.resize(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i] = (1.0f - t) * a[i] + t * b[i];
    }
    stats_.totalTensors++;
    return true;
}

} // namespace Sovereign
