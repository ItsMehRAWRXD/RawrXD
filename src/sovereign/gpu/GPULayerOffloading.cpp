// ============================================================================
// GPULayerOffloading.cpp - GPU Layer Offloading Implementation
// ============================================================================

#include "GPULayerOffloading.hpp"
#include <algorithm>
#include <iostream>

namespace Sovereign {

GPULayerOffloading::GPULayerOffloading() = default;
GPULayerOffloading::~GPULayerOffloading() { Shutdown(); }

bool GPULayerOffloading::Initialize(const LayerOffloadConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

void GPULayerOffloading::Shutdown() { assignments_.clear(); initialized_ = false; }

bool GPULayerOffloading::AssignLayers(const std::vector<uint64_t>& layerSizes) {
    std::lock_guard<std::mutex> lock(mutex_);
    assignments_.clear();
    gpuMemoryUsed_ = 0;
    
    for (uint32_t i = 0; i < layerSizes.size(); ++i) {
        LayerAssignment la;
        la.layerIndex = i;
        la.weightSize = layerSizes[i];
        la.onGPU = false;
        la.isTransferred = false;
        assignments_.push_back(la);
    }
    
    // Assign first N layers to GPU based on budget
    for (uint32_t i = 0; i < config_.gpuLayers && i < assignments_.size(); ++i) {
        if (gpuMemoryUsed_ + assignments_[i].weightSize <= config_.gpuMemoryBudget) {
            assignments_[i].onGPU = true;
            gpuMemoryUsed_ += assignments_[i].weightSize;
            gpuLRU_.push_back(i);
        }
    }
    
    return true;
}

bool GPULayerOffloading::OffloadLayer(uint32_t layerIndex) {
    if (layerIndex >= assignments_.size()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& la = assignments_[layerIndex];
    if (la.onGPU) return true;
    
    // Evict if needed
    while (gpuMemoryUsed_ + la.weightSize > config_.gpuMemoryBudget) {
        uint32_t victim = FindEvictionVictim();
        if (victim == UINT32_MAX) return false;
        EvictLayer(victim);
    }
    
    la.onGPU = true;
    la.isTransferred = true;
    gpuMemoryUsed_ += la.weightSize;
    UpdateLRU(layerIndex);
    stats_.totalTransfers++;
    stats_.totalBytesTransferred += la.weightSize;
    
    return true;
}

bool GPULayerOffloading::PrefetchLayer(uint32_t layerIndex) {
    return OffloadLayer(layerIndex);
}

bool GPULayerOffloading::EvictLayer(uint32_t layerIndex) {
    if (layerIndex >= assignments_.size()) return false;
    auto& la = assignments_[layerIndex];
    if (!la.onGPU) return false;
    
    la.onGPU = false;
    gpuMemoryUsed_ -= la.weightSize;
    gpuLRU_.erase(std::remove(gpuLRU_.begin(), gpuLRU_.end(), layerIndex), gpuLRU_.end());
    return true;
}

bool GPULayerOffloading::EnsureLayerOnGPU(uint32_t layerIndex) {
    if (layerIndex >= assignments_.size()) return false;
    if (assignments_[layerIndex].onGPU) {
        stats_.gpuCacheHits++;
        UpdateLRU(layerIndex);
        return true;
    }
    stats_.gpuCacheMisses++;
    return OffloadLayer(layerIndex);
}

uint32_t GPULayerOffloading::GetGPULayerCount() const {
    return std::count_if(assignments_.begin(), assignments_.end(), [](const auto& la) { return la.onGPU; });
}

uint32_t GPULayerOffloading::GetCPULayerCount() const {
    return assignments_.size() - GetGPULayerCount();
}

void GPULayerOffloading::UpdateLRU(uint32_t layerIndex) {
    gpuLRU_.erase(std::remove(gpuLRU_.begin(), gpuLRU_.end(), layerIndex), gpuLRU_.end());
    gpuLRU_.push_back(layerIndex);
}

uint32_t GPULayerOffloading::FindEvictionVictim() const {
    if (gpuLRU_.empty()) return UINT32_MAX;
    return gpuLRU_.front();
}

} // namespace Sovereign
