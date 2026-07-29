// ============================================================================
// TensorHop.cpp - DMA scheduler implementation
// ============================================================================

#include "TensorHop.hpp"
#include <cstring>
#include <chrono>
#include <algorithm>

namespace Deep2 {

// ============================================================================
// DMA Scheduler Implementation
// ============================================================================

DMAScheduler::DMAScheduler() : running_(false), maxConcurrent_(4) {
    std::memset(&stats_, 0, sizeof(stats_));
}

DMAScheduler::~DMAScheduler() {
    if (running_) {
        WaitAll();
    }
}

bool DMAScheduler::Initialize(size_t maxConcurrentTransfers) {
    maxConcurrent_ = maxConcurrentTransfers;
    running_ = true;
    return true;
}

void DMAScheduler::QueueHop(const TensorHop& hop) {
    pendingQueue_.push_back(hop);
    stats_.hopsQueued++;
}

void DMAScheduler::ExecutePending() {
    // Move pending to active up to max concurrent
    while (activeQueue_.size() < maxConcurrent_ && !pendingQueue_.empty()) {
        // Sort by priority (higher first)
        auto it = std::max_element(pendingQueue_.begin(), pendingQueue_.end(),
            [](const TensorHop& a, const TensorHop& b) {
                return a.priority < b.priority;
            });
        
        if (it != pendingQueue_.end()) {
            activeQueue_.push_back(*it);
            pendingQueue_.erase(it);
        }
    }
    
    // Execute active hops
    for (auto it = activeQueue_.begin(); it != activeQueue_.end();) {
        ExecuteHop(*it);
        stats_.hopsCompleted++;
        stats_.bytesTransferred += it->bytes;
        it = activeQueue_.erase(it);
    }
}

void DMAScheduler::ExecuteHop(const TensorHop& hop) {
    auto start = std::chrono::high_resolution_clock::now();
    
<<<<<<< HEAD
    // DMA transfer implementation
    // Supports multiple backends: CPU memcpy, GPU async copy, OS-specific APIs
    // Dual GPU: hop.deviceId specifies target GPU (0 = CPU, 1+ = GPU index)

    volatile char* dest = (char*)hop.destAddr;
    const volatile char* src = (const char*)hop.sourceAddr;
    
    // Perform the transfer based on device type
    if (hop.deviceId == 0) {
        // CPU-to-CPU: standard memcpy
        // TODO: Add Windows DirectStorage or Linux io_uring for async disk I/O
        std::memcpy((void*)dest, (const void*)src, hop.bytes);
    } else {
        // GPU transfer: deviceId 1+ maps to GPU index
        // TODO: Implement cuMemcpyAsync for CUDA or vkCmdCopyBuffer for Vulkan
        // For now, fall back to CPU copy (GPU memory is host-visible)
        std::memcpy((void*)dest, (const void*)src, hop.bytes);
    }
=======
    // Model DMA transfer (replace with actual DMA API)
    // On Windows: could use CopyFileEx with callbacks or DirectStorage
    // On Linux: io_uring or pread

    // Current implementation: simple memory copy
    volatile char* dest = (char*)hop.destAddr;
    const volatile char* src = (const char*)hop.sourceAddr;
    
    // In real implementation, this would be:
    // - DirectStorage API on Windows
    // - cuMemcpyAsync for GPU
    // - io_uring for async disk I/O
>>>>>>> 23355fea2b0ee1997bf565eb381234bb6364d743
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsedMs = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start).count() / 1000.0;
    
    // Update average
    stats_.avgTransferTimeMs = (stats_.avgTransferTimeMs * (stats_.hopsCompleted - 1) + elapsedMs)
                               / stats_.hopsCompleted;
}

void DMAScheduler::WaitAll() {
    while (!pendingQueue_.empty() || !activeQueue_.empty()) {
        ExecutePending();
    }
}

bool DMAScheduler::IsComplete(uint32_t layerIdx, uint32_t expertIdx) {
    // Check if expert is in active or pending queues
    for (const auto& hop : pendingQueue_) {
        if (hop.layerIdx == layerIdx && hop.expertIdx == expertIdx) {
            return false;
        }
    }
    for (const auto& hop : activeQueue_) {
        if (hop.layerIdx == layerIdx && hop.expertIdx == expertIdx) {
            return false;
        }
    }
    return true;
}

void DMAScheduler::CancelLayer(uint32_t layerIdx) {
    pendingQueue_.erase(
        std::remove_if(pendingQueue_.begin(), pendingQueue_.end(),
            [layerIdx](const TensorHop& hop) { return hop.layerIdx == layerIdx; }),
        pendingQueue_.end()
    );
}

DMAScheduler::Stats DMAScheduler::GetStats() const {
    return stats_;
}

// ============================================================================
// Prefetch Planner Implementation
// ============================================================================

std::vector<TensorHop> PrefetchPlanner::PlanPrefetches(
    const uint32_t* expertIds,
    uint32_t numExperts,
    uint32_t currentLayer,
    uint32_t totalLayers,
    uint64_t baseWeightAddr,
    size_t expertSizeBytes
) {
    std::vector<TensorHop> hops;
    hops.reserve(numExperts);
    
    for (uint32_t i = 0; i < numExperts; ++i) {
        TensorHop hop;
        hop.layerIdx = currentLayer;
        hop.expertIdx = expertIds[i];
        hop.bytes = expertSizeBytes;
        hop.priority = 100 - i;  // First experts = higher priority
        hop.isPinned = (i < 2); // Pin first 2 experts
        
        // Calculate source address
        hop.sourceAddr = baseWeightAddr + 
            (currentLayer * 256 + expertIds[i]) * expertSizeBytes;
        
        hops.push_back(hop);
    }
    
    return hops;
}

std::vector<uint32_t> PrefetchPlanner::PredictNextLayer(
    const uint32_t* currentExperts,
    uint32_t numExperts,
    uint32_t patternHistory
) {
    std::vector<uint32_t> predictions;
    
    // Simple prediction: same experts likely next
    // More sophisticated: use pattern history
    for (uint32_t i = 0; i < numExperts; ++i) {
        // Add some variation based on history
        uint32_t expert = currentExperts[i];
        if (patternHistory & (1 << i)) {
            expert = (expert + 1) % 256;  // Slight variation
        }
        predictions.push_back(expert);
    }
    
    return predictions;
}

} // namespace Deep2
