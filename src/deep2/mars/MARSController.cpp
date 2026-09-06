// ============================================================================
// MARSController.cpp - Memory Allocation + Routing System
// ============================================================================

#include "MARSController.hpp"
#include <cstdio>
#include <cmath>
#include <algorithm>

namespace Deep2 {
namespace MARS {

// ============================================================================
// TensorGraph
// ============================================================================
void TensorGraph::AddNode(const TensorGraphNode& node) {
    auto ptr = std::make_unique<TensorGraphNode>(node);
    idMap_[node.tensorId] = ptr.get();
    nodes_.push_back(std::move(ptr));
}

TensorGraphNode* TensorGraph::GetNode(uint64_t tensorId) {
    auto it = idMap_.find(tensorId);
    if (it != idMap_.end()) return it->second;
    return nullptr;
}

const TensorGraphNode* TensorGraph::GetNode(uint64_t tensorId) const {
    auto it = idMap_.find(tensorId);
    if (it != idMap_.end()) return it->second;
    return nullptr;
}

size_t TensorGraph::GetNodeCount() const {
    return nodes_.size();
}

std::vector<TensorGraphNode*> TensorGraph::GetNodesOnGPU(int gpu) {
    std::vector<TensorGraphNode*> result;
    for (auto& node : nodes_) {
        if (node->gpu == gpu) {
            result.push_back(node.get());
        }
    }
    return result;
}

std::vector<TensorGraphNode*> TensorGraph::GetNodesByLayer(int layer) {
    std::vector<TensorGraphNode*> result;
    for (auto& node : nodes_) {
        if (node->producerLayer == layer ||
            std::find(node->consumerLayers.begin(), node->consumerLayers.end(), layer) != node->consumerLayers.end()) {
            result.push_back(node.get());
        }
    }
    return result;
}

// ============================================================================
// MARSController
// ============================================================================
MARSController::MARSController() = default;
MARSController::~MARSController() {
    if (initialized_) {
        Shutdown();
    }
}

// ============================================================================
// Lifecycle
// ============================================================================
bool MARSController::Initialize(size_t gpu0Bytes, size_t gpu1Bytes) {
    if (initialized_) return true;

    printf("[MARS] Initializing controller...\n");

    if (!vramManager_.Initialize(gpu0Bytes, gpu1Bytes)) {
        printf("[MARS] ERROR: Failed to initialize VRAM manager\n");
        return false;
    }

    tensorHotpatch_.AttachVRAMManager(&vramManager_);

    if (!dualGPUBackend_.Initialize()) {
        printf("[MARS] WARNING: Dual GPU backend init failed (CPU fallback)\n");
    }

    initialized_ = true;
    printf("[MARS] Controller ready: GPU0=%.2f GB, GPU1=%.2f GB\n",
           gpu0Bytes / (1024.0 * 1024.0 * 1024.0),
           gpu1Bytes / (1024.0 * 1024.0 * 1024.0));
    return true;
}

void MARSController::Shutdown() {
    if (!initialized_) return;

    printf("[MARS] Shutting down...\n");
    dualGPUBackend_.Shutdown();
    vramManager_.Shutdown();
    initialized_ = false;
    printf("[MARS] Shutdown complete\n");
}

// ============================================================================
// Tensor Placement
// ============================================================================
int MARSController::ResolvePlacement(size_t bytes, float priority, bool preferLowLatency) {
    return vramManager_.SelectBestGPU(bytes, priority, preferLowLatency);
}

VRAMLease* MARSController::PlaceTensor(
    uint64_t tensorId,
    const std::string& name,
    size_t bytes,
    float priority,
    bool hotpatchable,
    int producerLayer,
    bool isWeight) {

    VRAMLease* lease = vramManager_.Allocate(tensorId, name, bytes, priority, hotpatchable);
    if (lease) {
        if (!hotpatchable) {
            lease->pinned = true;
        }
        TensorGraphNode node;
        node.tensorId = tensorId;
        node.name = name;
        node.bytes = bytes;
        node.gpu = lease->currentGPU;
        node.priority = priority;
        node.producerLayer = producerLayer;
        node.isWeight = isWeight;
        tensorGraph_.AddNode(node);
    }
    return lease;
}

// ============================================================================
// Rebalancing
// ============================================================================
void MARSController::Rebalance() {
    if (!initialized_) return;

    auto dp = vramManager_.GetDynamicParity();
    size_t used0 = vramManager_.GetUsedVRAM(0);
    size_t used1 = vramManager_.GetUsedVRAM(1);
    size_t total0 = vramManager_.GetTotalVRAM(0);
    size_t total1 = vramManager_.GetTotalVRAM(1);

    if (total0 == 0 && total1 == 0) return;

    float ratio0 = total0 > 0 ? (float)used0 / total0 : 0.0f;
    float ratio1 = total1 > 0 ? (float)used1 / total1 : 0.0f;

    const float threshold = 0.15f;
    if (std::abs(ratio0 - ratio1) < threshold) {
        return; // Balanced enough
    }

    printf("[MARS] Rebalancing: GPU0 %.1f%% vs GPU1 %.1f%%\n",
           ratio0 * 100.0f, ratio1 * 100.0f);

    // Move some load from more-loaded to less-loaded
    int fromGPU = (ratio0 > ratio1) ? 0 : 1;
    int toGPU   = (fromGPU == 0) ? 1 : 0;

    // In a full implementation, we would iterate leases and migrate
    // For now, trigger TensorHotpatch rebalance
    tensorHotpatch_.Rebalance();

    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.rebalanceCount++;
    }
}

void MARSController::RebalanceGraph(TensorGraph& graph) {
    if (!initialized_) return;

    size_t used0 = vramManager_.GetUsedVRAM(0);
    size_t used1 = vramManager_.GetUsedVRAM(1);
    size_t total0 = vramManager_.GetTotalVRAM(0);
    size_t total1 = vramManager_.GetTotalVRAM(1);
    if (total0 == 0 && total1 == 0) return;

    float ratio0 = total0 > 0 ? (float)used0 / total0 : 0.0f;
    float ratio1 = total1 > 0 ? (float)used1 / total1 : 0.0f;
    if (std::abs(ratio0 - ratio1) < 0.15f) return;

    int fromGPU = (ratio0 > ratio1) ? 0 : 1;
    int toGPU = 1 - fromGPU;

    auto nodes = graph.GetNodesOnGPU(fromGPU);
    std::sort(nodes.begin(), nodes.end(), [](const TensorGraphNode* a, const TensorGraphNode* b) {
        return (a ? a->priority : 0.0f) < (b ? b->priority : 0.0f);
    });

    for (TensorGraphNode* node : nodes) {
        used0 = vramManager_.GetUsedVRAM(0);
        used1 = vramManager_.GetUsedVRAM(1);
        ratio0 = total0 > 0 ? (float)used0 / total0 : 0.0f;
        ratio1 = total1 > 0 ? (float)used1 / total1 : 0.0f;
        if (std::abs(ratio0 - ratio1) < 0.15f) break;
        if (!node) continue;

        VRAMLease* lease = vramManager_.GetLease(node->tensorId);
        if (!lease || !lease->hotpatchable || lease->pinned) continue;
        if (vramManager_.GetFreeVRAM(toGPU) < lease->bytes) continue;

        if (tensorHotpatch_.Redirect(lease, toGPU) == HotpatchResult::OK) {
            node->gpu = toGPU;
        }
    }
}

void MARSController::OnVRAMPressure(int gpu) {
    printf("[MARS] VRAM pressure on GPU %d\n", gpu);

    // Evict low-priority tensors
    tensorHotpatch_.EvictLowPriority(gpu, 2.0f);

    // Try to migrate to other GPU
    int otherGPU = (gpu == 0) ? 1 : 0;
    if (vramManager_.GetFreeVRAM(otherGPU) > 0) {
        // Migrate some tensors
        // (requires lease iteration)
    }

    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.pressureEvents++;
    }
}

void MARSController::OnGPUIdle(int gpu) {
    printf("[MARS] GPU %d idle - checking for rebalance opportunities\n", gpu);

    // Could prefetch tensors or rebalance
    Rebalance();

    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.idleEvents++;
    }
}

// ============================================================================
// Reverse Recovery
// ============================================================================
bool MARSController::HandleTensorFault(uint64_t tensorId) {
    printf("[MARS] Handling tensor fault for %llu\n", (unsigned long long)tensorId);

    auto result = tensorHotpatch_.ReverseRecover(tensorId);
    bool ok = (result == HotpatchResult::OK || result == HotpatchResult::NO_VRAM);

    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.faultRecoveries++;
    }

    return ok;
}

bool MARSController::HandleGPUFailure(int gpu) {
    printf("[MARS] Handling GPU %d failure\n", gpu);

    auto result = tensorHotpatch_.HandleGPUFailure(gpu);
    bool ok = (result == HotpatchResult::OK);

    // Mark backend GPU as failed
    dualGPUBackend_.MarkGPUFailed(gpu);

    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.gpuFailovers++;
    }

    return ok;
}

// ============================================================================
// Inference Integration
// ============================================================================
bool MARSController::PrepareLayer(int layerIndex, int targetGPU) {
    auto nodes = tensorGraph_.GetNodesByLayer(layerIndex);
    bool ok = true;
    for (auto* node : nodes) {
        if (node && node->gpu != targetGPU) {
            VRAMLease* lease = vramManager_.GetLease(node->tensorId);
            if (lease && lease->hotpatchable) {
                auto result = tensorHotpatch_.Redirect(lease, targetGPU);
                if (result == HotpatchResult::OK) {
                    node->gpu = targetGPU;
                } else {
                    ok = false;
                }
            }
        }
    }
    return ok;
}

void MARSController::RecordLayerComplete(int layerIndex) {
    // Update access patterns, trigger rebalancing if needed
    (void)layerIndex;
}

// ============================================================================
// Queries
// ============================================================================
DynamicParity MARSController::GetCurrentParity() const {
    return vramManager_.GetDynamicParity();
}

size_t MARSController::GetTotalResidentVRAM() const {
    return vramManager_.GetUsedVRAM(0) + vramManager_.GetUsedVRAM(1);
}

size_t MARSController::GetTotalEvictedBytes() const {
    // Would need to track evicted bytes separately
    return 0;
}

// ============================================================================
// Stats
// ============================================================================
MARSController::Stats MARSController::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void MARSController::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats{};
}

// ============================================================================
// Internal
// ============================================================================
int MARSController::SelectBestGPU(size_t bytes, float priority, bool preferLowLatency) const {
    return vramManager_.SelectBestGPU(bytes, priority, preferLowLatency);
}

} // namespace MARS
} // namespace Deep2
