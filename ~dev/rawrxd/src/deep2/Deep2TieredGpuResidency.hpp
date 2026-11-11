#pragma once
// ============================================================================
// Deep2TieredGpuResidency.hpp — DEEP2_VULKAN_RESIDENCY_001
// Bridges deep2::tiered host cache → VulkanCompute device buffers
// No external deps. Fails closed on any bounds/transfer error.
// ============================================================================

#include "vulkan_compute.h"
#include "GGUFLoader.hpp"
#include "Deep2ExpertResidency.hpp"
#include "deep2_tiered_moe.hpp"
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {

// Forward declare for friendship
class VulkanCompute;

// ============================================================================
// GPU Residency Entry — owns a device-local buffer + metadata
// ============================================================================
struct GpuResidentTensor {
    VulkanCompute::DeviceBuf buffer{};
    size_t bytes = 0;
    int ggmlType = 0;
    uint32_t layer = 0;
    int32_t expert = -1;        // -1 = dense, >=0 = expert ID
    uint64_t lastTouchEpoch = 0;
    bool pinned = false;
};

// ============================================================================
// Per-device GPU residency cache (tiered: VRAM hot, evict to host tier)
// ============================================================================
class GpuResidencyCache {
public:
    explicit GpuResidencyCache(VulkanCompute* compute, uint64_t capacityBytes = 0)
        : compute_(compute), capacityBytes_(capacityBytes) {
        if (!compute_) throw std::invalid_argument("null VulkanCompute");
    }

    GpuResidencyCache(const GpuResidencyCache&) = delete;
    GpuResidencyCache& operator=(const GpuResidencyCache&) = delete;
    ~GpuResidencyCache() { reset(); }

    void reset(uint64_t newCapacity = 0) {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [_, entry] : entries_) {
            compute_->destroyBuffer(entry.buffer);
        }
        entries_.clear();
        usedBytes_ = 0;
        if (newCapacity) capacityBytes_ = newCapacity;
    }

    // Check if tensor already resident on this GPU
    bool contains(const std::string& key) const noexcept {
        std::lock_guard<std::mutex> lock(mu_);
        return entries_.find(key) != entries_.end();
    }

    // Ensure tensor is resident on this GPU; upload if needed
    // Returns false if OOM or upload fails
    bool ensure(const deep2::tiered::Cache::Lease& lease,
                const deep2::tiered::Tensor& tensor,
                uint64_t epoch,
                std::string* outKey = nullptr) {
        std::lock_guard<std::mutex> lock(mu_);

        // Build unique key: file|offset|bytes (matches tiered cache)
        std::string key = tensor.file.lexically_normal().string() + "|"
                        + std::to_string(tensor.offset) + "|"
                        + std::to_string(tensor.bytes);

        if (outKey) *outKey = key;

        auto it = entries_.find(key);
        if (it != entries_.end()) {
            ++hits_;
            it->second.lastTouchEpoch = epoch;
            it->second.pinned = it->second.pinned || true;
            return true;
        }

        ++misses_;

        if (!capacityBytes_ || tensor.bytes > capacityBytes_) return false;

        // Evict LRU unpinned entries until we have space
        while (usedBytes_ + tensor.bytes > capacityBytes_) {
            auto victim = entries_.end();
            uint64_t oldest = UINT64_MAX;
            for (auto jt = entries_.begin(); jt != entries_.end(); ++jt) {
                if (jt->second.pinned) continue;
                if (jt->second.lastTouchEpoch < oldest) {
                    oldest = jt->second.lastTouchEpoch;
                    victim = jt;
                }
            }
            if (victim == entries_.end()) return false; // all pinned
            compute_->destroyBuffer(victim->second.buffer);
            usedBytes_ -= victim->second.bytes;
            ++evictions_;
            evictedBytes_ += victim->second.bytes;
            entries_.erase(victim);
        }

        // Upload from host lease to GPU
        VulkanCompute::MaterialTicket ticket;
        if (!compute_->SubmitMaterialUploadAsync(
                lease.bytes().data(), tensor.bytes, epoch, ticket)) {
            return false;
        }

        GpuWorkInterval interval;
        if (!compute_->WaitMaterialUpload(ticket, &interval)) {
            return false;
        }

        // Install in residency
        GpuResidentTensor entry;
        entry.buffer = std::move(ticket.target);
        entry.bytes = tensor.bytes;
        entry.ggmlType = static_cast<int>(tensor.ggml_type);
        entry.layer = static_cast<uint32_t>(tensor.layer);
        entry.expert = tensor.expert;
        entry.lastTouchEpoch = epoch;
        entry.pinned = true;

        usedBytes_ += tensor.bytes;
        peakUsedBytes_ = std::max(peakUsedBytes_, usedBytes_);
        entries_.emplace(std::move(key), std::move(entry));

        uploadBytes_ += tensor.bytes;
        ++uploads_;
        return true;
    }

    // Release pin (allow eviction)
    void unpin(const std::string& key) noexcept {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(key);
        if (it != entries_.end() && it->second.pinned) {
            it->second.pinned = false;
        }
    }

    // Get resident buffer for compute
    std::optional<VulkanCompute::DeviceBuf> getBuffer(const std::string& key) const noexcept {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = entries_.find(key);
        if (it != entries_.end()) return it->second.buffer;
        return std::nullopt;
    }

    // Stats
    uint64_t usedBytes() const noexcept {
        std::lock_guard<std::mutex> lock(mu_); return usedBytes_; }
    uint64_t capacityBytes() const noexcept { return capacityBytes_; }
    uint64_t hits() const noexcept { std::lock_guard<std::mutex> lock(mu_); return hits_; }
    uint64_t misses() const noexcept { std::lock_guard<std::mutex> lock(mu_); return misses_; }
    uint64_t evictions() const noexcept { std::lock_guard<std::mutex> lock(mu_); return evictions_; }
    uint64_t evictedBytes() const noexcept { std::lock_guard<std::mutex> lock(mu_); return evictedBytes_; }
    uint64_t uploads() const noexcept { std::lock_guard<std::mutex> lock(mu_); return uploads_; }
    uint64_t uploadBytes() const noexcept { std::lock_guard<std::mutex> lock(mu_); return uploadBytes_; }
    uint64_t peakUsedBytes() const noexcept { std::lock_guard<std::mutex> lock(mu_); return peakUsedBytes_; }

private:
    VulkanCompute* compute_ = nullptr;
    uint64_t capacityBytes_ = 0;
    uint64_t usedBytes_ = 0;
    uint64_t peakUsedBytes_ = 0;
    uint64_t hits_ = 0, misses_ = 0, evictions_ = 0, evictedBytes_ = 0;
    uint64_t uploads_ = 0, uploadBytes_ = 0;
    mutable std::mutex mu_;
    std::unordered_map<std::string, GpuResidentTensor> entries_;
};

// ============================================================================
// Tensor name → (layer, expert) parser for MoE models
// ============================================================================
struct TensorIdentity {
    uint32_t layer = UINT32_MAX;
    int32_t expert = -1;          // -1 = dense, >=0 = expert
    bool isMoE = false;
};

inline TensorIdentity parseTensorIdentity(const std::string& name) {
    TensorIdentity id;
    // Common patterns: "blk.0.ffn_gate_exps.0.weight", "blk.1.attn_q.weight", "model.layers.2.mlp.experts.0.w1.weight"
    // Try blk.{layer}.{component}.exps.{expert}.{weight}
    size_t blkPos = name.find("blk.");
    if (blkPos != std::string::npos) {
        size_t dot = name.find('.', blkPos + 4);
        if (dot != std::string::npos) {
            id.layer = static_cast<uint32_t>(std::stoul(name.substr(blkPos + 4, dot - blkPos - 4)));
        }
        size_t exps = name.find(".exps.");
        if (exps != std::string::npos) {
            size_t dot2 = name.find('.', exps + 6);
            if (dot2 != std::string::npos) {
                id.expert = static_cast<int32_t>(std::stoul(name.substr(exps + 6, dot2 - exps - 6)));
                id.isMoE = true;
            }
        }
    }
    // Try model.layers.{layer}.mlp.experts.{expert}.
    size_t layers = name.find("model.layers.");
    if (layers != std::string::npos) {
        size_t dot = name.find('.', layers + 13);
        if (dot != std::string::npos) {
            id.layer = static_cast<uint32_t>(std::stoul(name.substr(layers + 13, dot - layers - 13)));
        }
        size_t experts = name.find(".experts.");
        if (experts != std::string::npos) {
            size_t dot2 = name.find('.', experts + 9);
            if (dot2 != std::string::npos) {
                id.expert = static_cast<int32_t>(std::stoul(name.substr(experts + 9, dot2 - experts - 9)));
                id.isMoE = true;
            }
        }
    }
    return id;
}

// ============================================================================
// Main integration: TieredGpuManager — orchestrates host cache + multi-GPU residency
// ============================================================================
class TieredGpuManager {
public:
    struct Config {
        uint64_t hostCacheBytes = 8ull * 1024 * 1024 * 1024;  // 8 GB default host cache
        uint64_t gpu0CacheBytes = 28ull * 1024 * 1024 * 1024; // R9700: 28 GB for weights (4 GB headroom)
        uint64_t gpu1CacheBytes = 12ull * 1024 * 1024 * 1024; // 7800 XT: 12 GB for weights (4 GB headroom)
    };

    struct AdmissionResult {
        bool accepted = false;
        uint64_t modelSizeBytes = 0;
        uint64_t requiredHostBytes = 0;
        std::string reason;
        deep2::tiered::Admission hostAdmission{};
    };

    TieredGpuManager(std::vector<VulkanCompute*>& gpus, const Config& cfg = {})
        : gpus_(gpus), config_(cfg),
          hostCache_(config_.hostCacheBytes),
          gpu0Cache_(gpus_.size() > 0 ? gpus_[0] : nullptr, config_.gpu0CacheBytes),
          gpu1Cache_(gpus_.size() > 1 ? gpus_[1] : nullptr, config_.gpu1CacheBytes) {
        if (gpus_.empty()) throw std::invalid_argument("no GPUs provided");
        if (!gpus_[0]) throw std::invalid_argument("GPU 0 is null");
    }

    // Build tensor index from loaded GGUF loader
    bool buildIndex(const GGUFLoader& loader, const std::filesystem::path& modelPath) {
        std::lock_guard<std::mutex> lock(indexMu_);
        tensorIndex_ = std::make_unique<deep2::tiered::TensorIndex>();

        for (const auto& [name, tensor] : loader.tensors_) {
            if (!tensor.mapped || !tensor.data || tensor.sizeBytes == 0) continue;

            deep2::tiered::Tensor td;
            td.name = name;
            td.file = modelPath;
            td.offset = tensor.fileOffset;
            td.bytes = tensor.sizeBytes;
            td.ggml_type = static_cast<uint32_t>(tensor.type);

            auto identity = parseTensorIdentity(name);
            td.layer = identity.layer;
            td.expert = identity.expert;

            try {
                tensorIndex_->add(std::move(td));
            } catch (const std::exception&) {
                return false;
            }
        }
        return !tensorIndex_->size();
    }

    // Admit model: check if it fits in memory hierarchy
    AdmissionResult admitModel() const {
        AdmissionResult result;
        std::lock_guard<std::mutex> lock(indexMu_);
        if (!tensorIndex_) {
            result.reason = "no tensor index built";
            return result;
        }

        result.modelSizeBytes = tensorIndex_->total_bytes();

        // Host budget: total RAM - KV - scratch - staging
        const uint64_t totalHostBytes = 64ull * 1024 * 1024 * 1024; // 64 GB DDR5
        const uint64_t kvBudget = 4ull * 1024 * 1024 * 1024;       // 4 GB KV
        const uint64_t scratchBudget = 2ull * 1024 * 1024 * 1024;  // 2 GB scratch
        const uint64_t stagingBudget = 4ull * 1024 * 1024 * 1024;  // 4 GB staging

        deep2::tiered::Budget budget;
        budget.host = totalHostBytes;
        budget.kv = kvBudget;
        budget.scratch = scratchBudget;
        budget.staging = stagingBudget;
        budget.gpu0 = config_.gpu0CacheBytes;
        budget.gpu1 = config_.gpu1CacheBytes;

        result.hostAdmission = deep2::tiered::admit(budget, result.modelSizeBytes);
        result.requiredHostBytes = result.modelSizeBytes;
        result.accepted = result.hostAdmission.accepted;
        result.reason = result.hostAdmission.reason;
        return result;
    }

    // Acquire tensor for GPU execution
    // Returns lease that must be kept alive until GPU work completes
    deep2::tiered::Cache::Lease acquireForGpu(const std::string& tensorName, uint32_t targetGpu = 0) {
        std::lock_guard<std::mutex> lock(indexMu_);
        if (!tensorIndex_) throw std::runtime_error("tensor index not built");

        const auto& tensor = tensorIndex_->at(tensorName);
        auto lease = hostCache_.acquire(tensor);

        // Also ensure on target GPU
        GpuResidencyCache* gpuCache = (targetGpu == 0) ? &gpu0Cache_ : &gpu1Cache_;
        std::string gpuKey;
        bool ok = gpuCache->ensure(lease, tensor, currentEpoch_, &gpuKey);
        if (!ok) {
            // Release lease on failure
            lease.release();
            throw std::runtime_error("GPU residency failed for " + tensorName);
        }
        gpuKeys_[tensorName] = gpuKey;
        return lease;
    }

    // Release GPU pin after compute completes
    void releaseGpuPin(const std::string& tensorName, uint32_t targetGpu = 0) {
        GpuResidencyCache* gpuCache = (targetGpu == 0) ? &gpu0Cache_ : &gpu1Cache_;
        auto it = gpuKeys_.find(tensorName);
        if (it != gpuKeys_.end()) {
            gpuCache->unpin(it->second);
            gpuKeys_.erase(it);
        }
    }

    // Get resident GPU buffer for compute dispatch
    std::optional<VulkanCompute::DeviceBuf> getGpuBuffer(const std::string& tensorName, uint32_t targetGpu = 0) const {
        const GpuResidencyCache* gpuCache = (targetGpu == 0) ? &gpu0Cache_ : &gpu1Cache_;
        auto it = gpuKeys_.find(tensorName);
        if (it == gpuKeys_.end()) return std::nullopt;
        return gpuCache->getBuffer(it->second);
    }

    // Expert-aware prefetch: given router decision, prefetch next experts
    void prefetchExperts(const std::vector<std::pair<uint32_t, int32_t>>& expertPlan, uint32_t targetGpu = 0) {
        std::lock_guard<std::mutex> lock(indexMu_);
        if (!tensorIndex_) return;

        GpuResidencyCache* gpuCache = (targetGpu == 0) ? &gpu0Cache_ : &gpu1Cache_;
        for (const auto& [layer, expert] : expertPlan) {
            // Find tensors matching this layer+expert
            for (const auto& name : tensorIndex_->list_names()) {
                auto identity = parseTensorIdentity(name);
                if (identity.layer == layer && identity.expert == expert) {
                    try {
                        const auto& tensor = tensorIndex_->at(name);
                        auto lease = hostCache_.acquire(tensor);
                        std::string gpuKey;
                        gpuCache->ensure(lease, tensor, currentEpoch_, &gpuKey);
                        gpuKeys_[name] = gpuKey;
                    } catch (...) {
                        // Prefetch is best-effort
                    }
                }
            }
        }
    }

    void advanceEpoch() { ++currentEpoch_; }

    // Telemetry
    deep2::tiered::Cache::Stats hostCacheStats() const { return hostCache_.stats(); }
    uint64_t gpu0UsedBytes() const { return gpu0Cache_.usedBytes(); }
    uint64_t gpu1UsedBytes() const { return gpu1Cache_.usedBytes(); }
    uint64_t gpu0Uploads() const { return gpu0Cache_.uploads(); }
    uint64_t gpu1Uploads() const { return gpu1Cache_.uploads(); }
    uint64_t gpu0UploadBytes() const { return gpu0Cache_.uploadBytes(); }
    uint64_t gpu1UploadBytes() const { return gpu1Cache_.uploadBytes(); }

private:
    std::vector<VulkanCompute*>& gpus_;
    Config config_;
    mutable std::mutex indexMu_;
    std::unique_ptr<deep2::tiered::TensorIndex> tensorIndex_;
    deep2::tiered::Cache hostCache_;
    GpuResidencyCache gpu0Cache_;
    GpuResidencyCache gpu1Cache_;
    std::unordered_map<std::string, std::string> gpuKeys_;
    uint64_t currentEpoch_ = 0;
};

} // namespace Deep2