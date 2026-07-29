//============================================================================
// nevm_tensor_descriptor.cpp
// Cached execution descriptor implementation
//============================================================================

#include "nevm_tensor_descriptor.hpp"
#include "nevm_mmu.hpp"
#include <chrono>

namespace RawrXD {
namespace NEVM {

//============================================================================
// DescriptorCache Implementation
//============================================================================

DescriptorCache::Config DescriptorCache::DefaultConfig() {
    Config config;
    config.max_entries = 10000;
    config.hot_threshold = 100;
    config.ttl_ms = 60000;
    return config;
}

DescriptorCache::DescriptorCache(const Config& config) 
    : config_(config), lru_pos_(0), hits_(0), misses_(0), evictions_(0) {}

DescriptorCache::~DescriptorCache() = default;

const TensorExecutionDescriptor* DescriptorCache::Lookup(VirtualTensorAddress vta) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(vta);
    if (it != cache_.end()) {
        // Check TTL
        auto now = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
        if (now - it->second.last_access < config_.ttl_ms) {
            hits_++;
            UpdateLRU(vta);
            return &it->second;
        }
    }
    
    misses_++;
    return nullptr;
}

TensorExecutionDescriptor* DescriptorCache::GetOrCreate(VirtualTensorAddress vta) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(vta);
    if (it != cache_.end()) {
        hits_++;
        return &it->second;
    }
    
    EvictIfNeeded();
    
    auto& desc = cache_[vta];
    desc.version = 1;
    desc.last_access = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
    desc.access_count = 0;
    
    misses_++;
    return &desc;
}

void DescriptorCache::Update(VirtualTensorAddress vta, const TensorExecutionDescriptor& desc) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto& entry = cache_[vta];
    entry = desc;
    entry.version++;
    entry.last_access = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
}

void DescriptorCache::Invalidate(VirtualTensorAddress vta) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    cache_.erase(vta);
}

void DescriptorCache::InvalidateAll() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    cache_.clear();
    lru_list_.clear();
}

void DescriptorCache::Touch(VirtualTensorAddress vta) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(vta);
    if (it != cache_.end()) {
        it->second.access_count++;
        it->second.last_access = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
        
        // Mark as hot if threshold reached
        if (it->second.access_count >= config_.hot_threshold) {
            it->second.flags |= TensorExecutionDescriptor::FLAG_HOT;
        }
    }
}

void DescriptorCache::OnResidencyChange(VirtualTensorAddress vta, 
                                         TensorExecutionDescriptor::ResidencyTier new_tier) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(vta);
    if (it != cache_.end()) {
        it->second.residency_tier = new_tier;
        it->second.version++;
        it->second.flags &= ~TensorExecutionDescriptor::FLAG_PREFETCHED;  // Invalidate prefetch
    }
}

void DescriptorCache::OnPrecisionChange(VirtualTensorAddress vta, ISA::PrecisionMode new_mode) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    auto it = cache_.find(vta);
    if (it != cache_.end()) {
        it->second.precision_mode = new_mode;
        it->second.version++;
        // Kernel entry may need update
        it->second.kernel_entry = nullptr;  // Will be resolved on next lookup
    }
}

std::vector<VirtualTensorAddress> DescriptorCache::GetHotEntries(size_t max_count) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::vector<VirtualTensorAddress> hot;
    hot.reserve(max_count);
    
    for (const auto& [vta, desc] : cache_) {
        if (desc.flags & TensorExecutionDescriptor::FLAG_HOT) {
            hot.push_back(vta);
            if (hot.size() >= max_count) break;
        }
    }
    
    return hot;
}

DescriptorCache::Stats DescriptorCache::GetStats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    Stats stats;
    stats.entries = cache_.size();
    stats.hits = hits_;
    stats.misses = misses_;
    stats.evictions = evictions_;
    stats.hit_rate = (hits_ + misses_ > 0) ? 
        static_cast<float>(hits_) / (hits_ + misses_) : 0.0f;
    
    return stats;
}

void DescriptorCache::ResetStats() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    hits_ = 0;
    misses_ = 0;
    evictions_ = 0;
}

void DescriptorCache::EvictIfNeeded() {
    if (cache_.size() < config_.max_entries) return;
    
    // Simple LRU eviction
    if (!lru_list_.empty() && lru_pos_ < lru_list_.size()) {
        cache_.erase(lru_list_[lru_pos_]);
        lru_pos_++;
        evictions_++;
    }
}

void DescriptorCache::UpdateLRU(VirtualTensorAddress vta) const {
    // Add to LRU list (simplified)
    if (lru_list_.size() < config_.max_entries) {
        lru_list_.push_back(vta);
    }
}

//============================================================================
// FastDispatcher Implementation
//============================================================================

FastDispatcher::FastDispatcher(DescriptorCache* cache) : cache_(cache) {}

FastDispatcher::~FastDispatcher() = default;

void FastDispatcher::Initialize() {
    // Pre-populate kernel registry
    Kernels::KernelRegistry::Initialize();
}

bool FastDispatcher::DispatchFast(VirtualTensorAddress vta_a,
                                   VirtualTensorAddress vta_b,
                                   VirtualTensorAddress vta_out,
                                   void* output_buffer) {
    // Fast path: lookup descriptors
    const auto* desc_a = cache_->Lookup(vta_a);
    const auto* desc_b = cache_->Lookup(vta_b);
    const auto* desc_out = cache_->Lookup(vta_out);
    
    if (!desc_a || !desc_b || !desc_out) {
        slow_count_++;
        return false;  // Cache miss, need slow path
    }
    
    // Validate descriptors
    if (!ValidateDescriptor(desc_a) || 
        !ValidateDescriptor(desc_b) || 
        !ValidateDescriptor(desc_out)) {
        slow_count_++;
        return false;
    }
    
    // Branchless dispatch: kernel_entry is pre-resolved
    if (!desc_a->kernel_entry) {
        slow_count_++;
        return false;
    }
    
    // Execute kernel (direct call)
    auto kernel = reinterpret_cast<Kernels::Q4DotFn>(desc_a->kernel_entry);
    
    // TODO: Get actual pointers from descriptor
    // For now, this is a placeholder
    // float result = kernel(desc_a->host_ptr, desc_b->host_ptr);
    
    // Mark as touched
    cache_->Touch(vta_a);
    cache_->Touch(vta_b);
    cache_->Touch(vta_out);
    
    fast_count_++;
    return true;
}

bool FastDispatcher::DispatchSlow(VirtualTensorAddress vta_a,
                                  VirtualTensorAddress vta_b,
                                  VirtualTensorAddress vta_out,
                                  void* output_buffer) {
    // Build descriptors
    auto* desc_a = cache_->GetOrCreate(vta_a);
    auto* desc_b = cache_->GetOrCreate(vta_b);
    auto* desc_out = cache_->GetOrCreate(vta_out);
    
    if (!desc_a || !desc_b || !desc_out) {
        return false;
    }
    
    // Build full descriptors
    *desc_a = BuildDescriptor(vta_a);
    *desc_b = BuildDescriptor(vta_b);
    *desc_out = BuildDescriptor(vta_out);
    
    // Retry fast path
    return DispatchFast(vta_a, vta_b, vta_out, output_buffer);
}

bool FastDispatcher::Dispatch(VirtualTensorAddress vta_a,
                              VirtualTensorAddress vta_b,
                              VirtualTensorAddress vta_out,
                              void* output_buffer) {
    // Try fast path first
    if (DispatchFast(vta_a, vta_b, vta_out, output_buffer)) {
        return true;
    }
    
    // Fall back to slow path
    return DispatchSlow(vta_a, vta_b, vta_out, output_buffer);
}

void FastDispatcher::Prewarm(const std::vector<VirtualTensorAddress>& vtas) {
    for (auto vta : vtas) {
        auto* desc = cache_->GetOrCreate(vta);
        if (desc && desc->version == 0) {
            *desc = BuildDescriptor(vta);
        }
    }
}

FastDispatcher::Stats FastDispatcher::GetStats() const {
    Stats stats;
    stats.fast_dispatches = fast_count_.load();
    stats.slow_dispatches = slow_count_.load();
    
    uint64_t total = stats.fast_dispatches + stats.slow_dispatches;
    stats.fast_path_percentage = (total > 0) ?
        (100.0f * stats.fast_dispatches / total) : 0.0f;
    
    return stats;
}

bool FastDispatcher::ValidateDescriptor(const TensorExecutionDescriptor* desc) const {
    if (!desc) return false;
    
    // Check version (should be > 0)
    if (desc->version == 0) return false;
    
    // Check kernel entry
    if (!desc->kernel_entry) return false;
    
    // Check residency
    if (desc->residency_tier == TensorExecutionDescriptor::ResidencyTier::MIGRATING) {
        return false;  // Can't execute while migrating
    }
    
    return true;
}

TensorExecutionDescriptor FastDispatcher::BuildDescriptor(VirtualTensorAddress vta) {
    TensorExecutionDescriptor desc = {};
    
    // Resolve through MMU
    // TODO: Integrate with Neural MMU
    // auto tensor_info = NeuralMMU::Resolve(vta);
    
    // Determine optimal kernel
    auto caps = Kernels::KernelRegistry::GetCpuCaps();
    
    if (Kernels::has_cap(caps, Kernels::KernelCaps::AVX512F)) {
        desc.kernel_id = Kernels::KernelID::Q4_PREPROCESSED_AVX512;
        desc.required_isa = Kernels::KernelCaps::AVX512F | Kernels::KernelCaps::AVX512VL;
        desc.kernel_entry = Kernels::KernelRegistry::GetQ4DotKernel();
        desc.estimated_latency_ms = 0.001f;
    } else {
        desc.kernel_id = Kernels::KernelID::Q4_PREPROCESSED_SCALAR;
        desc.required_isa = Kernels::KernelCaps::NONE;
        desc.kernel_entry = nullptr;  // Fallback
        desc.estimated_latency_ms = 0.08f;
    }
    
    // Default precision
    desc.precision_mode = ISA::PrecisionMode::Q4;
    desc.quant_type = Kernels::QuantType::Q4_0;
    desc.estimated_error = 0.004f;
    
    // Default residency
    desc.residency_tier = TensorExecutionDescriptor::ResidencyTier::HOST_ONLY;
    desc.host_ptr = nullptr;  // Will be resolved
    desc.device_ptr = nullptr;
    
    desc.flags = 0;
    desc.version = 1;
    desc.last_access = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000;
    desc.access_count = 0;
    
    return desc;
}

} // namespace NEVM
} // namespace RawrXD
