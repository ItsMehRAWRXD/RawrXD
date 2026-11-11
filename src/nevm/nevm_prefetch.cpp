//============================================================================
// nevm_prefetch.cpp
// RawrXD N-EVM Pre-fetch Engine - Implementation
//============================================================================

#include "nevm_prefetch.hpp"
#include <algorithm>

namespace RawrXD {
namespace NEVM {

//============================================================================
// PrefetchEngine Implementation
//============================================================================

PrefetchEngine::Config PrefetchEngine::DefaultConfig() {
    Config config;
    config.max_concurrent_prefetches = 4;
    config.prefetch_queue_depth = 16;
    config.strategy = PrefetchStrategy::ADAPTIVE;
    config.prefetch_threshold = 0.7f;  // 70% confidence
    config.prefetch_lookahead = 2;      // 2 layers ahead
    return config;
}

PrefetchEngine::PrefetchEngine(NeuralMMU* mmu,
                                 PrecisionController* controller,
                                 const Config& config)
    : mmu_(mmu)
    , controller_(controller)
    , config_(config)
    , shutdown_(false)
    , current_layer_(0) {
    
    stats_ = {};
    worker_thread_ = std::thread(&PrefetchEngine::WorkerLoop, this);
}

PrefetchEngine::~PrefetchEngine() {
    shutdown_ = true;
    queue_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

bool PrefetchEngine::Prefetch(VirtualTensorAddress vta,
                               PrecisionMode format,
                               bool blocking) {
    // Check if already resident
    if (mmu_->Translate(vta, false) != nullptr) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.cache_hits++;
        return true;
    }
    
    // Check if already in flight
    {
        std::shared_lock<std::shared_mutex> lock(status_mutex_);
        auto it = status_map_.find(vta.BlockKey());
        if (it != status_map_.end()) {
            if (it->second == PrefetchStatus::QUEUED ||
                it->second == PrefetchStatus::IN_PROGRESS) {
                // Already being prefetched
                if (blocking) {
                    lock.unlock();
                    return WaitFor(vta, 1000);  // 1 second timeout
                }
                return true;
            }
            if (it->second == PrefetchStatus::COMPLETED) {
                return true;
            }
        }
    }
    
    // Create request
    PrefetchRequest request;
    request.vta = vta;
    request.target_format = format;
    request.target_residency = ResidencyTarget::RAM;
    request.priority = 100;  // Default priority
    request.deadline_tick = GetTick() + 1000;  // 1 second deadline
    request.blocking = blocking;
    
    // Queue the request
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (prefetch_queue_.size() >= config_.prefetch_queue_depth) {
            // Queue full - drop oldest non-blocking request
            std::queue<PrefetchRequest> new_queue;
            bool dropped = false;
            while (!prefetch_queue_.empty()) {
                auto& front = prefetch_queue_.front();
                if (!dropped && !front.blocking) {
                    // Drop this one
                    UpdateStatus(front.vta, PrefetchStatus::FAILED);
                    dropped = true;
                    {
                        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                        stats_.prefetches_cancelled++;
                    }
                } else {
                    new_queue.push(std::move(front));
                }
                prefetch_queue_.pop();
            }
            prefetch_queue_ = std::move(new_queue);
        }
        
        prefetch_queue_.push(request);
        UpdateStatus(vta, PrefetchStatus::QUEUED);
        
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.prefetches_requested++;
        }
    }
    
    queue_cv_.notify_one();
    
    if (blocking) {
        return WaitFor(vta, 1000);
    }
    
    return true;
}

bool PrefetchEngine::UpgradeFormat(VirtualTensorAddress vta,
                                     PrecisionMode new_format,
                                     bool blocking) {
    // Strategy: If blocking, we must wait for the upgrade
    // If non-blocking, we can continue with old format while upgrade happens
    
    if (blocking) {
        // Check current format
        auto current = mmu_->GetCurrentFormat(vta);
        if (current == new_format) {
            return true;  // Already at target
        }
        
        // Initiate prefetch with new format
        bool result = Prefetch(vta, new_format, true);
        
        if (result) {
            // Select the new representation
            result = mmu_->SelectRepresentation(vta, new_format);
        }
        
        return result;
    } else {
        // Non-blocking: initiate async prefetch
        return Prefetch(vta, new_format, false);
    }
}

void PrefetchEngine::OnLayerStart(uint8_t layer_id) {
    current_layer_ = layer_id;
    
    // Update history
    {
        std::lock_guard<std::mutex> lock(history_mutex_);
        layer_history_.push_back(layer_id);
        if (layer_history_.size() > 10) {
            layer_history_.pop_front();
        }
    }
    
    // Predict and prefetch next layers
    if (config_.strategy == PrefetchStrategy::AGGRESSIVE ||
        config_.strategy == PrefetchStrategy::ADAPTIVE) {
        
        std::vector<uint8_t> next_layers;
        PredictNextLayers(next_layers);
        
        for (auto next_layer : next_layers) {
            // Prefetch entire layer with conservative format
            PrefetchLayer(next_layer, PrecisionMode::Q8);
        }
    }
}

void PrefetchEngine::OnPrecisionChange(VirtualTensorAddress vta, 
                                        PrecisionMode new_format) {
    // Trigger immediate prefetch for the new format
    // This is high priority - the precision controller needs this
    PrefetchRequest request;
    request.vta = vta;
    request.target_format = new_format;
    request.target_residency = ResidencyTarget::HOT;  // L3 cache
    request.priority = 1000;  // High priority
    request.deadline_tick = GetTick() + 100;  // 100ms deadline
    request.blocking = false;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        // Insert at front of queue (high priority)
        std::queue<PrefetchRequest> new_queue;
        new_queue.push(request);
        while (!prefetch_queue_.empty()) {
            new_queue.push(std::move(prefetch_queue_.front()));
            prefetch_queue_.pop();
        }
        prefetch_queue_ = std::move(new_queue);
    }
    
    queue_cv_.notify_one();
}

void PrefetchEngine::WorkerLoop() {
    while (!shutdown_) {
        PrefetchRequest request;
        
        // Wait for work
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { 
                return !prefetch_queue_.empty() || shutdown_; 
            });
            
            if (shutdown_) break;
            
            request = std::move(prefetch_queue_.front());
            prefetch_queue_.pop();
        }
        
        // Execute prefetch
        UpdateStatus(request.vta, PrefetchStatus::IN_PROGRESS);
        
        auto start_tick = GetTick();
        bool success = ExecutePrefetch(request);
        auto end_tick = GetTick();
        
        UpdateStatus(request.vta, success ? 
                      PrefetchStatus::COMPLETED : 
                      PrefetchStatus::FAILED);
        
        // Update stats
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            if (success) {
                stats_.prefetches_completed++;
                float latency = (end_tick - start_tick) / 10000.0f;  // Approximate ms
                stats_.avg_prefetch_latency_ms = 
                    (stats_.avg_prefetch_latency_ms * (stats_.prefetches_completed - 1) + 
                     latency) / stats_.prefetches_completed;
            } else {
                stats_.prefetches_failed++;
            }
        }
        
        // Notify completion
        if (request.on_complete) {
            request.on_complete(success);
        }
    }
}

bool PrefetchEngine::ExecutePrefetch(const PrefetchRequest& request) {
    // Get decoder for target format
    auto* decoder = DecoderRegistry::Instance().GetDecoder(request.target_format);
    if (!decoder) {
        return false;
    }
    
    // Allocate physical memory
    size_t decoded_size = decoder->GetDecodedSize(4096);  // Assume 4K elements per block
    void* physical = mmu_->AllocatePhysical(request.target_residency, decoded_size);
    if (!physical) {
        return false;
    }
    
    // In real implementation, would:
    // 1. Read compressed data from file
    // 2. Decode to physical buffer
    // 3. Update MMU TLB
    
    // For now, just mark as allocated
    return true;
}

void PrefetchEngine::PredictNextLayers(std::vector<uint8_t>& out_layers) {
    // Simple prediction: sequential layers
    for (uint64_t i = 1; i <= config_.prefetch_lookahead; ++i) {
        uint8_t next = current_layer_ + static_cast<uint8_t>(i);
        if (next > current_layer_) {  // Wrap-around check
            out_layers.push_back(next);
        }
    }
}

bool PrefetchEngine::WaitFor(VirtualTensorAddress vta, uint64_t timeout_ms) {
    auto start = GetTick();
    while (GetTick() - start < timeout_ms) {
        auto status = GetStatus(vta);
        if (status == PrefetchStatus::COMPLETED) {
            return true;
        }
        if (status == PrefetchStatus::FAILED) {
            return false;
        }
        // Yield
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    return false;  // Timeout
}

PrefetchEngine::PrefetchStatus PrefetchEngine::GetStatus(
    VirtualTensorAddress vta) const {
    
    std::shared_lock<std::shared_mutex> lock(status_mutex_);
    auto it = status_map_.find(vta.BlockKey());
    if (it != status_map_.end()) {
        return it->second;
    }
    return PrefetchStatus::NOT_REQUESTED;
}

void PrefetchEngine::UpdateStatus(VirtualTensorAddress vta, PrefetchStatus status) {
    std::unique_lock<std::shared_mutex> lock(status_mutex_);
    status_map_[vta.BlockKey()] = status;
}

PrefetchEngine::Stats PrefetchEngine::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    Stats s = stats_;
    if (s.prefetches_requested > 0) {
        s.hit_rate = static_cast<float>(s.prefetches_completed) / 
                     s.prefetches_requested;
    }
    return s;
}

uint64_t PrefetchEngine::GetTick() const {
    return GetTickCount64();
}

//============================================================================
// PipelineStallManager Implementation
//============================================================================

PipelineStallManager::PipelineStallManager(PrefetchEngine* prefetch,
                                           const Config& config)
    : prefetch_(prefetch)
    , config_(config) {}

void* PipelineStallManager::RequestPrecisionChange(VirtualTensorAddress vta,
                                                    PrecisionMode new_format) {
    if (!config_.enable_double_buffering) {
        // Simple: block until upgrade complete
        return prefetch_->WaitForFormat(vta, new_format, config_.max_stall_ticks);
    }
    
    // Double buffering: keep old format while upgrading
    uint64_t key = vta.BlockKey();
    
    {
        std::lock_guard<std::mutex> lock(buffer_mutex_);
        
        // Check if already transitioning
        auto it = double_buffers_.find(key);
        if (it != double_buffers_.end()) {
            if (it->second.transition_complete) {
                // Transition done, return new
                return it->second.new_ptr;
            }
            // Transition in progress, return old
            return it->second.old_ptr;
        }
    }
    
    // Start new transition
    // Get current pointer (old format)
    void* old_ptr = prefetch_->GetTensorVA(vta.BlockKey());
    if (!old_ptr) {
        return nullptr;
    }
    
    // Initiate async prefetch for new format
    prefetch_->UpgradeFormat(vta, new_format, false);
    
    // Return old pointer for now
    return old_ptr;
}

bool PipelineStallManager::IsReady(VirtualTensorAddress vta, 
                                    PrecisionMode format) {
    return prefetch_->GetStatus(vta) == PrefetchEngine::PrefetchStatus::COMPLETED;
}

void* PipelineStallManager::WaitForFormat(VirtualTensorAddress vta,
                                           PrecisionMode format,
                                           uint64_t timeout_ms) {
    // Wait for prefetch to complete
    if (!prefetch_->WaitFor(vta, timeout_ms)) {
        return nullptr;
    }
    
    // Get the pointer
    return prefetch_->GetTensorVA(vta.BlockKey());
}

//============================================================================
// PrecisionPrefetchCoordinator Implementation
//============================================================================

PrecisionPrefetchCoordinator::PrecisionPrefetchCoordinator(
    PrecisionController* controller,
    PrefetchEngine* prefetch)
    : controller_(controller)
    , prefetch_(prefetch) {}

void PrecisionPrefetchCoordinator::OnPrecisionDecision(
    VirtualTensorAddress vta,
    PrecisionMode old_format,
    PrecisionMode new_format,
    float urgency) {
    
    // Determine strategy based on urgency
    bool blocking = (urgency > 0.9f);
    
    // Initiate prefetch
    prefetch_->UpgradeFormat(vta, new_format, blocking);
    
    // Track pending upgrade
    {
        std::lock_guard<std::mutex> lock(upgrade_mutex_);
        pending_upgrades_[vta.BlockKey()] = new_format;
    }
}

PrecisionMode PrecisionPrefetchCoordinator::PrepareAccess(
    VirtualTensorAddress vta,
    PrecisionMode desired_format) {
    
    // Check if there's a pending upgrade
    {
        std::lock_guard<std::mutex> lock(upgrade_mutex_);
        auto it = pending_upgrades_.find(vta.BlockKey());
        if (it != pending_upgrades_.end()) {
            // There's an upgrade in progress
            // Check if it's complete
            if (prefetch_->IsResident(vta)) {
                // Upgrade complete, can use new format
                pending_upgrades_.erase(it);
                return desired_format;
            } else {
                // Upgrade not complete, fall back to available format
                // For now, just return desired and let caller handle miss
                return desired_format;
            }
        }
    }
    
    // No pending upgrade, use desired format
    return desired_format;
}

void PrecisionPrefetchCoordinator::RecordAccess(VirtualTensorAddress vta,
                                                  PrecisionMode format_used,
                                                  float compute_time_ms) {
    // Record telemetry for precision controller
    TelemetrySample sample;
    sample.timestamp = GetTickCount64();
    sample.vta = vta;
    sample.compute_latency_ms = compute_time_ms;
    
    controller_->RecordCompute(sample);
}

} // namespace NEVM
} // namespace RawrXD
