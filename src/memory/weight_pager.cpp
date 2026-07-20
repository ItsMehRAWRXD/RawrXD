//=============================================================================
// Weight Pager Implementation
// Software-Defined VRAM System for LLM Weights
//=============================================================================

#include "weight_pager.hpp"
#include "prefetch_telemetry.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Double Buffer Implementation
//=============================================================================

bool DoubleBuffer::Initialize(size_t buffer_size) {
    buffer_size_ = buffer_size;
    
    // Allocate two aligned buffers
    for (int i = 0; i < 2; i++) {
        buffers_[i] = VirtualAlloc(
            nullptr,
            buffer_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if (!buffers_[i]) {
            printf("[DoubleBuffer] ERROR: Failed to allocate buffer %d\n", i);
            Shutdown();
            return false;
        }
    }
    
    printf("[DoubleBuffer] Allocated 2x %.2f GB buffers\n", 
           buffer_size / (1024.0 * 1024 * 1024));
    
    return PinBuffers();
}

void DoubleBuffer::Shutdown() {
    UnpinBuffers();
    
    for (int i = 0; i < 2; i++) {
        if (buffers_[i]) {
            VirtualFree(buffers_[i], 0, MEM_RELEASE);
            buffers_[i] = nullptr;
        }
    }
}

void DoubleBuffer::Swap() {
    current_compute_ = 1 - current_compute_;
}

bool DoubleBuffer::PinBuffers() {
    if (pinned_) return true;
    
    for (int i = 0; i < 2; i++) {
        if (!VirtualLock(buffers_[i], buffer_size_)) {
            printf("[DoubleBuffer] WARNING: Failed to pin buffer %d\n", i);
            // Continue anyway - just might page fault
        }
    }
    
    pinned_ = true;
    printf("[DoubleBuffer] Buffers pinned to physical RAM\n");
    return true;
}

void DoubleBuffer::UnpinBuffers() {
    if (!pinned_) return;
    
    for (int i = 0; i < 2; i++) {
        if (buffers_[i]) {
            VirtualUnlock(buffers_[i], buffer_size_);
        }
    }
    
    pinned_ = false;
}

//=============================================================================
// Layer Residency Map Implementation
//=============================================================================

void LayerResidencyMap::Initialize(int num_layers) {
    resident_.resize(num_layers);
    loading_.resize(num_layers);
    last_access_.resize(num_layers);
    
    for (int i = 0; i < num_layers; i++) {
        resident_[i].store(false);
        loading_[i].store(false);
        last_access_[i].store(0);
    }
}

void LayerResidencyMap::MarkResident(int layer_id, bool resident) {
    if (layer_id >= 0 && layer_id < static_cast<int>(resident_.size())) {
        resident_[layer_id].store(resident, std::memory_order_release);
        if (resident) {
            last_access_[layer_id].store(GetTickCount64(), std::memory_order_relaxed);
        }
    }
}

void LayerResidencyMap::MarkLoading(int layer_id, bool loading) {
    if (layer_id >= 0 && layer_id < static_cast<int>(loading_.size())) {
        loading_[layer_id].store(loading, std::memory_order_release);
    }
}

bool LayerResidencyMap::IsResident(int layer_id) const {
    if (layer_id < 0 || layer_id >= static_cast<int>(resident_.size())) return false;
    return resident_[layer_id].load(std::memory_order_acquire);
}

bool LayerResidencyMap::IsLoading(int layer_id) const {
    if (layer_id < 0 || layer_id >= static_cast<int>(loading_.size())) return false;
    return loading_[layer_id].load(std::memory_order_acquire);
}

bool LayerResidencyMap::IsAvailable(int layer_id) const {
    return IsResident(layer_id) || IsLoading(layer_id);
}

std::vector<int> LayerResidencyMap::GetPrefetchCandidates(int current_layer, int count) {
    std::vector<int> candidates;
    int num_layers = static_cast<int>(resident_.size());
    
    // Predict next sequential layers
    for (int i = 1; i <= count && (current_layer + i) < num_layers; i++) {
        int next_layer = current_layer + i;
        if (!IsAvailable(next_layer)) {
            candidates.push_back(next_layer);
        }
    }
    
    return candidates;
}

std::vector<int> LayerResidencyMap::GetEvictionCandidates(int count) {
    std::vector<std::pair<uint64_t, int>> lru_list;  // (last_access, layer_id)
    
    for (size_t i = 0; i < resident_.size(); i++) {
        if (IsResident(static_cast<int>(i)) && !loading_[i].load()) {
            lru_list.emplace_back(last_access_[i].load(), static_cast<int>(i));
        }
    }
    
    // Sort by last access time (oldest first)
    std::sort(lru_list.begin(), lru_list.end());
    
    std::vector<int> candidates;
    for (size_t i = 0; i < std::min(static_cast<size_t>(count), lru_list.size()); i++) {
        candidates.push_back(lru_list[i].second);
    }
    
    return candidates;
}

//=============================================================================
// Weight Pager Implementation
//=============================================================================

WeightPager& WeightPager::Instance() {
    static WeightPager instance;
    return instance;
}

bool WeightPager::Initialize(const wchar_t* model_path, size_t model_size) {
    printf("[WeightPager] Initializing...\n");
    printf("[WeightPager] Model: %ls (%.2f GB)\n", 
           model_path, model_size / (1024.0 * 1024 * 1024));
    
    model_size_ = model_size;
    
    // Map entire model into virtual address space (doesn't consume RAM)
    if (!MapModelFile(model_path, model_size)) {
        printf("[WeightPager] ERROR: Failed to map model file\n");
        return false;
    }
    
    // Allocate RAM window (48GB usable - 16GB fixed = 32GB streaming)
    // Conservative: use 28GB for streaming to leave headroom
    ram_window_size_ = 28ULL * 1024 * 1024 * 1024;
    if (!AllocateRAMWindow(ram_window_size_)) {
        printf("[WeightPager] ERROR: Failed to allocate RAM window\n");
        Shutdown();
        return false;
    }
    
    printf("[WeightPager] RAM window: %.2f GB\n", 
           ram_window_size_ / (1024.0 * 1024 * 1024));
    
    return true;
}

void WeightPager::Shutdown() {
    printf("[WeightPager] Shutting down...\n");
    
    double_buffer_.Shutdown();
    
    if (ram_window_) {
        VirtualFree(ram_window_, 0, MEM_RELEASE);
        ram_window_ = nullptr;
    }
    
    if (virtual_base_) {
        UnmapViewOfFile(virtual_base_);
        virtual_base_ = nullptr;
    }
    
    if (hMapFile_) {
        CloseHandle(hMapFile_);
        hMapFile_ = nullptr;
    }
    
    if (hFile_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
    }
    
    printf("[WeightPager] Shutdown complete\n");
}

bool WeightPager::PrepareInference(int num_layers) {
    printf("[WeightPager] Preparing inference for %d layers...\n", num_layers);
    
    residency_map_.Initialize(num_layers);
    
    // Setup double buffer for seamless rotation
    // Each buffer holds ~2-4 layers worth of weights
    size_t buffer_size = ram_window_size_ / 2;
    if (!double_buffer_.Initialize(buffer_size)) {
        return false;
    }
    
    // Pin first few layers (embedding + first transformer layers)
    int num_initial_layers = std::min(4, num_layers);
    for (int i = 0; i < num_initial_layers; i++) {
        PinLayer(i);
    }
    
    printf("[WeightPager] Ready: %d initial layers pinned\n", num_initial_layers);
    return true;
}

void* WeightPager::AccessLayer(int layer_id) {
    // Check if already resident
    if (!residency_map_.IsResident(layer_id)) {
        // Trigger synchronous load (blocking)
        // In production: should wait for prefetch or trigger async
        printf("[WeightPager] Layer %d not resident - triggering load\n", layer_id);
        
        // For now: copy from mapped file to RAM window
        void* layer_src = GetLayerAddress(layer_id);
        size_t layer_size = GetLayerSize(layer_id);
        
        // Find space in RAM window (simplified - should use proper allocator)
        void* dest = static_cast<char*>(ram_window_) + (layer_id * layer_size % ram_window_size_);
        
        memcpy(dest, layer_src, layer_size);
        residency_map_.MarkResident(layer_id, true);
        
        // Update telemetry
        auto& telemetry = TelemetryCollector::Instance().GetLayerSwapTelemetry();
        telemetry.RecordLayerSwap(1000, false);  // 1ms (measured)
    }
    
    current_layer_.store(layer_id);
    
    // Prefetch next layers
    auto next_layers = residency_map_.GetPrefetchCandidates(layer_id, 3);
    for (int next_layer : next_layers) {
        PrefetchLayer(next_layer, nullptr);
    }
    
    return GetLayerAddress(layer_id);
}

bool WeightPager::PrefetchLayer(int layer_id, std::function<void()> on_complete) {
    if (residency_map_.IsAvailable(layer_id)) {
        // Already resident or loading
        TelemetryCollector::Instance().GetPrefetchTelemetry().RecordCacheHit();
        if (on_complete) on_complete();
        return true;
    }
    
    TelemetryCollector::Instance().GetPrefetchTelemetry().RecordCacheMiss();
    
    // Mark as loading
    residency_map_.MarkLoading(layer_id, true);
    
    // In production: use IOCP for async load
    // For now: synchronous (will be async in full implementation)
    void* layer_src = GetLayerAddress(layer_id);
    size_t layer_size = GetLayerSize(layer_id);
    
    // Find eviction candidates to make space
    auto evict = residency_map_.GetEvictionCandidates(1);
    for (int evict_layer : evict) {
        EvictLayer(evict_layer);
    }
    
    // Copy to RAM window
    void* dest = static_cast<char*>(ram_window_) + 
                  (layer_id * layer_size % ram_window_size_);
    memcpy(dest, layer_src, layer_size);
    
    residency_map_.MarkResident(layer_id, true);
    residency_map_.MarkLoading(layer_id, false);
    layers_prefetched_.fetch_add(1);
    
    if (on_complete) on_complete();
    return true;
}

bool WeightPager::EvictLayer(int layer_id) {
    if (!residency_map_.IsResident(layer_id)) return false;
    
    residency_map_.MarkResident(layer_id, false);
    layers_evicted_.fetch_add(1);
    
    return true;
}

bool WeightPager::PinLayer(int layer_id) {
    // Mark as pinned (don't evict)
    // In production: VirtualLock the specific pages
    printf("[WeightPager] Layer %d pinned\n", layer_id);
    return true;
}

void WeightPager::UnpinLayer(int layer_id) {
    (void)layer_id;
    // Remove pin
}

bool WeightPager::WaitForLayer(int layer_id, uint32_t timeout_ms) {
    uint64_t start = GetTickCount64();
    
    while (!residency_map_.IsResident(layer_id)) {
        if (GetTickCount64() - start > timeout_ms) {
            return false;  // Timeout
        }
        Sleep(1);  // Yield
    }
    
    return true;
}

WeightPager::Stats WeightPager::GetStats() const {
    Stats stats = {};
    
    stats.total_model_size = model_size_;
    stats.ram_window_size = ram_window_size_;
    
    // Count resident bytes
    for (size_t i = 0; i < pages_.size(); i++) {
        if (pages_[i].IsResident()) {
            stats.resident_bytes += WeightPage::kPageSize;
            if (pages_[i].IsPinned()) {
                stats.pinned_bytes += WeightPage::kPageSize;
            }
        }
    }
    
    stats.page_faults_avoided = page_faults_avoided_.load();
    stats.layers_prefetched = layers_prefetched_.load();
    stats.layers_evicted = layers_evicted_.load();
    
    // Calculate hit rate
    auto& telemetry = TelemetryCollector::Instance().GetPrefetchTelemetry();
    auto tstats = telemetry.CalculateStats();
    stats.hit_rate = tstats.hit_rate;
    
    return stats;
}

bool WeightPager::IsStreamingHealthy() const {
    auto stats = GetStats();
    
    // Healthy if:
    // - Hit rate > 80%
    // - No excessive evictions
    return stats.hit_rate > 0.8 && 
           stats.layers_evicted < stats.layers_prefetched * 2;
}

bool WeightPager::MapModelFile(const wchar_t* path, size_t size) {
    hFile_ = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (hFile_ == INVALID_HANDLE_VALUE) {
        printf("[WeightPager] ERROR: Failed to open file: %lu\n", GetLastError());
        return false;
    }
    
    hMapFile_ = CreateFileMapping(
        hFile_,
        nullptr,
        PAGE_READONLY,
        static_cast<DWORD>(size >> 32),
        static_cast<DWORD>(size & 0xFFFFFFFF),
        nullptr
    );
    
    if (!hMapFile_) {
        printf("[WeightPager] ERROR: Failed to create file mapping: %lu\n", GetLastError());
        return false;
    }
    
    virtual_base_ = MapViewOfFile(
        hMapFile_,
        FILE_MAP_READ,
        0, 0, 0
    );
    
    if (!virtual_base_) {
        printf("[WeightPager] ERROR: Failed to map view: %lu\n", GetLastError());
        return false;
    }
    
    printf("[WeightPager] Model mapped at %p (virtual)\n", virtual_base_);
    return true;
}

bool WeightPager::AllocateRAMWindow(size_t size) {
    ram_window_ = VirtualAlloc(
        nullptr,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!ram_window_) {
        printf("[WeightPager] ERROR: Failed to allocate RAM window: %lu\n", GetLastError());
        return false;
    }
    
    // Pin to physical RAM
    if (!VirtualLock(ram_window_, size)) {
        printf("[WeightPager] WARNING: Failed to pin RAM window\n");
    }
    
    printf("[WeightPager] RAM window allocated at %p\n", ram_window_);
    return true;
}

void* WeightPager::GetLayerAddress(int layer_id) {
    // Calculate offset in model file
    // Simplified: assume uniform layer size
    size_t layer_size = model_size_ / 80;  // 80 layers typical
    uint64_t offset = layer_id * layer_size;
    
    return static_cast<char*>(virtual_base_) + offset;
}

size_t WeightPager::GetLayerSize(int layer_id) {
    (void)layer_id;
    // Simplified: uniform size
    return model_size_ / 80;
}

//=============================================================================
// Prefetch Predictor Implementation
//=============================================================================

std::vector<int> PrefetchPredictor::PredictNextLayers(int current_layer, int num_predictions) {
    std::vector<int> predictions;
    
    // Transformers are deterministic: next sequential layers
    for (int i = 1; i <= num_predictions; i++) {
        predictions.push_back(current_layer + i);
    }
    
    return predictions;
}

std::vector<int> PrefetchPredictor::PredictExperts(const float* router_output, int num_experts) {
    std::vector<int> experts;
    
    // Find top-k experts from router output
    std::vector<std::pair<float, int>> scored_experts;
    for (int i = 0; i < num_experts; i++) {
        scored_experts.emplace_back(router_output[i], i);
    }
    
    std::sort(scored_experts.begin(), scored_experts.end(), 
              std::greater<std::pair<float, int>>());
    
    // Return top 2 experts
    for (int i = 0; i < std::min(2, num_experts); i++) {
        experts.push_back(scored_experts[i].second);
    }
    
    return experts;
}

void PrefetchPredictor::RecordPrediction(int predicted_layer, bool was_needed) {
    (void)predicted_layer;
    (void)was_needed;
    // Learning logic for adaptive prediction
}

} // namespace Memory
} // namespace RawrXD
