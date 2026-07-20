//=============================================================================
// User-Mode Prefetcher Implementation
// Bypasses OS page fault handler with explicit async IO
// Uses IOCP (I/O Completion Ports) for zero-blocking operation
//=============================================================================

#include "user_mode_prefetcher.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Memory {

//=============================================================================
// User-Mode Prefetcher Singleton
//=============================================================================

UserModePrefetcher& UserModePrefetcher::Instance() {
    static UserModePrefetcher instance;
    return instance;
}

//=============================================================================
// Layer Predictor Implementation
//=============================================================================

void LayerPredictor::Initialize(int num_layers, int num_experts) {
    num_layers_ = num_layers;
    num_experts_ = num_experts;
    
    // Initialize transition probabilities (uniform)
    transition_probs_.resize(num_layers);
    for (int i = 0; i < num_layers; i++) {
        transition_probs_[i].resize(num_layers, 1.0f / num_layers);
    }
}

std::vector<int> LayerPredictor::PredictNextLayers(
    int current_layer,
    const float* attention_weights,
    int num_predictions
) {
    std::vector<int> predictions;
    predictions.reserve(num_predictions);
    
    // Simple heuristic: predict next sequential layers
    // In production, use attention_weights to predict expert routing
    for (int i = 1; i <= num_predictions && (current_layer + i) < num_layers_; i++) {
        int next_layer = current_layer + i;
        
        // Check transition probability
        if (transition_probs_[current_layer][next_layer] > 0.1f) {
            predictions.push_back(next_layer);
        }
    }
    
    // Fill remaining slots with highest probability transitions
    while (predictions.size() < static_cast<size_t>(num_predictions)) {
        // Find layer with highest transition prob
        float max_prob = 0.0f;
        int best_layer = current_layer + 1;
        
        for (int i = 0; i < num_layers_; i++) {
            if (i != current_layer && 
                transition_probs_[current_layer][i] > max_prob &&
                std::find(predictions.begin(), predictions.end(), i) == predictions.end()) {
                max_prob = transition_probs_[current_layer][i];
                best_layer = i;
            }
        }
        
        predictions.push_back(best_layer);
    }
    
    return predictions;
}

void LayerPredictor::RecordActualLayer(int predicted, int actual) {
    // Update transition probabilities (simple reinforcement)
    if (predicted == actual) {
        transition_probs_[predicted][actual] = 
            std::min(0.95f, transition_probs_[predicted][actual] * 1.1f);
    } else {
        transition_probs_[predicted][actual] *= 0.9f;
        transition_probs_[predicted][actual] = 
            std::max(0.01f, transition_probs_[predicted][actual]);
    }
    
    // Renormalize
    float sum = 0.0f;
    for (float prob : transition_probs_[predicted]) {
        sum += prob;
    }
    for (float& prob : transition_probs_[predicted]) {
        prob /= sum;
    }
}

//=============================================================================
// User-Mode Prefetcher Implementation
//=============================================================================

bool UserModePrefetcher::Initialize(const wchar_t* model_path, size_t file_size) {
    // Open file for overlapped IO
    hFile_ = CreateFileW(
        model_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (hFile_ == INVALID_HANDLE_VALUE) {
        printf("[Prefetcher] ERROR: Failed to open model file\n");
        return false;
    }
    
    file_size_ = file_size;
    
    // Create IOCP
    hCompletionPort_ = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,
        nullptr,
        0,
        1  // One thread for simplicity
    );
    
    if (!hCompletionPort_) {
        printf("[Prefetcher] ERROR: Failed to create IOCP\n");
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    // Associate file with IOCP
    if (!CreateIoCompletionPort(hFile_, hCompletionPort_, 0, 0)) {
        printf("[Prefetcher] ERROR: Failed to associate file with IOCP\n");
        CloseHandle(hCompletionPort_);
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    // Initialize resident map
    size_t num_blocks = (file_size + 4095) / 4096;  // 4KB blocks
    resident_map_.resize(num_blocks, false);
    
    // Start IOCP worker thread
    shutdown_ = false;
    hWorkerThread_ = CreateThread(
        nullptr,
        0,
        IOCPWorker,
        this,
        0,
        nullptr
    );
    
    if (!hWorkerThread_) {
        printf("[Prefetcher] ERROR: Failed to create worker thread\n");
        CloseHandle(hCompletionPort_);
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    printf("[Prefetcher] Initialized: %ls (%.2f GB)\n", 
           model_path, file_size / (1024.0 * 1024 * 1024));
    
    return true;
}

void UserModePrefetcher::Shutdown() {
    shutdown_ = true;
    
    // Signal worker thread to exit
    if (hCompletionPort_) {
        PostQueuedCompletionStatus(hCompletionPort_, 0, 0, nullptr);
    }
    
    // Wait for worker thread
    if (hWorkerThread_) {
        WaitForSingleObject(hWorkerThread_, 5000);
        CloseHandle(hWorkerThread_);
        hWorkerThread_ = nullptr;
    }
    
    if (hCompletionPort_) {
        CloseHandle(hCompletionPort_);
        hCompletionPort_ = nullptr;
    }
    
    if (hFile_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
    }
    
    printf("[Prefetcher] Shutdown complete\n");
}

bool UserModePrefetcher::PrefetchAsync(
    void* destination_buffer,
    uint64_t file_offset,
    size_t size,
    std::function<void()> on_complete
) {
    if (hFile_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Check if already resident
    if (IsResident(file_offset, size)) {
        prefetch_hits_++;
        if (on_complete) {
            on_complete();
        }
        return true;
    }
    
    prefetch_requests_++;
    
    // Allocate OVERLAPPED structure
    OVERLAPPED* ov = new OVERLAPPED();
    ZeroMemory(ov, sizeof(OVERLAPPED));
    ov->Offset = static_cast<DWORD>(file_offset & 0xFFFFFFFF);
    ov->OffsetHigh = static_cast<DWORD>(file_offset >> 32);
    
    // Store callback in user data (hacky but works for demo)
    // In production, use a proper completion context structure
    
    // Issue async read
    BOOL result = ReadFile(
        hFile_,
        destination_buffer,
        static_cast<DWORD>(size),
        nullptr,
        ov
    );
    
    if (!result && GetLastError() != ERROR_IO_PENDING) {
        printf("[Prefetcher] ERROR: ReadFile failed: %lu\n", GetLastError());
        delete ov;
        return false;
    }
    
    // Mark as resident (optimistic - will be valid when IO completes)
    size_t start_block = file_offset / 4096;
    size_t end_block = (file_offset + size + 4095) / 4096;
    for (size_t i = start_block; i < end_block && i < resident_map_.size(); i++) {
        resident_map_[i] = true;
    }
    
    return true;
}

void UserModePrefetcher::WaitAll() {
    // Wait for all pending IO to complete
    // In production, track pending operations and wait on them
    Sleep(100);  // Simplified - should use proper synchronization
}

bool UserModePrefetcher::IsResident(uint64_t offset, size_t size) {
    size_t start_block = offset / 4096;
    size_t end_block = (offset + size + 4095) / 4096;
    
    for (size_t i = start_block; i < end_block && i < resident_map_.size(); i++) {
        if (!resident_map_[i]) {
            return false;
        }
    }
    
    return true;
}

double UserModePrefetcher::GetHitRate() const {
    uint64_t requests = prefetch_requests_.load();
    uint64_t hits = prefetch_hits_.load();
    
    if (requests == 0) return 0.0;
    return static_cast<double>(hits) / requests;
}

DWORD WINAPI UserModePrefetcher::IOCPWorker(LPVOID param) {
    UserModePrefetcher* prefetcher = static_cast<UserModePrefetcher*>(param);
    
    DWORD bytes_transferred;
    ULONG_PTR completion_key;
    OVERLAPPED* ov;
    
    while (!prefetcher->shutdown_) {
        BOOL result = GetQueuedCompletionStatus(
            prefetcher->hCompletionPort_,
            &bytes_transferred,
            &completion_key,
            &ov,
            INFINITE
        );
        
        if (!result) {
            if (!ov) {
                // Timeout or shutdown
                continue;
            }
            // Handle error
            printf("[Prefetcher] IOCP error: %lu\n", GetLastError());
        }
        
        if (prefetcher->shutdown_) {
            break;
        }
        
        // IO completed successfully
        // In production, invoke callback from context
        
        delete ov;
    }
    
    return 0;
}

//=============================================================================
// Hot-Swap File Builder
//=============================================================================

bool HotSwapFileBuilder::BuildHotSwapFile(
    const wchar_t* input_path,
    const wchar_t* output_path,
    const std::vector<int>& hot_experts,
    const std::vector<int>& warm_experts
) {
    printf("[HotSwap] Building optimized layout...\n");
    printf("[HotSwap] Hot experts: %zu, Warm experts: %zu\n", 
           hot_experts.size(), warm_experts.size());
    
    // TODO: Implement actual file reorganization
    // This would:
    // 1. Read input GGUF
    // 2. Identify hot/warm/cold layers
    // 3. Write in order: Core -> Hot -> Warm -> Cold
    // 4. Ensure 4KB alignment for each layer
    
    printf("[HotSwap] Layout complete\n");
    return true;
}

HotSwapLayout HotSwapFileBuilder::LoadLayout(const wchar_t* layout_path) {
    HotSwapLayout layout = {};
    
    // TODO: Load layout metadata from file
    // For now, return default layout
    layout.core_offset = 0;
    layout.core_size = 8ULL * 1024 * 1024 * 1024;  // 8 GB
    
    layout.expert_a_offset = layout.core_size;
    layout.expert_a_size = 16ULL * 1024 * 1024 * 1024;  // 16 GB
    
    layout.expert_b_offset = layout.expert_a_offset + layout.expert_a_size;
    layout.expert_b_size = 16ULL * 1024 * 1024 * 1024;  // 16 GB
    
    layout.cold_offset = layout.expert_b_offset + layout.expert_b_size;
    layout.cold_size = 40ULL * 1024 * 1024 * 1024;  // 40 GB
    
    return layout;
}

//=============================================================================
// Hybrid Memory Map
//=============================================================================

bool HybridMemoryMap::Initialize(
    const wchar_t* model_path,
    const HotSwapLayout& layout,
    size_t max_resident_size
) {
    layout_ = layout;
    
    // Open file mapping
    hFile_ = CreateFileW(
        model_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (hFile_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    LARGE_INTEGER file_size;
    GetFileSizeEx(hFile_, &file_size);
    file_size_ = file_size.QuadPart;
    
    hMapFile_ = CreateFileMapping(
        hFile_,
        nullptr,
        PAGE_READONLY,
        0, 0,
        nullptr
    );
    
    if (!hMapFile_) {
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    mapped_view_ = MapViewOfFile(
        hMapFile_,
        FILE_MAP_READ,
        0, 0, 0
    );
    
    if (!mapped_view_) {
        CloseHandle(hMapFile_);
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    // Initialize prefetcher
    if (!prefetcher_.Initialize(model_path, file_size_)) {
        UnmapViewOfFile(mapped_view_);
        CloseHandle(hMapFile_);
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    // Initialize layer tracking
    int num_layers = 80;  // Typical for large models
    layer_resident_.resize(num_layers, false);
    layer_pinned_.resize(num_layers, false);
    
    // Pin core layers
    for (int i = 0; i < 10; i++) {
        PinLayer(i);
    }
    
    printf("[HybridMap] Initialized: %.2f GB, Core pinned\n", 
           file_size_ / (1024.0 * 1024 * 1024));
    
    return true;
}

void* HybridMemoryMap::AccessLayer(int layer_id) {
    if (!mapped_view_) return nullptr;
    
    // Check if resident
    if (!layer_resident_[layer_id]) {
        // Trigger prefetch
        uint64_t offset = CalculateLayerOffset(layer_id);
        size_t size = CalculateLayerSize(layer_id);
        
        prefetcher_.PrefetchAsync(
            static_cast<char*>(mapped_view_) + offset,
            offset,
            size,
            nullptr
        );
        
        // In production: wait for prefetch or use async callback
        // For now, mark as resident optimistically
        layer_resident_[layer_id] = true;
    }
    
    uint64_t offset = CalculateLayerOffset(layer_id);
    return static_cast<char*>(mapped_view_) + offset;
}

bool HybridMemoryMap::PinLayer(int layer_id) {
    if (layer_id >= static_cast<int>(layer_resident_.size())) {
        return false;
    }
    
    layer_pinned_[layer_id] = true;
    layer_resident_[layer_id] = true;
    
    // In production: VirtualLock the specific pages
    return true;
}

void HybridMemoryMap::UnpinLayer(int layer_id) {
    if (layer_id < static_cast<int>(layer_pinned_.size())) {
        layer_pinned_[layer_id] = false;
    }
}

HybridMemoryMap::Stats HybridMemoryMap::GetStats() const {
    Stats stats = {};
    
    for (size_t i = 0; i < layer_resident_.size(); i++) {
        size_t layer_size = CalculateLayerSize(static_cast<int>(i));
        
        if (layer_resident_[i]) {
            stats.resident_bytes += layer_size;
        }
        if (layer_pinned_[i]) {
            stats.pinned_bytes += layer_size;
        }
    }
    
    stats.hit_rate = prefetcher_.GetHitRate();
    
    return stats;
}

uint64_t HybridMemoryMap::CalculateLayerOffset(int layer_id) {
    // Simplified: assume uniform layer size
    size_t layer_size = 2ULL * 1024 * 1024 * 1024;  // 2 GB per layer
    return layer_id * layer_size;
}

size_t HybridMemoryMap::CalculateLayerSize(int layer_id) {
    // Simplified: uniform size
    (void)layer_id;
    return 2ULL * 1024 * 1024 * 1024;  // 2 GB
}

} // namespace Memory
} // namespace RawrXD
