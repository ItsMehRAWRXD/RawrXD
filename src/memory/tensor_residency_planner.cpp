//=============================================================================
// Tensor Residency Planner Implementation
// Finer-grained streaming: 256MB tensor blocks vs 5GB layers
//=============================================================================

#include "tensor_residency_planner.hpp"
#include "prefetch_telemetry.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Tensor Residency Planner Implementation
//=============================================================================

void TensorResidencyPlanner::Initialize(int num_layers) {
    // Build kernel execution graph for transformer
    // Each layer has: Q, K, V, O projections + FFN (Gate, Up, Down)
    
    for (int layer = 0; layer < num_layers; layer++) {
        // Attention Q projection
        KernelNode q_proj;
        q_proj.type = KernelType::ATTENTION_Q;
        q_proj.layer_id = layer;
        q_proj.estimated_compute_us = 15000;  // 15ms
        kernel_graph_.push_back(q_proj);
        
        // Attention K projection
        KernelNode k_proj;
        k_proj.type = KernelType::ATTENTION_K;
        k_proj.layer_id = layer;
        k_proj.estimated_compute_us = 15000;
        kernel_graph_.push_back(k_proj);
        
        // Attention V projection
        KernelNode v_proj;
        v_proj.type = KernelType::ATTENTION_V;
        v_proj.layer_id = layer;
        v_proj.estimated_compute_us = 15000;
        kernel_graph_.push_back(v_proj);
        
        // Attention output
        KernelNode o_proj;
        o_proj.type = KernelType::ATTENTION_O;
        o_proj.layer_id = layer;
        o_proj.estimated_compute_us = 20000;
        // Depends on Q, K, V completing
        kernel_graph_.push_back(o_proj);
        
        // FFN Gate
        KernelNode ffn_gate;
        ffn_gate.type = KernelType::FFN_GATE;
        ffn_gate.layer_id = layer;
        ffn_gate.estimated_compute_us = 25000;
        kernel_graph_.push_back(ffn_gate);
        
        // FFN Up
        KernelNode ffn_up;
        ffn_up.type = KernelType::FFN_UP;
        ffn_up.layer_id = layer;
        ffn_up.estimated_compute_us = 25000;
        kernel_graph_.push_back(ffn_up);
        
        // FFN Down
        KernelNode ffn_down;
        ffn_down.type = KernelType::FFN_DOWN;
        ffn_down.layer_id = layer;
        ffn_down.estimated_compute_us = 30000;
        // Depends on Gate and Up
        kernel_graph_.push_back(ffn_down);
    }
    
    printf("[TensorPlanner] Initialized graph with %zu kernels\n", kernel_graph_.size());
}

void TensorResidencyPlanner::RegisterKernelGraph(const std::vector<KernelNode>& graph) {
    kernel_graph_ = graph;
}

std::vector<uint64_t> TensorResidencyPlanner::GetPrefetchPlan(
    uint32_t current_kernel,
    uint32_t lookahead_count
) {
    std::vector<uint64_t> prefetch_offsets;
    
    // Predict next kernels
    auto next_kernels = PredictNextKernels(current_kernel, lookahead_count);
    
    // Get tensors needed by those kernels
    for (uint32_t kernel_id : next_kernels) {
        auto tensors = GetRequiredTensors(kernel_id);
        for (uint32_t tensor_id : tensors) {
            // Calculate file offset for this tensor
            // Simplified: assume uniform tensor size
            uint64_t offset = tensor_id * TensorBlock::kBlockSize;
            prefetch_offsets.push_back(offset);
        }
    }
    
    return prefetch_offsets;
}

void TensorResidencyPlanner::RecordKernelComplete(uint32_t kernel_id, uint64_t actual_time_us) {
    (void)kernel_id;
    (void)actual_time_us;
    // Update predictions based on actual execution time
    // For now: static graph
}

std::vector<uint32_t> TensorResidencyPlanner::GetRequiredTensors(uint32_t kernel_id) {
    std::vector<uint32_t> tensors;
    
    if (kernel_id >= kernel_graph_.size()) return tensors;
    
    const auto& kernel = kernel_graph_[kernel_id];
    
    // Map kernel type to tensor types
    switch (kernel.type) {
        case KernelType::ATTENTION_Q:
            tensors.push_back(kernel.layer_id * 10 + 0);  // Q weight
            break;
        case KernelType::ATTENTION_K:
            tensors.push_back(kernel.layer_id * 10 + 1);  // K weight
            break;
        case KernelType::ATTENTION_V:
            tensors.push_back(kernel.layer_id * 10 + 2);  // V weight
            break;
        case KernelType::ATTENTION_O:
            tensors.push_back(kernel.layer_id * 10 + 3);  // O weight
            break;
        case KernelType::FFN_GATE:
            tensors.push_back(kernel.layer_id * 10 + 4);  // Gate weight
            break;
        case KernelType::FFN_UP:
            tensors.push_back(kernel.layer_id * 10 + 5);  // Up weight
            break;
        case KernelType::FFN_DOWN:
            tensors.push_back(kernel.layer_id * 10 + 6);  // Down weight
            break;
        default:
            break;
    }
    
    return tensors;
}

std::vector<uint32_t> TensorResidencyPlanner::PredictNextKernels(uint32_t current_kernel, int count) {
    std::vector<uint32_t> predictions;
    
    // Simple sequential prediction for transformers
    for (int i = 1; i <= count && (current_kernel + i) < kernel_graph_.size(); i++) {
        predictions.push_back(current_kernel + i);
    }
    
    return predictions;
}

//=============================================================================
// Triple Buffer Implementation
//=============================================================================

bool TripleBuffer::Initialize(size_t buffer_size) {
    buffer_size_ = buffer_size;
    
    // Allocate three aligned buffers
    for (int i = 0; i < 3; i++) {
        buffers_[i].address = VirtualAlloc(
            nullptr,
            buffer_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if (!buffers_[i].address) {
            printf("[TripleBuffer] ERROR: Failed to allocate buffer %d\n", i);
            Shutdown();
            return false;
        }
        
        buffers_[i].state = BufferState::EMPTY;
        buffers_[i].content_offset = 0;
        buffers_[i].content_size = 0;
        
        // Pin to physical RAM
        if (!VirtualLock(buffers_[i].address, buffer_size)) {
            printf("[TripleBuffer] WARNING: Failed to pin buffer %d\n", i);
        }
    }
    
    printf("[TripleBuffer] Allocated 3x %.2f GB buffers\n", 
           buffer_size / (1024.0 * 1024 * 1024));
    
    return true;
}

void TripleBuffer::Shutdown() {
    for (int i = 0; i < 3; i++) {
        if (buffers_[i].address) {
            VirtualUnlock(buffers_[i].address, buffer_size_);
            VirtualFree(buffers_[i].address, 0, MEM_RELEASE);
            buffers_[i].address = nullptr;
        }
    }
}

void* TripleBuffer::AcquireComputeBuffer(uint32_t timeout_ms) {
    uint64_t start = GetTickCount64();
    
    // Wait for ready buffer
    while (buffers_[ready_idx_].state != BufferState::READY) {
        if (GetTickCount64() - start > timeout_ms) {
            // Timeout - use emergency buffer
            return GetEmergencyBuffer();
        }
        Sleep(1);
    }
    
    // Mark as computing
    buffers_[ready_idx_].state = BufferState::COMPUTING;
    compute_idx_ = ready_idx_;
    
    return buffers_[compute_idx_].address;
}

void TripleBuffer::ReleaseComputeBuffer() {
    if (buffers_[compute_idx_].state == BufferState::COMPUTING) {
        buffers_[compute_idx_].state = BufferState::EMPTY;
    }
}

void* TripleBuffer::AcquirePrefetchBuffer() {
    // Find empty buffer
    for (int i = 0; i < 3; i++) {
        if (buffers_[i].state == BufferState::EMPTY) {
            buffers_[i].state = BufferState::LOADING;
            prefetch_idx_ = i;
            return buffers_[i].address;
        }
    }
    
    // No empty buffer - this shouldn't happen with proper rotation
    printf("[TripleBuffer] WARNING: No empty buffer for prefetch\n");
    return nullptr;
}

void TripleBuffer::MarkPrefetchComplete() {
    if (buffers_[prefetch_idx_].state == BufferState::LOADING) {
        buffers_[prefetch_idx_].state = BufferState::READY;
    }
}

void TripleBuffer::Rotate() {
    // Current compute -> Empty
    if (buffers_[compute_idx_].state == BufferState::COMPUTING) {
        buffers_[compute_idx_].state = BufferState::EMPTY;
    }
    
    // Ready -> Computing (next iteration)
    // Loading -> Ready (when complete)
    
    // Update indices for next cycle
    // Simple rotation: compute -> ready -> prefetch -> compute
    int old_compute = compute_idx_;
    compute_idx_ = ready_idx_;
    ready_idx_ = prefetch_idx_;
    prefetch_idx_ = old_compute;
}

void* TripleBuffer::GetEmergencyBuffer() {
    // Return any buffer that's not currently computing
    for (int i = 0; i < 3; i++) {
        if (buffers_[i].state != BufferState::COMPUTING) {
            return buffers_[i].address;
        }
    }
    
    // Worst case: return current compute buffer (will cause stall)
    return buffers_[compute_idx_].address;
}

//=============================================================================
// Fine-Grained Weight Pager Implementation
//=============================================================================

FineGrainedWeightPager& FineGrainedWeightPager::Instance() {
    static FineGrainedWeightPager instance;
    return instance;
}

bool FineGrainedWeightPager::Initialize(const wchar_t* model_path, size_t model_size) {
    printf("[FineGrainedPager] Initializing...\n");
    printf("[FineGrainedPager] Model: %ls (%.2f GB)\n", 
           model_path, model_size / (1024.0 * 1024 * 1024));
    
    model_size_ = model_size;
    
    // Map entire model into virtual address space
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
        printf("[FineGrainedPager] ERROR: Failed to open file\n");
        return false;
    }
    
    hMapFile_ = CreateFileMapping(
        hFile_,
        nullptr,
        PAGE_READONLY,
        static_cast<DWORD>(model_size >> 32),
        static_cast<DWORD>(model_size & 0xFFFFFFFF),
        nullptr
    );
    
    if (!hMapFile_) {
        printf("[FineGrainedPager] ERROR: Failed to create file mapping\n");
        return false;
    }
    
    virtual_base_ = MapViewOfFile(
        hMapFile_,
        FILE_MAP_READ,
        0, 0, 0
    );
    
    if (!virtual_base_) {
        printf("[FineGrainedPager] ERROR: Failed to map view\n");
        return false;
    }
    
    printf("[FineGrainedPager] Model mapped at %p\n", virtual_base_);
    
    // Initialize triple buffer (3 x 256MB = 768MB streaming zone)
    if (!triple_buffer_.Initialize(TensorBlock::kBlockSize)) {
        printf("[FineGrainedPager] ERROR: Failed to initialize triple buffer\n");
        return false;
    }
    
    // Create IOCP for async IO
    hIOCP_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (!hIOCP_) {
        printf("[FineGrainedPager] ERROR: Failed to create IOCP\n");
        return false;
    }
    
    printf("[FineGrainedPager] Ready\n");
    return true;
}

void FineGrainedWeightPager::Shutdown() {
    printf("[FineGrainedPager] Shutting down...\n");
    
    triple_buffer_.Shutdown();
    
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
    
    if (hIOCP_) {
        CloseHandle(hIOCP_);
        hIOCP_ = nullptr;
    }
    
    printf("[FineGrainedPager] Shutdown complete\n");
}

bool FineGrainedWeightPager::PrepareInference(int num_layers) {
    printf("[FineGrainedPager] Preparing inference for %d layers...\n", num_layers);
    
    planner_.Initialize(num_layers);
    
    // Initialize tensor blocks
    size_t num_blocks = (model_size_ + TensorBlock::kBlockSize - 1) / TensorBlock::kBlockSize;
    tensor_blocks_.resize(num_blocks);
    
    for (size_t i = 0; i < num_blocks; i++) {
        tensor_blocks_[i].file_offset = i * TensorBlock::kBlockSize;
        tensor_blocks_[i].virtual_address = static_cast<char*>(virtual_base_) + tensor_blocks_[i].file_offset;
        tensor_blocks_[i].physical_address = nullptr;
        tensor_blocks_[i].resident.store(false);
    }
    
    printf("[FineGrainedPager] Created %zu tensor blocks\n", num_blocks);
    return true;
}

bool FineGrainedWeightPager::ExecuteKernel(KernelType type, uint32_t layer_id, void* input, void* output) {
    (void)type;
    (void)input;
    (void)output;
    
    // Get required tensors for this kernel
    // For now: simplified - just ensure layer weights are resident
    
    // Acquire compute buffer
    void* compute_buffer = triple_buffer_.AcquireComputeBuffer(100);  // 100ms timeout
    if (!compute_buffer) {
        emergency_fetches_.fetch_add(1);
        return false;
    }
    
    // Copy weights to compute buffer (simplified)
    // In production: use async IO with IOCP
    
    // Execute kernel
    // ... kernel execution ...
    
    kernels_executed_.fetch_add(1);
    
    // Release and rotate
    triple_buffer_.ReleaseComputeBuffer();
    triple_buffer_.Rotate();
    
    // Prefetch next tensors
    auto prefetch_plan = planner_.GetPrefetchPlan(layer_id * 10, 3);
    for (uint64_t offset : prefetch_plan) {
        // Trigger async prefetch
        tensor_prefetches_.fetch_add(1);
    }
    
    return true;
}

bool FineGrainedWeightPager::PrefetchTensor(uint32_t layer_id, uint32_t tensor_type, std::function<void()> on_complete) {
    (void)layer_id;
    (void)tensor_type;
    (void)on_complete;
    
    // Calculate tensor block index
    // Simplified mapping
    
    // Check if already resident
    // If not: trigger async load via IOCP
    
    return true;
}

FineGrainedWeightPager::Stats FineGrainedWeightPager::GetStats() const {
    Stats stats = {};
    
    stats.kernels_executed = kernels_executed_.load();
    stats.tensor_prefetches = tensor_prefetches_.load();
    stats.cache_hits = cache_hits_.load();
    stats.cache_misses = cache_misses_.load();
    stats.emergency_fetches = emergency_fetches_.load();
    
    uint64_t total_accesses = stats.cache_hits + stats.cache_misses;
    if (total_accesses > 0) {
        stats.hit_rate = static_cast<double>(stats.cache_hits) / total_accesses;
    }
    
    return stats;
}

} // namespace Memory
} // namespace RawrXD
