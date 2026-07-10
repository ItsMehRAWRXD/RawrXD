// ============================================================================
// GGUF_MASM_Adapter.cpp - MASM Adapter Implementation
// ============================================================================
// Implementation of the StreamingGGUFLoader MASM backend integration
// ============================================================================

#include "GGUF_MASM_Adapter.h"
#include <fstream>
#include <chrono>
#include <algorithm>

namespace RawrXD {

// ============================================================================
// StreamingGGUFLoaderMASM Implementation
// ============================================================================

bool StreamingGGUFLoaderMASM::LoadFile(const std::string& filepath) {
    // Read entire file into memory
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return false;
    }
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Allocate buffer
    file_data_.resize(size);
    if (!file.read(reinterpret_cast<char*>(file_data_.data()), size)) {
        file_data_.clear();
        return false;
    }
    
    // Initialize MASM backend
    return initialize(file_data_.data(), size);
}

std::vector<TensorInfo> StreamingGGUFLoaderMASM::GetTensorInfo() const {
    std::vector<TensorInfo> infos;
    
    auto iter = get_iterator();
    MASMTensorView view;
    
    while (iter.next(view)) {
        TensorInfo info;
        info.name = view.name();
        info.type = static_cast<GGMLType>(view.type());
        info.offset = view.offset();
        info.size_bytes = view.size_bytes();
        
        // Copy dimensions
        for (uint32_t i = 0; i < view.n_dims(); ++i) {
            info.shape.push_back(view.dim(i));
        }
        
        infos.push_back(std::move(info));
    }
    
    return infos;
}

bool StreamingGGUFLoaderMASM::LoadZone(const std::string& zone_name, uint64_t max_memory_mb) {
    // Get tensors in this zone
    const auto& tensors = get_tensors_in_zone(zone_name);
    if (tensors.empty()) {
        return false;
    }
    
    // Calculate total size needed
    uint64_t total_size = 0;
    for (const auto& name : tensors) {
        auto view = find_tensor(name.c_str());
        if (view.valid()) {
            total_size += view.size_bytes();
        }
    }
    
    // Check memory limit
    if (total_size > max_memory_mb * 1024 * 1024) {
        // Would exceed memory limit - implement eviction policy
        return false;
    }
    
    // Mark zone as loaded
    loaded_zones_[zone_name] = true;
    
    return true;
}

bool StreamingGGUFLoaderMASM::GetTensorData(const std::string& tensor_name, 
                                             std::vector<uint8_t>& data) {
    auto view = find_tensor(tensor_name.c_str());
    if (!view.valid()) {
        return false;
    }
    
    // Copy tensor data
    data.resize(view.size_bytes());
    if (view.data() && !data.empty()) {
        memcpy(data.data(), view.data(), view.size_bytes());
        return true;
    }
    
    return false;
}

// ============================================================================
// C API Implementation
// ============================================================================

} // extern "C"

GGUF_MASM_Context GGUF_MASM_Create(void* data, size_t size) {
    auto* backend = new RawrXD::MASMStreamingBackend();
    if (!backend->initialize(data, size)) {
        delete backend;
        return nullptr;
    }
    return backend;
}

void GGUF_MASM_Destroy(GGUF_MASM_Context ctx) {
    if (ctx) {
        delete static_cast<RawrXD::MASMStreamingBackend*>(ctx);
    }
}

int GGUF_MASM_Next(GGUF_MASM_Context ctx, GGUF_Tensor* tensor) {
    if (!ctx || !tensor) return -1;
    
    auto* backend = static_cast<RawrXD::MASMStreamingBackend*>(ctx);
    auto iter = backend->get_iterator();
    
    // Note: This requires maintaining iterator state in the backend
    // For now, return the next tensor
    RawrXD::MASMTensorView view;
    if (iter.next(view)) {
        // Copy tensor data
        tensor->name_len = static_cast<uint32_t>(strlen(view.name()));
        strncpy_s(tensor->name, sizeof(tensor->name), view.name(), _TRUNCATE);
        tensor->n_dims = view.n_dims();
        for (uint32_t i = 0; i < view.n_dims() && i < GGUF_MAX_DIMS; ++i) {
            tensor->dims[i] = view.dim(i);
        }
        tensor->type = view.type();
        tensor->offset = view.offset();
        tensor->data_ptr = const_cast<void*>(view.data());
        tensor->size_bytes = view.size_bytes();
        return 1;
    }
    
    return 0; // End of stream
}

void GGUF_MASM_Reset(GGUF_MASM_Context ctx) {
    if (!ctx) return;
    auto* backend = static_cast<RawrXD::MASMStreamingBackend*>(ctx);
    backend->get_iterator().reset();
}

uint64_t GGUF_MASM_Count(GGUF_MASM_Context ctx) {
    if (!ctx) return 0;
    auto* backend = static_cast<RawrXD::MASMStreamingBackend*>(ctx);
    return backend->tensor_count();
}

// ============================================================================
// Benchmark Driver
// ============================================================================

#ifdef GGUF_MASM_BENCHMARK

#include <stdio.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <gguf_file>\n", argv[0]);
        return 1;
    }
    
    // Load file
    std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        printf("Failed to open: %s\n", argv[1]);
        return 1;
    }
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    file.close();
    
    printf("GGUF MASM Adapter Benchmark\n");
    printf("===========================\n");
    printf("File: %s\n", argv[1]);
    printf("Size: %.2f MB\n\n", size / (1024.0 * 1024.0));
    
    // Run benchmark
    auto metrics = RawrXD::benchmark_gguf_load(data.data(), size);
    
    printf("Results:\n");
    printf("  Parse time:          %.3f ms\n", metrics.parse_time_ns / 1e6);
    printf("  Tensor iteration:    %.3f ms\n", metrics.tensor_iteration_ns / 1e6);
    printf("  Total tensors:       %llu\n", metrics.total_tensors);
    printf("  Total bytes:         %.2f MB\n", metrics.total_bytes / (1024.0 * 1024.0));
    printf("  Throughput:          %.2f MB/s\n", metrics.throughput_mbps);
    printf("\n");
    
    // Detailed tensor breakdown
    RawrXD::MASMStreamingBackend backend;
    if (backend.initialize(data.data(), size)) {
        printf("Zone Breakdown:\n");
        for (const auto& zone : backend.get_zone_names()) {
            const auto& tensors = backend.get_tensors_in_zone(zone);
            printf("  %-20s: %zu tensors\n", zone.c_str(), tensors.size());
        }
    }
    
    return 0;
}

#endif // GGUF_MASM_BENCHMARK
