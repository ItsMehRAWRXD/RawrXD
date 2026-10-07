// ============================================================================
// GGUF_MASM_Adapter.h - Sovereign MASM Adapter Integration
// ============================================================================
// Bridges the MASM GGUF_NextTensor iterator with StreamingGGUFLoader
// 
// This adapter replaces the C++ tensor parsing logic with the optimized
// MASM implementation for maximum throughput.
// ============================================================================

#pragma once

#include "GGUF_NextTensor.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {

// ============================================================================
// MASM-Accelerated Tensor View
// ============================================================================
// Lightweight wrapper around GGUF_Tensor with C++ conveniences
class MASMTensorView {
public:
    MASMTensorView() = default;
    explicit MASMTensorView(const GGUF_Tensor* tensor) : tensor_(tensor) {}
    
    // Accessors
    const char* name() const { return tensor_ ? tensor_->name : nullptr; }
    uint32_t n_dims() const { return tensor_ ? tensor_->n_dims : 0; }
    const uint64_t* dims() const { return tensor_ ? tensor_->dims : nullptr; }
    uint32_t type() const { return tensor_ ? tensor_->type : 0; }
    uint64_t offset() const { return tensor_ ? tensor_->offset : 0; }
    const void* data() const { return tensor_ ? tensor_->data_ptr : nullptr; }
    uint64_t size_bytes() const { return tensor_ ? tensor_->size_bytes : 0; }
    
    // Type queries
    bool is_quantized() const { return tensor_ ? GGUF_IsTypeQuantized(tensor_->type) : false; }
    const char* type_name() const { return tensor_ ? GGUF_GetTypeName(tensor_->type) : "unknown"; }
    size_t element_size() const { return tensor_ ? GGUF_GetTypeSize(tensor_->type) : 0; }
    
    // Calculate total elements
    uint64_t element_count() const {
        if (!tensor_) return 0;
        return GGUF_CalculateElementCount(tensor_->n_dims, tensor_->dims);
    }
    
    // Shape helpers
    uint64_t dim(size_t idx) const {
        if (!tensor_ || idx >= tensor_->n_dims) return 0;
        return tensor_->dims[idx];
    }
    
    // Common tensor patterns
    bool is_weight() const {
        const char* n = name();
        return n && (strstr(n, "weight") || strstr(n, "w"));
    }
    
    bool is_bias() const {
        const char* n = name();
        return n && strstr(n, "bias");
    }
    
    bool is_embedding() const {
        const char* n = name();
        return n && strstr(n, "embed");
    }
    
    bool is_attention() const {
        const char* n = name();
        return n && (strstr(n, "attn") || strstr(n, "attention") || 
                     strstr(n, "q_proj") || strstr(n, "k_proj") || strstr(n, "v_proj"));
    }
    
    bool is_layer_tensor(int* layer_num = nullptr) const {
        const char* n = name();
        if (!n) return false;
        
        // Pattern: blk.N.XXX or layers.N.XXX or transformer.h.N
        const char* patterns[] = {"blk.", "layers.", "model.layers.", "transformer.h."};
        for (const char* pat : patterns) {
            const char* found = strstr(n, pat);
            if (found) {
                int num = atoi(found + strlen(pat));
                if (layer_num) *layer_num = num;
                return true;
            }
        }
        return false;
    }
    
    // Zone classification for streaming
    std::string get_zone_name() const {
        int layer_num;
        if (is_layer_tensor(&layer_num)) {
            // Group layers into zones of 4
            int zone_start = (layer_num / 4) * 4;
            int zone_end = zone_start + 3;
            char buf[64];
            sprintf_s(buf, "layers_%d_%d", zone_start, zone_end);
            return std::string(buf);
        }
        
        const char* n = name();
        if (!n) return "unknown";
        
        if (strstr(n, "embed")) return "embedding";
        if (strstr(n, "norm") || strstr(n, "ln_")) return "normalization";
        if (strstr(n, "lm_head") || strstr(n, "output")) return "output";
        if (strstr(n, "rope")) return "rope";
        
        return "other";
    }
    
    // Data access with type safety
    template<typename T>
    const T* typed_data() const {
        return static_cast<const T*>(data());
    }
    
    // Validity check
    explicit operator bool() const { return tensor_ != nullptr; }
    bool valid() const { return tensor_ != nullptr; }

private:
    const GGUF_Tensor* tensor_ = nullptr;
};

// ============================================================================
// MASM-Accelerated GGUF Iterator
// ============================================================================
// High-performance iterator using the MASM backend
class MASMTensorIterator {
public:
    MASMTensorIterator() = default;
    explicit MASMTensorIterator(GGUF_Context* ctx) : context_(ctx) {}
    
    // Iterator protocol
    bool next(MASMTensorView& view) {
        if (!context_) return false;
        
        int result = GGUF_NextTensor(context_, &current_tensor_);
        if (result == 1) {
            view = MASMTensorView(&current_tensor_);
            return true;
        }
        return false;
    }
    
    // Reset to beginning
    void reset() {
        if (context_) {
            GGUF_ResetIterator(context_);
        }
    }
    
    // Count remaining tensors
    uint64_t remaining() const {
        if (!context_) return 0;
        uint64_t total = GGUF_GetTensorCount(context_);
        uint64_t current = context_->current_idx;
        return (total > current) ? (total - current) : 0;
    }
    
    // Total count
    uint64_t total() const {
        return context_ ? GGUF_GetTensorCount(context_) : 0;
    }
    
    // Current position
    uint64_t position() const {
        return context_ ? context_->current_idx : 0;
    }
    
    // For-each support
    template<typename Func>
    void for_each(Func&& fn) {
        MASMTensorView view;
        while (next(view)) {
            fn(view);
        }
    }
    
    // Filtered iteration
    template<typename Func, typename Pred>
    void for_each_if(Pred&& predicate, Func&& fn) {
        MASMTensorView view;
        while (next(view)) {
            if (predicate(view)) {
                fn(view);
            }
        }
    }
    
    // Collect all tensors matching predicate
    template<typename Pred>
    std::vector<MASMTensorView> collect(Pred&& predicate) {
        std::vector<MASMTensorView> results;
        MASMTensorView view;
        while (next(view)) {
            if (predicate(view)) {
                results.push_back(view);
            }
        }
        return results;
    }

private:
    GGUF_Context* context_ = nullptr;
    GGUF_Tensor current_tensor_;
};

// ============================================================================
// Streaming Loader MASM Backend
// ============================================================================
// Drop-in replacement backend for StreamingGGUFLoader
class MASMStreamingBackend {
public:
    MASMStreamingBackend() = default;
    ~MASMStreamingBackend() { cleanup(); }
    
    // Initialize from file data
    bool initialize(void* gguf_data, size_t size) {
        cleanup();
        
        context_ = static_cast<GGUF_Context*>(
            GGUF_CreateContext(gguf_data, size)
        );
        
        if (!context_) {
            return false;
        }
        
        // Build zone index
        build_zone_index();
        return true;
    }
    
    // Cleanup
    void cleanup() {
        if (context_) {
            GGUF_DestroyContext(context_);
            context_ = nullptr;
        }
        zone_tensors_.clear();
    }
    
    // Get iterator
    MASMTensorIterator get_iterator() const {
        return MASMTensorIterator(context_);
    }
    
    // Zone-based access
    const std::vector<std::string>& get_zone_names() const {
        return zone_names_;
    }
    
    const std::vector<std::string>& get_tensors_in_zone(const std::string& zone) const {
        auto it = zone_tensors_.find(zone);
        if (it != zone_tensors_.end()) {
            return it->second;
        }
        static std::vector<std::string> empty;
        return empty;
    }
    
    // Get tensor by name (requires scan - use zone-based for performance)
    MASMTensorView find_tensor(const char* name) {
        if (!context_) return MASMTensorView();
        
        GGUF_ResetIterator(context_);
        MASMTensorView view;
        MASMTensorIterator iter(context_);
        
        while (iter.next(view)) {
            if (strcmp(view.name(), name) == 0) {
                return view;
            }
        }
        
        return MASMTensorView();
    }
    
    // Statistics
    uint64_t tensor_count() const {
        return context_ ? GGUF_GetTensorCount(context_) : 0;
    }
    
    // Error handling
    uint32_t error_code() const {
        return context_ ? context_->error_code : 0;
    }
    
    const char* error_string() const {
        switch (error_code()) {
            case 0: return "OK";
            case 1: return "Invalid type";
            case 2: return "Invalid dimensions";
            case 3: return "End of stream";
            case 4: return "Memory error";
            default: return "Unknown";
        }
    }

private:
    GGUF_Context* context_ = nullptr;
    std::vector<std::string> zone_names_;
    std::unordered_map<std::string, std::vector<std::string>> zone_tensors_;
    
    void build_zone_index() {
        zone_tensors_.clear();
        zone_names_.clear();
        
        MASMTensorIterator iter(context_);
        MASMTensorView view;
        
        while (iter.next(view)) {
            std::string zone = view.get_zone_name();
            zone_tensors_[zone].push_back(view.name());
        }
        
        // Collect unique zone names
        for (const auto& [zone, _] : zone_tensors_) {
            zone_names_.push_back(zone);
        }
        
        // Reset iterator for user
        iter.reset();
    }
};

// ============================================================================
// Performance Benchmarking
// ============================================================================
struct GGUFLoadMetrics {
    uint64_t parse_time_ns = 0;          // Time to parse header
    uint64_t tensor_iteration_ns = 0;    // Time to iterate all tensors
    uint64_t first_token_latency_ns = 0; // Time to first token
    uint64_t total_tensors = 0;
    uint64_t total_bytes = 0;
    double throughput_mbps = 0.0;        // MB/s parsing throughput
};

// Benchmark function
inline GGUFLoadMetrics benchmark_gguf_load(void* gguf_data, size_t size) {
    GGUFLoadMetrics metrics;
    
    auto t1 = std::chrono::high_resolution_clock::now();
    
    MASMStreamingBackend backend;
    if (!backend.initialize(gguf_data, size)) {
        return metrics;
    }
    
    auto t2 = std::chrono::high_resolution_clock::now();
    metrics.parse_time_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
    
    // Iterate all tensors
    auto iter = backend.get_iterator();
    MASMTensorView view;
    
    auto t3 = std::chrono::high_resolution_clock::now();
    
    while (iter.next(view)) {
        metrics.total_tensors++;
        metrics.total_bytes += view.size_bytes();
    }
    
    auto t4 = std::chrono::high_resolution_clock::now();
    metrics.tensor_iteration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t4 - t3).count();
    
    // Calculate throughput
    double seconds = metrics.tensor_iteration_ns / 1e9;
    if (seconds > 0) {
        metrics.throughput_mbps = (metrics.total_bytes / (1024.0 * 1024.0)) / seconds;
    }
    
    return metrics;
}

// ============================================================================
// Integration Helpers for StreamingGGUFLoader
// ============================================================================

// Adapter to bridge MASM backend with existing loader interface
class StreamingGGUFLoaderMASM : public MASMStreamingBackend {
public:
    // Load file and initialize MASM context
    bool LoadFile(const std::string& filepath);
    
    // Get tensor info compatible with existing code
    std::vector<TensorInfo> GetTensorInfo() const;
    
    // Zone-based loading
    bool LoadZone(const std::string& zone_name, uint64_t max_memory_mb = 512);
    
    // Get tensor data
    bool GetTensorData(const std::string& tensor_name, std::vector<uint8_t>& data);
    
    // Access underlying MASM iterator
    MASMTensorIterator GetIterator() const { return get_iterator(); }
};

} // namespace RawrXD

// ============================================================================
// C Integration Macros
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Quick C API for direct MASM access
typedef void* GGUF_MASM_Context;

// Create context from file data
GGUF_MASM_Context GGUF_MASM_Create(void* data, size_t size);

// Destroy context
void GGUF_MASM_Destroy(GGUF_MASM_Context ctx);

// Get next tensor (returns 1 on success, 0 on EOS, -1 on error)
int GGUF_MASM_Next(GGUF_MASM_Context ctx, GGUF_Tensor* tensor);

// Reset iterator
void GGUF_MASM_Reset(GGUF_MASM_Context ctx);

// Get tensor count
uint64_t GGUF_MASM_Count(GGUF_MASM_Context ctx);

#ifdef __cplusplus
}
#endif
