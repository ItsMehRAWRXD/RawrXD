// deep2_execution_trace.hpp - Authoritative execution trace for Deep2 inference
// Provides per-layer, per-token, per-operation timing and dispatch evidence

#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>
#include <array>
#include <optional>

namespace rawrxd::deep2::trace {

enum class Operation : uint8_t {
    EmbeddingLookup,
    RmsNorm,
    Linear,
    Attention,
    MlaDecompress,
    Router,
    TopK,
    MoEExecute,
    ResidualAdd,
    LmHead,
    SsmScan,
    SwiGLU,
    SquaredReLU,
    Other
};

enum class Backend : uint8_t {
    Unknown,
    CPU,
    Vulkan,
    Fallback
};

struct OpTraceRecord {
    uint64_t token_index = 0;
    size_t position = 0;
    Operation op = Operation::Other;
    int32_t block = -1;
    std::string op_name;
    std::string weight_name;
    std::string input_name;
    size_t output_size = 0;
    Backend backend = Backend::Unknown;
    bool fallback = false;
    std::string fallback_reason;
    bool forced_cpu = false;
    double cpu_time_ms = 0.0;
    double gpu_submit_ms = 0.0;
    double gpu_sync_ms = 0.0;
    double dequant_ms = 0.0;
    double weight_transfer_ms = 0.0;
    uint64_t checksum = 0;
    float first_vals[8] = {0};
    uint32_t layer_executions = 0;  // For prefill: how many layer passes this op triggered
};

struct LayerTraceRecord {
    uint64_t token_index = 0;
    size_t position = 0;
    int32_t block = -1;
    double layer_start_ms = 0;
    double layer_end_ms = 0;
    size_t ops_in_layer = 0;
    size_t gpu_dispatches_in_layer = 0;
    size_t cpu_ops_in_layer = 0;
    bool all_gpu = true;
};

struct PrefillTraceRecord {
    uint64_t request_id = 0;
    size_t input_tokens = 0;
    size_t batch_size = 0;
    int32_t layer_count = 0;
    uint64_t total_layer_executions = 0;  // Critical: counts actual layer passes
    double total_prefill_ms = 0;
    double cpu_kernel_ms = 0;
    double gpu_kernel_ms = 0;
    double gpu_sync_ms = 0;
    double dequantization_ms = 0;
    double weight_transfer_ms = 0;
    double dispatch_overhead_ms = 0;
    size_t kv_reused_tokens = 0;
    size_t kv_appended_tokens = 0;
    bool used_batched_prefill = false;
};

struct DecodeTraceRecord {
    uint64_t request_id = 0;
    size_t tokens_generated = 0;
    double total_decode_ms = 0;
    double cpu_kernel_ms = 0;
    double gpu_kernel_ms = 0;
    double gpu_sync_ms = 0;
    double dequantization_ms = 0;
    double weight_transfer_ms = 0;
};

struct KVCacheTraceRecord {
    std::string model_fingerprint;
    size_t valid_prefix_tokens = 0;
    size_t reused_tokens = 0;
    size_t appended_tokens = 0;
    bool fingerprint_match = false;
    bool positional_match = false;
    bool model_match = false;
    bool tokenizer_match = false;
};

struct ExecutionTrace {
    std::vector<OpTraceRecord> op_traces;
    std::vector<LayerTraceRecord> layer_traces;
    std::optional<PrefillTraceRecord> prefill;
    std::optional<DecodeTraceRecord> decode;
    KVCacheTraceRecord kv_cache;
    std::string model_name;
    std::string model_fingerprint;
    uint64_t request_id = 0;
    uint64_t executor_id = 0;
    uint32_t device_id = 0;
    
    void clear() {
        op_traces.clear();
        layer_traces.clear();
        prefill.reset();
        decode.reset();
        kv_cache = {};
    }
};

class ExecutionTracer {
    // mutable: the read-only accessors (getTrace, isActive, ...) take the lock
    // on a const tracer, which requires locking a non-const mutex.
    mutable std::mutex mutex_;
    ExecutionTrace current_trace_;
    bool active_ = false;
    uint64_t next_request_id_ = 1;
    uint64_t next_executor_id_ = 1;
    
    // Current operation timing
    std::chrono::steady_clock::time_point op_start_;
    std::chrono::steady_clock::time_point layer_start_;
    int32_t current_block_ = -1;
    size_t current_token_ = 0;
    bool in_layer_ = false;
    size_t layer_ops_ = 0;
    size_t layer_gpu_dispatches_ = 0;
    size_t layer_cpu_ops_ = 0;
    bool layer_all_gpu_ = true;
    
public:
    ExecutionTracer() = default;
    
    // Begin a new request trace
    uint64_t beginRequest(const std::string& model_name, uint32_t device_id = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        current_trace_.clear();
        current_trace_.model_name = model_name;
        current_trace_.request_id = next_request_id_++;
        current_trace_.executor_id = next_executor_id_++;
        current_trace_.device_id = device_id;
        active_ = true;
        return current_trace_.request_id;
    }
    
    // End the current request
    ExecutionTrace endRequest() {
        std::lock_guard<std::mutex> lock(mutex_);
        ExecutionTrace result = current_trace_;
        active_ = false;
        return result;
    }
    
    // Begin prefill trace
    void beginPrefill(size_t input_tokens, size_t batch_size, int32_t layer_count, bool batched) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        current_trace_.prefill = PrefillTraceRecord{};
        current_trace_.prefill->request_id = current_trace_.request_id;
        current_trace_.prefill->input_tokens = input_tokens;
        current_trace_.prefill->batch_size = batch_size;
        current_trace_.prefill->layer_count = layer_count;
        current_trace_.prefill->used_batched_prefill = batched;
    }
    
    void endPrefill(double total_ms, double cpu_ms, double gpu_ms, double sync_ms,
                    double dequant_ms, double weight_xfer_ms, double dispatch_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || !current_trace_.prefill) return;
        auto& p = *current_trace_.prefill;
        p.total_prefill_ms = total_ms;
        p.cpu_kernel_ms = cpu_ms;
        p.gpu_kernel_ms = gpu_ms;
        p.gpu_sync_ms = sync_ms;
        p.dequantization_ms = dequant_ms;
        p.weight_transfer_ms = weight_xfer_ms;
        p.dispatch_overhead_ms = dispatch_ms;
    }
    
    void addPrefillLayerExecution() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || !current_trace_.prefill) return;
        current_trace_.prefill->total_layer_executions++;
    }
    
    void addPrefillKVReused(size_t tokens) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || !current_trace_.prefill) return;
        current_trace_.prefill->kv_reused_tokens += tokens;
    }
    
    void addPrefillKVAppended(size_t tokens) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || !current_trace_.prefill) return;
        current_trace_.prefill->kv_appended_tokens += tokens;
    }
    
    // Begin decode trace
    void beginDecode() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        current_trace_.decode = DecodeTraceRecord{};
        current_trace_.decode->request_id = current_trace_.request_id;
    }
    
    void endDecode(double total_ms, double cpu_ms, double gpu_ms, double sync_ms,
                   double dequant_ms, double weight_xfer_ms) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || !current_trace_.decode) return;
        auto& d = *current_trace_.decode;
        d.total_decode_ms = total_ms;
        d.cpu_kernel_ms = cpu_ms;
        d.gpu_kernel_ms = gpu_ms;
        d.gpu_sync_ms = sync_ms;
        d.dequantization_ms = dequant_ms;
        d.weight_transfer_ms = weight_xfer_ms;
    }
    
    void incrementDecodeTokens() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || !current_trace_.decode) return;
        current_trace_.decode->tokens_generated++;
    }
    
    // KV cache trace
    void setKVCacheTrace(const KVCacheTraceRecord& kv) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        current_trace_.kv_cache = kv;
    }
    
    // Per-layer tracing
    void beginLayer(int32_t block, size_t token_index, size_t position) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        in_layer_ = true;
        current_block_ = block;
        current_token_ = token_index;
        layer_start_ = std::chrono::steady_clock::now();
        layer_ops_ = 0;
        layer_gpu_dispatches_ = 0;
        layer_cpu_ops_ = 0;
        layer_all_gpu_ = true;
    }
    
    void endLayer() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_ || !in_layer_) return;
        auto now = std::chrono::steady_clock::now();
        LayerTraceRecord rec;
        rec.token_index = current_token_;
        rec.position = current_token_;
        rec.block = current_block_;
        rec.layer_start_ms = 0;  // Relative to token start
        rec.layer_end_ms = std::chrono::duration<double, std::milli>(now - layer_start_).count();
        rec.ops_in_layer = layer_ops_;
        rec.gpu_dispatches_in_layer = layer_gpu_dispatches_;
        rec.cpu_ops_in_layer = layer_cpu_ops_;
        rec.all_gpu = layer_all_gpu_;
        current_trace_.layer_traces.push_back(rec);
        in_layer_ = false;
    }
    
    // Per-operation tracing
    void beginOp(Operation op, int32_t block, const std::string& op_name,
                 const std::string& weight_name, const std::string& input_name,
                 size_t output_size, size_t token_index, size_t position) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        op_start_ = std::chrono::steady_clock::now();
        // Record in current layer if active
        if (in_layer_) {
            layer_ops_++;
        }
    }
    
    void endOp(Backend backend, bool fallback, const std::string& fallback_reason,
               bool forced_cpu, double cpu_ms, double gpu_submit_ms, double gpu_sync_ms,
               double dequant_ms, double weight_xfer_ms, uint64_t checksum,
               const float* first_vals, uint32_t layer_executions) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        
        OpTraceRecord rec;
        rec.token_index = current_token_;
        rec.position = current_token_;
        rec.op = current_op_;
        rec.block = current_block_;
        rec.op_name = current_op_name_;
        rec.weight_name = current_weight_name_;
        rec.input_name = current_input_name_;
        rec.output_size = current_output_size_;
        rec.backend = backend;
        rec.fallback = fallback;
        rec.fallback_reason = fallback_reason;
        rec.forced_cpu = forced_cpu;
        rec.cpu_time_ms = cpu_ms;
        rec.gpu_submit_ms = gpu_submit_ms;
        rec.gpu_sync_ms = gpu_sync_ms;
        rec.dequant_ms = dequant_ms;
        rec.weight_transfer_ms = weight_xfer_ms;
        rec.checksum = checksum;
        rec.layer_executions = layer_executions;
        if (first_vals) {
            for (int i = 0; i < 8; ++i) rec.first_vals[i] = first_vals[i];
        }
        
        if (in_layer_) {
            if (backend == Backend::Vulkan) layer_gpu_dispatches_++;
            else layer_cpu_ops_++;
            if (backend != Backend::Vulkan) layer_all_gpu_ = false;
        }
        
        current_trace_.op_traces.push_back(rec);
    }
    
    // Record GPU dispatch
    void recordGPUDispatch(size_t count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        if (in_layer_) layer_gpu_dispatches_ += count;
    }
    
    // Record CPU operation
    void recordCPUOp(size_t count = 1) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        if (in_layer_) layer_cpu_ops_ += count;
    }
    
    // Record weight transfer bytes
    void recordWeightTransfer(uint64_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_) return;
        // Could aggregate per-op or globally
    }
    
    // Access current trace (read-only)
    const ExecutionTrace& getTrace() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return current_trace_;
    }
    
    bool isActive() const { return active_; }
    
    // Set model fingerprint
    void setModelFingerprint(const std::string& fingerprint) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_) current_trace_.model_fingerprint = fingerprint;
    }
    
private:
    Operation current_op_ = Operation::Other;
    std::string current_op_name_;
    std::string current_weight_name_;
    std::string current_input_name_;
    size_t current_output_size_ = 0;
};

// Global tracer instance
inline ExecutionTracer& GlobalTracer() {
    static ExecutionTracer tracer;
    return tracer;
}

// Convenience macros for instrumentation
#define DEEP2_TRACE_BEGIN_REQUEST(model, device) \
    rawrxd::deep2::trace::GlobalTracer().beginRequest(model, device)

#define DEEP2_TRACE_END_REQUEST() \
    rawrxd::deep2::trace::GlobalTracer().endRequest()

#define DEEP2_TRACE_PREFILL_START(tokens, batch, layers, batched) \
    rawrxd::deep2::trace::GlobalTracer().beginPrefill(tokens, batch, layers, batched)

#define DEEP2_TRACE_PREFILL_END(total, cpu, gpu, sync, dequant, weight, dispatch) \
    rawrxd::deep2::trace::GlobalTracer().endPrefill(total, cpu, gpu, sync, dequant, weight, dispatch)

#define DEEP2_TRACE_PREFILL_LAYER_EXEC() \
    rawrxd::deep2::trace::GlobalTracer().addPrefillLayerExecution()

#define DEEP2_TRACE_KV_REUSED(tokens) \
    rawrxd::deep2::trace::GlobalTracer().addPrefillKVReused(tokens)

#define DEEP2_TRACE_KV_APPENDED(tokens) \
    rawrxd::deep2::trace::GlobalTracer().addPrefillKVAppended(tokens)

#define DEEP2_TRACE_DECODE_START() \
    rawrxd::deep2::trace::GlobalTracer().beginDecode()

#define DEEP2_TRACE_DECODE_END(total, cpu, gpu, sync, dequant, weight) \
    rawrxd::deep2::trace::GlobalTracer().endDecode(total, cpu, gpu, sync, dequant, weight)

#define DEEP2_TRACE_DECODE_TOKEN() \
    rawrxd::deep2::trace::GlobalTracer().incrementDecodeTokens()

#define DEEP2_TRACE_LAYER_START(block, token, pos) \
    rawrxd::deep2::trace::GlobalTracer().beginLayer(block, token, pos)

#define DEEP2_TRACE_LAYER_END() \
    rawrxd::deep2::trace::GlobalTracer().endLayer()

#define DEEP2_TRACE_OP_START(op, block, name, weight, input, out_size, token, pos) \
    do { \
        rawrxd::deep2::trace::GlobalTracer().beginOp( \
            rawrxd::deep2::trace::Operation::op, \
            block, name, weight, input, out_size, token, pos); \
    } while(0)

#define DEEP2_TRACE_OP_END(backend, fallback, reason, forced, cpu, gpu_submit, gpu_sync, \
                           dequant, weight, checksum, first_vals, layer_execs) \
    rawrxd::deep2::trace::GlobalTracer().endOp( \
        rawrxd::deep2::trace::Backend::backend, fallback, reason, forced, \
        cpu, gpu_submit, gpu_sync, dequant, weight, checksum, first_vals, layer_execs)

#define DEEP2_TRACE_GPU_DISPATCH(count) \
    rawrxd::deep2::trace::GlobalTracer().recordGPUDispatch(count)

#define DEEP2_TRACE_CPU_OP(count) \
    rawrxd::deep2::trace::GlobalTracer().recordCPUOp(count)

#define DEEP2_TRACE_WEIGHT_TRANSFER(bytes) \
    rawrxd::deep2::trace::GlobalTracer().recordWeightTransfer(bytes)

#define DEEP2_TRACE_KV_CACHE(kv) \
    rawrxd::deep2::trace::GlobalTracer().setKVCacheTrace(kv)

#define DEEP2_TRACE_MODEL_FINGERPRINT(fp) \
    rawrxd::deep2::trace::GlobalTracer().setModelFingerprint(fp)

} // namespace rawrxd::deep2::trace