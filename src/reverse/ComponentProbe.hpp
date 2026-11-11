#pragma once
/**
 * @file ComponentProbe.hpp
 * @brief Reverse compatibility harness — probes each subsystem against reference behavior
 *
 * The goal is not copying llama.cpp. The goal is proving:
 *   - every required tensor has an owner
 *   - every layer has an execution handler
 *   - every activation has a lifetime
 *   - every memory movement has a reason
 */

#include "../runtime/CoreTypes.hpp"
#include <string>
#include <vector>
#include <chrono>
#include <cmath>
#include <iostream>

namespace RawrXD {
namespace Reverse {

// ─── Telemetry ──────────────────────────────────────────────────────────────

struct KernelTelemetry {
    size_t bytes_read;
    size_t bytes_written;
    double milliseconds;
    double tokens_per_second;
};

struct ComparisonResult {
    double cosine_similarity;
    double max_abs_error;
    double mean_squared_error;
    bool within_tolerance;
    KernelTelemetry telemetry;
};

// ─── Logit Comparator ──────────────────────────────────────────────────────

class LogitComparator {
public:
    static ComparisonResult Compare(
        const float* reference_logits,
        const float* rawrxd_logits,
        size_t n,
        double tolerance = 1e-4)
    {
        ComparisonResult r{};
        double dot = 0.0, norm_ref = 0.0, norm_rxd = 0.0;
        double max_err = 0.0, mse = 0.0;

        for (size_t i = 0; i < n; ++i) {
            double ref = static_cast<double>(reference_logits[i]);
            double rxd = static_cast<double>(rawrxd_logits[i]);
            double diff = ref - rxd;

            dot += ref * rxd;
            norm_ref += ref * ref;
            norm_rxd += rxd * rxd;
            max_err = std::max(max_err, std::abs(diff));
            mse += diff * diff;
        }

        r.cosine_similarity = (norm_ref > 0 && norm_rxd > 0)
            ? dot / (std::sqrt(norm_ref) * std::sqrt(norm_rxd))
            : 0.0;
        r.max_abs_error = max_err;
        r.mean_squared_error = mse / static_cast<double>(n);
        r.within_tolerance = r.max_abs_error < tolerance;
        return r;
    }

    static void PrintReport(const ComparisonResult& r, const char* label) {
        std::cout << "[" << label << "] cos_sim=" << r.cosine_similarity
                  << " max_err=" << r.max_abs_error
                  << " mse=" << r.mean_squared_error
                  << " pass=" << (r.within_tolerance ? "YES" : "NO")
                  << std::endl;
    }
};

// ─── Tensor Probe ──────────────────────────────────────────────────────────

class TensorProbe {
public:
    struct TensorInfo {
        std::string name;
        size_t num_elements;
        size_t size_bytes;
        size_t stride;
        std::vector<size_t> shape;
        float min_val;
        float max_val;
        float mean;
        float variance;
    };

    static TensorInfo Probe(const TensorView& tv, const char* label = "tensor") {
        TensorInfo info;
        info.name = label;
        info.num_elements = tv.size;
        info.size_bytes = tv.size * sizeof(float);
        info.stride = tv.stride;
        info.shape = tv.shape;

        double sum = 0.0, sum_sq = 0.0;
        info.min_val = std::numeric_limits<float>::max();
        info.max_val = std::numeric_limits<float>::lowest();

        for (size_t i = 0; i < tv.size; ++i) {
            float v = tv.data[i];
            sum += v;
            sum_sq += v * v;
            info.min_val = std::min(info.min_val, v);
            info.max_val = std::max(info.max_val, v);
        }

        info.mean = static_cast<float>(sum / tv.size);
        info.variance = static_cast<float>(sum_sq / tv.size - info.mean * info.mean);
        return info;
    }

    static void PrintReport(const TensorInfo& info) {
        std::cout << "  Tensor: " << info.name
                  << "  elements=" << info.num_elements
                  << "  bytes=" << info.size_bytes
                  << "  range=[" << info.min_val << ", " << info.max_val << "]"
                  << "  mean=" << info.mean
                  << "  var=" << info.variance
                  << std::endl;
    }
};

// ─── Kernel Probe ──────────────────────────────────────────────────────────

class KernelProbe {
public:
    static KernelTelemetry Measure(
        const std::function<bool()>& kernel_fn,
        size_t bytes_in,
        size_t bytes_out,
        const char* label = "kernel")
    {
        KernelTelemetry t{};
        t.bytes_read = bytes_in;
        t.bytes_written = bytes_out;

        auto start = std::chrono::steady_clock::now();
        bool ok = kernel_fn();
        auto end = std::chrono::steady_clock::now();

        t.milliseconds = std::chrono::duration<double, std::milli>(end - start).count();
        t.tokens_per_second = (t.milliseconds > 0) ? (1000.0 / t.milliseconds) : 0.0;

        std::cout << "[" << label << "] " << (ok ? "OK" : "FAIL")
                  << "  " << t.milliseconds << " ms"
                  << "  " << (bytes_in + bytes_out) / 1024.0 / 1024.0 / (t.milliseconds / 1000.0) << " MB/s"
                  << "  " << t.tokens_per_second << " tok/s"
                  << std::endl;
        return t;
    }
};

// ─── GGUF Loader Probe ─────────────────────────────────────────────────────

class GGUFProbe {
public:
    struct GGUFInfo {
        std::string path;
        size_t file_size;
        uint32_t tensor_count;
        uint32_t metadata_count;
        std::string architecture;
        uint64_t context_length;
        uint64_t embedding_length;
        uint64_t block_count;
        uint64_t head_count;
        uint64_t head_dim;
    };

    // Stub: will call RawrXD_LoadModel when bridge is complete
    static GGUFInfo ProbeFile(const char* path) {
        GGUFInfo info{};
        info.path = path;
        std::cout << "[GGUFProbe] " << path << " — probe stub (bridge pending)" << std::endl;
        return info;
    }
};

// ─── Transformer Block Probe ────────────────────────────────────────────────

class TransformerBlockProbe {
public:
    struct BlockTelemetry {
        KernelTelemetry rmsnorm;
        KernelTelemetry qkv;
        KernelTelemetry rope;
        KernelTelemetry attention;
        KernelTelemetry ffn;
        KernelTelemetry residual;
        double total_ms;
    };

    // Stub: will execute one transformer block when bridge is complete
    static BlockTelemetry ExecuteBlock(uint32_t layer_idx, const TensorView& input) {
        BlockTelemetry t{};
        std::cout << "[TransformerBlock] layer=" << layer_idx
                  << " input_size=" << input.size
                  << " — stub (bridge pending)" << std::endl;
        return t;
    }
};

} // namespace Reverse
} // namespace RawrXD
