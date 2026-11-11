// ============================================================================
// StrataInt8KVCache.hpp  --  RAWRXD_DEEP2_STRATA_S06
// ============================================================================
// Native INT8 (Q8_0) KV-cache storage for the Deep2 runtime graph executor.
//
// The executor's KV cache is FP32 (with F16 rounding on write to match
// llama.cpp - see OpAttention). This header adds an INT8 storage tier with
// ggml's Q8_0 block semantics:
//
//   block = 32 values: one FP32 scale `d` + 32 signed INT8 codes `qs`.
//   d = amax(|x|) / 127,  qs[i] = round(x[i] / d)
//   x_hat = d * qs[i]
//
// 36 bytes of payload per 32 values versus 128 bytes of FP32: a 71.9%
// storage reduction before any metadata (llama.cpp's own figure for -ctk q8_0).
//
// Integration contract (runtime_graph_executor.cpp, opt-in, default OFF so
// every previously certified run keeps its exact numerics):
//   * On KV write, each row is mirrored into the INT8 store and the FP32 row
//     the attention reads is replaced by its INT8 round-trip, so attention
//     consumes exactly the quantised representation and parity is measurable.
//   * The MLA latent cache (kvat_) is NOT touched: DeepSeek's compressed
//     latent is a model-defined representation, not a plain K/V row, and
//     quantising it as if it were one would be a silent correctness change.
//
// Header-only, no external dependencies.
// ============================================================================
#pragma once

#include <cmath>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>

namespace RawrXD {
namespace Deep2 {
namespace Strata {

// One Q8_0 block: 32 values share an FP32 scale.
struct Q8_0Block {
    float d = 0.0f;
    int8_t qs[32] = {0};
};

// Per-row error tracking for parity evidence.
struct Int8KVStats {
    uint64_t k_rows = 0;
    uint64_t v_rows = 0;
    uint64_t blocks = 0;               // Q8_0 blocks stored
    uint64_t q8_bytes = 0;             // bytes held in INT8 form
    uint64_t fp32_equivalent = 0;      // bytes the same rows would take as FP32
    uint64_t max_abs_err_count = 0;    // rows whose round-trip error was tracked
    double max_abs_err = 0.0;          // worst |x - x_hat| observed
    double sum_abs_err = 0.0;          // for the mean over tracked values
    uint64_t err_values = 0;
    double SavingsRatio() const
    {
        return fp32_equivalent ? 1.0 - (double)q8_bytes / (double)fp32_equivalent : 0.0;
    }
    double MeanAbsErr() const { return err_values ? sum_abs_err / (double)err_values : 0.0; }
};

class Int8KVCache {
public:
    // Quantise one row (n values) into Q8_0 blocks. n need not divide 32;
    // the final block is zero-padded (its codes are never read back beyond n).
    static void QuantizeRow(const float* src, size_t n, std::vector<Q8_0Block>& dst)
    {
        dst.clear();
        const size_t blocks = (n + 31) / 32;
        dst.resize(blocks);
        for (size_t b = 0; b < blocks; ++b) {
            const size_t base = b * 32;
            const size_t count = (n - base < 32) ? (n - base) : 32;
            float amax = 0.0f;
            for (size_t i = 0; i < count; ++i) {
                const float a = std::fabs(src[base + i]);
                if (a > amax) amax = a;
            }
            const float d = amax / 127.0f;
            const float inv = (d > 0.0f) ? 1.0f / d : 0.0f;
            dst[b].d = d;
            for (size_t i = 0; i < count; ++i) {
                const float q = src[base + i] * inv;
                int v = (int)std::lround(q);
                if (v > 127) v = 127;
                if (v < -127) v = -127;
                dst[b].qs[i] = (int8_t)v;
            }
            for (size_t i = count; i < 32; ++i)
                dst[b].qs[i] = 0;
        }
    }

    // Dequantise one row back to FP32.
    static void DequantizeRow(const std::vector<Q8_0Block>& src, size_t n, float* dst)
    {
        for (size_t i = 0; i < n; ++i) {
            const Q8_0Block& b = src[i / 32];
            dst[i] = b.d * (float)b.qs[i % 32];
        }
    }

    // Quantise then dequantise a row, writing the round-trip result to `out`
    // (resized to n). This is what the attention path consumes when the INT8
    // tier is enabled, so the parity of the quantised representation is
    // exercised by every attention read.
    void RoundTripRow(const float* src, size_t n, std::vector<float>& out)
    {
        std::vector<Q8_0Block> blocks;
        QuantizeRow(src, n, blocks);
        out.resize(n);
        DequantizeRow(blocks, n, out.data());
        // Parity accounting: track worst and accumulated absolute error.
        for (size_t i = 0; i < n; ++i) {
            const double e = std::fabs((double)src[i] - (double)out[i]);
            if (e > max_abs_err_) max_abs_err_ = e;
            sum_abs_err_ += e;
            ++err_values_;
        }
        q8_bytes_ += blocks.size() * sizeof(Q8_0Block);
        fp32_equivalent_ += n * sizeof(float);
        ++blocks_;
    }

    // Mirror a K (or V) row into the INT8 store for layer `layer`, growing the
    // store one row at a time exactly like the executor's FP32 cache.
    void AppendK(int layer, const float* row, size_t n)
    {
        EnsureLayer(layer);
        std::vector<Q8_0Block> blocks;
        QuantizeRow(row, n, blocks);
        const size_t nb = blocks.size();
        k_[(size_t)layer].push_back(std::move(blocks));
        ++k_rows_;
        q8_bytes_ += nb * sizeof(Q8_0Block);
        fp32_equivalent_ += n * sizeof(float);
        blocks_ += nb;
    }

    void AppendV(int layer, const float* row, size_t n)
    {
        EnsureLayer(layer);
        std::vector<Q8_0Block> blocks;
        QuantizeRow(row, n, blocks);
        const size_t nb = blocks.size();
        v_[(size_t)layer].push_back(std::move(blocks));
        ++v_rows_;
        q8_bytes_ += nb * sizeof(Q8_0Block);
        fp32_equivalent_ += n * sizeof(float);
        blocks_ += nb;
    }

    // Dequantise one stored row back out (used by long-context verification).
    void ReadK(int layer, size_t row, size_t n, float* dst) const
    {
        if ((size_t)layer >= k_.size() || row >= k_[(size_t)layer].size()) return;
        DequantizeRow(k_[(size_t)layer][row], n, dst);
    }

    void ReadV(int layer, size_t row, size_t n, float* dst) const
    {
        if ((size_t)layer >= v_.size() || row >= v_[(size_t)layer].size()) return;
        DequantizeRow(v_[(size_t)layer][row], n, dst);
    }

    Int8KVStats Snapshot() const
    {
        Int8KVStats s;
        s.k_rows = k_rows_;
        s.v_rows = v_rows_;
        s.blocks = blocks_;
        s.q8_bytes = q8_bytes_;
        s.fp32_equivalent = fp32_equivalent_;
        s.max_abs_err = max_abs_err_;
        s.sum_abs_err = sum_abs_err_;
        s.err_values = err_values_;
        return s;
    }

    void Reset()
    {
        k_.clear();
        v_.clear();
        k_rows_ = v_rows_ = blocks_ = 0;
        q8_bytes_ = fp32_equivalent_ = 0;
        max_abs_err_ = 0.0;
        sum_abs_err_ = 0.0;
        err_values_ = 0;
    }

private:
    void EnsureLayer(int layer)
    {
        if ((size_t)layer >= k_.size()) {
            k_.resize((size_t)layer + 1);
            v_.resize((size_t)layer + 1);
        }
    }
    // [layer][row] -> that row's Q8_0 blocks.
    std::vector<std::vector<std::vector<Q8_0Block>>> k_, v_;
    uint64_t k_rows_ = 0, v_rows_ = 0, blocks_ = 0;
    uint64_t q8_bytes_ = 0, fp32_equivalent_ = 0;
    double max_abs_err_ = 0.0, sum_abs_err_ = 0.0;
    uint64_t err_values_ = 0;
};

}   // namespace Strata
}   // namespace Deep2
}   // namespace RawrXD
