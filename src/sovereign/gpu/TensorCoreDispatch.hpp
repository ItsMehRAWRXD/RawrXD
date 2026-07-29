// ============================================================================
// TensorCoreDispatch.hpp - Tensor Core & Mixed Precision Dispatch
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

enum class PrecisionMode { FP32, FP16, BF16, FP8, MIXED };
enum class TensorOp { GEMM, GEMV, ATTENTION, CONV, NORM, ACTIVATION };

struct TensorOpConfig {
    TensorOp op;
    PrecisionMode inputPrecision;
    PrecisionMode outputPrecision;
    PrecisionMode computePrecision;
    uint32_t m, n, k;
    bool useTensorCores;
    bool useSubgroups;
    uint32_t tileSizeM, tileSizeN, tileSizeK;
};

class TensorCoreDispatch {
public:
    TensorCoreDispatch();
    ~TensorCoreDispatch();

    bool Initialize();
    void Shutdown();

    bool SelectPrecision(const TensorOpConfig& config);
    PrecisionMode GetOptimalPrecision(TensorOp op, uint32_t m, uint32_t n, uint32_t k) const;
    bool SupportsPrecision(PrecisionMode mode) const;

    bool DispatchGEMV(const float* weights, const float* input, float* output, uint32_t rows, uint32_t cols, PrecisionMode mode);
    bool DispatchGEMM(const float* A, const float* B, float* C, uint32_t m, uint32_t n, uint32_t k, PrecisionMode mode);

    struct TensorCoreStats {
        uint64_t totalDispatches;
        uint64_t fp32Dispatches;
        uint64_t fp16Dispatches;
        uint64_t bf16Dispatches;
        uint64_t fp8Dispatches;
        uint64_t mixedDispatches;
    };
    TensorCoreStats GetStats() const { return stats_; }

private:
    bool initialized_ = false;
    bool hasTensorCores_ = false;
    bool hasFP16_ = false;
    bool hasBF16_ = false;
    bool hasFP8_ = false;
    TensorCoreStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
