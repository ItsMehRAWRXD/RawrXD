/* K2VNNIKernel — AVX-512 VNNI kernel wrapper for K2 packed dot products
 * Provides VNNI-accelerated Q6_K x Q8_K and Q4_K x int8 dot products.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include "rawr_gemm_avx512.h"
#include "K2Telemetry.hpp"

namespace rawrxd {
namespace deep2 {

class K2VNNIKernel {
public:
    static bool is_available() {
        const auto& features = rawrxd::gemm::get_cpu_features();
        return features.has_avx512vnni;
    }

    // Q6_K x Q8_K dot product using VNNI
    static float dot_q6k_q8k_vnni(const rawrxd::gemm::block_q6_K* q6, const rawrxd::gemm::block_q8_K* q8) {
        auto& tel = GetK2Telemetry();
        tel.q6k_q8k_dot_entry.fetch_add(1, std::memory_order_relaxed);
        return rawrxd::gemm::vec_dot_q6_K_q8_K_vnni(q6, q8);
    }

    // Q6_K x Q8_K dot product scalar fallback
    static float dot_q6k_q8k_scalar(const rawrxd::gemm::block_q6_K* q6, const rawrxd::gemm::block_q8_K* q8) {
        auto& tel = GetK2Telemetry();
        tel.q6k_q8k_dot_entry.fetch_add(1, std::memory_order_relaxed);
        return rawrxd::gemm::vec_dot_q6_K_q8_K_scalar(q6, q8);
    }

    // Dispatch: use VNNI if available, otherwise scalar
    static float dot_q6k_q8k(const rawrxd::gemm::block_q6_K* q6, const rawrxd::gemm::block_q8_K* q8) {
        if (is_available()) {
            return dot_q6k_q8k_vnni(q6, q8);
        }
        return dot_q6k_q8k_scalar(q6, q8);
    }
};

} // namespace deep2
} // namespace rawrxd