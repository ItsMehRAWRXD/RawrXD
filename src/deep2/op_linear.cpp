// RAWRXD_DEEP2_GPU_QUANT_DOT_CLOSURE_001
//
// GPU-first linear op for the Deep2 forward path. Routing only: all arithmetic
// lives in quant_dot_dispatch.cpp and vulkan_compute.cpp.

#include "op_linear.hpp"

#include <ggml.h>

#include <cstdio>
#include <mutex>

namespace RawrXD {
namespace Deep2 {
namespace {

struct LastState {
    bool        used_gpu = false;
    bool        ok       = false;
    int         gguf_type = 0;
    std::string reason;
};
LastState g_last;
std::mutex g_last_mu;

void SetLast(bool ok, bool used_gpu, int t, const char* reason) {
    std::lock_guard<std::mutex> lk(g_last_mu);
    g_last.ok = ok;
    g_last.used_gpu = used_gpu;
    g_last.gguf_type = t;
    g_last.reason = reason ? reason : "";
}

}  // namespace

bool OpLinear(int gguf_type,
              const void* wBytes, size_t wBytesCount,
              const float* x, size_t n_in,
              float* y, size_t n_out,
              const QuantDot::CpuDot& cpu,
              bool gpu_only,
              const void* q8_interleaved,
              size_t q8_bytes) {
    int kind = -1;
    switch (gguf_type) {
        case GGML_TYPE_Q4_K: kind = 0; break;
        case GGML_TYPE_Q6_K: kind = 1; break;
        case GGML_TYPE_F16:
            break;  // handled below via DotF16
        default:
            // Fail-loud contract: callers must see this, never a CPU dequant.
            SetLast(false, false, gguf_type, "unsupported GGML type for GPU quant-dot");
            return false;
    }

    bool used_gpu = false;
    if (gguf_type == GGML_TYPE_F16) {
        used_gpu = QuantDot::DotF16(wBytes, wBytesCount, x, n_in, y, n_out, cpu);
    } else {
        used_gpu = QuantDot::DotBlocked(kind, wBytes, wBytesCount, x, n_in,
                                        y, n_out, cpu, q8_interleaved, q8_bytes);
    }

    if (used_gpu) {
        const QuantDot::Receipt& r = QuantDot::LastReceipt();
        SetLast(true, true, gguf_type, nullptr);
        (void)r;
        return true;
    }

    // CPU path ran (or the call failed). In gpu_only mode this is a failure of
    // the closure, not a silent fallback: report it.
    const QuantDot::Receipt& r = QuantDot::LastReceipt();
    const char* why = r.fallback_reason ? r.fallback_reason : "CPU path executed";
    if (gpu_only) {
        SetLast(false, false, gguf_type, why);
        return false;
    }
    SetLast(true, false, gguf_type, why);
    return true;
}

std::string OpLinearLastReceipt() {
    std::lock_guard<std::mutex> lk(g_last_mu);
    const QuantDot::Receipt& r = QuantDot::LastReceipt();
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "OpLinear{ok=%d used_gpu=%d gpu_rows=%zu cpu_rows=%zu fallback=%s}",
                  (int)g_last.ok, (int)g_last.used_gpu, r.gpu_rows, r.cpu_rows,
                  r.fallback_reason ? r.fallback_reason : "-");
    return std::string(buf);
}

std::string OpLinearLastError() {
    std::lock_guard<std::mutex> lk(g_last_mu);
    return g_last.reason;
}

}  // namespace Deep2
}  // namespace RawrXD
