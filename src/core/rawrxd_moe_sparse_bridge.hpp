#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <windows.h>

namespace RawrXD::MoE {

struct MoeConfig {
    uint32_t num_experts;
    uint32_t top_k;
    uint32_t hidden_dim;
    uint32_t ffn_dim;
    uint32_t weight_dtype;
    uint64_t expert_size_bytes;
    void* weights_base;
    void* scales_base;
};

// Externs for MASM kernel
extern "C" void* SparseGather_Initialize(MoeConfig* config, void* telemetry_handle);
extern "C" int SparseGather_Execute(void* context, float* input, float* router_logits, float* output, uint32_t layer_index);
extern "C" void SparseGather_FlushCache(void* context);
extern "C" void SparseGather_GetStats(void* context, uint64_t* loaded, uint64_t* skipped);

class SparseGatherBridge {
public:
    static inline bool ShouldFailLoud() {
        // Default to soft-fail for IDE stability.
        // Set RAWRXD_SPARSEGATHER_FAIL_LOUD=1 to enable hard abort on misconfig.
        char buf[8] = {};
        const DWORD n = GetEnvironmentVariableA("RAWRXD_SPARSEGATHER_FAIL_LOUD", buf, static_cast<DWORD>(sizeof(buf)));
        if (n == 0) {
            return false;  // Default: soft-fail for IDE mode
        }
        return (buf[0] == '1' || buf[0] == 'y' || buf[0] == 'Y' || buf[0] == 't' || buf[0] == 'T');
    }

    static inline void FailLoud(const char* reason) {
        char msg[512] = {};
        std::snprintf(msg, sizeof(msg),
                      "[SparseGatherBridge] FATAL: %s\n"
                      "This would produce invalid/no-op benchmarking results.\n"
                      "Set RAWRXD_SPARSEGATHER_FAIL_LOUD=0 to downgrade to soft-fail.\n",
                      reason ? reason : "unknown error");
        OutputDebugStringA(msg);
        std::fputs(msg, stderr);
        std::fflush(stderr);
        std::abort();
    }

    static inline bool ValidateConfig(const MoeConfig& config, const char** why = nullptr) {
        if (config.num_experts == 0) {
            if (why) *why = "num_experts is zero";
            return false;
        }
        if (config.hidden_dim == 0 || config.ffn_dim == 0) {
            if (why) *why = "hidden_dim/ffn_dim is zero";
            return false;
        }
        if (config.weights_base == nullptr) {
            if (why) *why = "weights_base is null";
            return false;
        }
        return true;
    }

    SparseGatherBridge(const MoeConfig& config) {
        m_config = config;
        const char* why = nullptr;
        if (!ValidateConfig(m_config, &why)) {
            if (ShouldFailLoud()) {
                FailLoud(why);
            }
            return;
        }
        m_context = SparseGather_Initialize(&m_config, nullptr);
        if (!m_context && ShouldFailLoud()) {
            FailLoud("SparseGather_Initialize returned null context");
        }
    }

    ~SparseGatherBridge() {
        if (m_context) {
            // Cleanup logic (VirtualFree) should be in SparseGather_Shutdown in MASM
        }
    }

    bool ExecuteLayer(float* input, float* router_logits, float* output, uint32_t layer) {
        const char* why = nullptr;
        if (!ValidateConfig(m_config, &why)) {
            if (ShouldFailLoud()) {
                FailLoud(why);
            }
            return false;
        }
        if (!m_context) {
            if (ShouldFailLoud()) {
                FailLoud("SparseGather context is null");
            }
            return false;
        }
        __try {
            return SparseGather_Execute(m_context, input, router_logits, output, layer) == 1;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    void Flush() {
        if (m_context) {
            __try {
                SparseGather_FlushCache(m_context);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                // Ignore
            }
        }
    }

    struct Stats {
        uint64_t loaded;
        uint64_t skipped;
    };

    Stats GetStats() {
        Stats s = {0, 0};
        // Additional safety: check m_context is valid before calling into ASM
        // Use SEH to catch any access violations from invalid context
        if (m_context) {
            __try {
                SparseGather_GetStats(m_context, &s.loaded, &s.skipped);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                // Silently ignore exceptions from invalid context
                s.loaded = 0;
                s.skipped = 0;
            }
        }
        return s;
    }

private:
    MoeConfig m_config;
    void* m_context = nullptr;
};

} // namespace RawrXD::MoE
