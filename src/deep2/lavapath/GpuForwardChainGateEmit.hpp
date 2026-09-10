#pragma once
/* Emit sealed GPU-forward chain gate receipt. Runtime authority only. ≤99 lines. */
#include "GPUForwardChildIgnore.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "lavapath/OneByOneIgnoreLadder.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace rawr::gpu_chain_gate {

inline const char* ChainGate() noexcept {
    const char* g = std::getenv("DEEP2_GPU_FORWARD_CHAIN_GATE");
    return (g && *g) ? g : "G0_REFERENCE";
}

inline const char* ChildIgnore() noexcept {
    const char* c = std::getenv("DEEP2_GPU_FORWARD_CHILD_IGNORE");
    return (c && *c) ? c : "NONE";
}

inline bool ChildIs(const char* want) noexcept {
    const char* c = ChildIgnore();
    if (!c || !want) return false;
    return _stricmp(c, want) == 0;
}

/* Canonical G1–G7 have no safe tensor bypass in this tree. */
inline bool SafeApplyPossible() noexcept {
    if (ChildIs("NONE") || !*ChildIgnore()) return true;
    if (ChildIs("READBACK")) return true; /* in-place download elision only */
    return false;
}

inline void Emit(FILE* f, double gpuForwardMs, uint64_t gpuForwardCalls) noexcept {
    if (!f) return;
    using namespace RawrXD::Deep2::GpuForwardIgnore;
    const char* gate = ChainGate();
    const char* child = ChildIgnore();
    const bool requested = child && *child && _stricmp(child, "NONE") != 0;
    const bool applied = false; /* G1–G7: never fabricate; READBACK applied at callsite */
    const char* blocked = (!requested) ? "NONE"
        : (SafeApplyPossible() ? "NONE" : "SAFE_BYPASS");

    auto emitChild = [&](const char* name, Child ch) {
        const Counter& c = State::Get().counter(ch);
        const auto a = c.attempted.load(std::memory_order_relaxed);
        const auto e = c.executed.load(std::memory_order_relaxed);
        const auto n = c.elapsedNs.load(std::memory_order_relaxed);
        const bool req = ChildIs(name);
        const bool app = req && applied;
        std::fprintf(f,
            "%s_CALLS=%llu\n%s_MS=%.3f\n%s_IGNORE_REQUESTED=%u\n%s_IGNORE_APPLIED=%u\n",
            name, (unsigned long long)(e ? e : a), name, n / 1e6,
            name, req ? 1u : 0u, name, app ? 1u : 0u);
    };

    std::fprintf(f, "GATE=%s\n", gate);
    std::fprintf(f, "DEEP2_GPU_ISO_RUN=1\n");
    std::fprintf(f, "GPU_FORWARD_CHILD_IGNORE=%s\n", requested ? child : "NONE");
    std::fprintf(f, "GPU_FORWARD_CALLS=%llu\n", (unsigned long long)gpuForwardCalls);
    std::fprintf(f, "GPU_FORWARD_MS=%.3f\n", gpuForwardMs);
    emitChild("QKV", Child::QKV);
    emitChild("DEVICE_ATTENTION", Child::DeviceAttention);
    emitChild("FFN", Child::FFN);
    emitChild("GEMV", Child::QuantGEMV);
    emitChild("OUTPUT_PROJECTION", Child::AttentionOutputProj);
    emitChild("KV", Child::KVUpdate);
    emitChild("SYNC", Child::SyncWait);
    emitChild("READBACK", Child::ReadbackD2H);
    std::fprintf(f, "IGNORE_REQUESTED=%u\n", requested ? 1u : 0u);
    std::fprintf(f, "IGNORE_APPLIED=%u\n", 0u);
    std::fprintf(f, "BLOCKED_AT=%s\n", blocked);
    std::fprintf(f, "GATE_BLOCKED_AT=%s\n", blocked);
    std::fprintf(f, "CLAIM_AUTHORITY=OWN_RUNTIME_EMISSION_ONLY\n");
    std::fprintf(f, "RUNTIME_AUTHORITY=1\n");
    std::fprintf(f, "OLLAMA_HTTP=0\n");
    std::fprintf(f, "PROMOTE=0\n");
    std::fprintf(f, "TOKENS_COMMITTED=%llu\n",
                 (unsigned long long)rawr::iso_ladder::A().tokensCommitted);
    std::fflush(f);
}

} // namespace rawr::gpu_chain_gate
