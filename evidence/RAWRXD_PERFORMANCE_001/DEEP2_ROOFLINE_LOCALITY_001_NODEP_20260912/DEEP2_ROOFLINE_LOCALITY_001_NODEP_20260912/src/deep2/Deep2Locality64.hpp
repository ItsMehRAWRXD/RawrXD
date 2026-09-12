#pragma once
// Deep2Locality64.hpp — no-dependency live locality accounting for the
// DEEP2_ROOFLINE_LOCALITY_001 64-token authority gate.
// C++17 standard library only. Does not mint PROMOTE authority.

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <mutex>

namespace Deep2 {

enum class LocalityKind : uint8_t {
    Weight = 0,
    KV = 1,
    Activation = 2,
    Reduction = 3,
    Other = 4,
    Count = 5
};

struct Locality64ParentSeal {
    bool bind16_sealed = false;
    bool persistent_decode_sealed = false;
    bool residency_sealed = false;
    uint64_t weight_upload_delta = UINT64_MAX;
    uint64_t device_create_delta = UINT64_MAX;
    uint64_t model_load_delta = UINT64_MAX;
    uint64_t reload_bytes_delta = UINT64_MAX;
    uint64_t pin_evict_delta = UINT64_MAX;
};

struct Locality64Policy {
    // REQUIRED. Zero means "unset" and therefore FAIL/CANNOT_SEAL.
    uint64_t max_nonlocal_bytes_per_token = 0;

    // Optional. UINT64_MAX means not part of the conjunction.
    uint64_t max_critical_path_host_bytes_per_token = UINT64_MAX;
    uint64_t max_inter_gpu_bytes_per_token = UINT64_MAX;

    bool require_dual_gpu = true;
    bool require_same_token_overlap = true;
};

struct Locality64Snapshot {
    uint64_t demand_bytes_total = 0;
    uint64_t already_local_bytes_total = 0;
    uint64_t bytes_not_already_local_total = 0;

    uint64_t weight_bytes_requested_total = 0;
    uint64_t weight_bytes_already_local = 0;
    uint64_t kv_bytes_requested_total = 0;
    uint64_t kv_bytes_already_local = 0;

    uint64_t host_to_device_bytes = 0;
    uint64_t critical_path_host_bytes = 0;
    uint64_t inter_gpu_bytes = 0;

    uint64_t gpu0_forward_count = 0;
    uint64_t gpu1_forward_count = 0;
    uint64_t same_token_overlap_count = 0;

    uint64_t generation_wall_ns = 0;
    uint64_t token_ns_p50 = 0;
    uint64_t token_ns_p95 = 0;
    uint64_t token_ns_max = 0;
    uint64_t tps_milli = 0;
    uint64_t measured_tokens = 0;

    bool accounting_overflow = false;
    bool sequence_error = false;
};

struct Locality64Verdict {
    Locality64Snapshot s{};
    bool exact_64 = false;
    bool parents_sealed = false;
    bool residency_still_zero_delta = false;
    bool accounting_valid = false;
    bool timing_valid = false;
    bool threshold_configured = false;
    bool locality_limit_ok = false;
    bool critical_host_limit_ok = false;
    bool inter_gpu_limit_ok = false;
    bool dual_gpu_ok = false;
    bool overlap_ok = false;
    bool conjunction = false;
};

class Locality64Collector {
public:
    static constexpr uint64_t kTargetTokens = 64;

    Locality64Collector();
    void reset();

    // Arm only after warm-up/token-1 baseline. Calls while disarmed are ignored.
    void setArmed(bool armed);
    bool armed() const;

    void beginWindow(uint64_t now_ns);
    bool beginToken(uint64_t ordinal, uint64_t now_ns);
    bool endToken(uint64_t ordinal, uint64_t now_ns);
    void endWindow(uint64_t now_ns);

    // Demand accounting: "already_local" is true only when execution can consume
    // the exact requested bytes without a new host/device/inter-device fetch.
    void noteDemand(LocalityKind kind, uint64_t bytes, bool already_local);
    void noteHostToDevice(uint64_t bytes, bool on_critical_path);
    void noteInterGpu(uint64_t bytes);

    // Record true execution intervals. Same-token overlap is interval intersection,
    // not merely "both devices were used somewhere in the generation".
    void noteGpuForwardSpan(unsigned gpu_slot, uint64_t token_ordinal,
                            uint64_t start_ns, uint64_t end_ns);

    Locality64Snapshot snapshot() const;
    Locality64Verdict evaluate(const Locality64ParentSeal& parent,
                               const Locality64Policy& policy) const;

    static int writeReceipt(const char* path,
                            const Locality64ParentSeal& parent,
                            const Locality64Policy& policy,
                            const Locality64Verdict& v,
                            uint64_t raw_generated_tokens);

private:
    struct Span { uint64_t start = 0, end = 0; bool valid = false; };

    static bool addSat(std::atomic<uint64_t>& dst, uint64_t add,
                       std::atomic<bool>& overflow);
    static uint64_t percentile(std::array<uint64_t, kTargetTokens> a,
                               uint64_t n, unsigned pct);

    std::atomic<bool> armed_{false};
    std::atomic<bool> overflow_{false};
    std::atomic<bool> sequence_error_{false};

    std::array<std::atomic<uint64_t>, static_cast<size_t>(LocalityKind::Count)> demand_{};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(LocalityKind::Count)> local_{};
    std::atomic<uint64_t> h2d_{0};
    std::atomic<uint64_t> critical_host_{0};
    std::atomic<uint64_t> inter_gpu_{0};
    std::array<std::atomic<uint64_t>, 2> gpu_fwd_{};

    mutable std::mutex mu_;
    std::array<uint64_t, kTargetTokens> token_begin_{};
    std::array<uint64_t, kTargetTokens> token_ns_{};
    std::array<std::array<Span, 2>, kTargetTokens> spans_{};
    uint64_t measured_tokens_ = 0;
    uint64_t window_begin_ns_ = 0;
    uint64_t window_end_ns_ = 0;
};

// Process-global seam for low-friction product instrumentation.
Locality64Collector& Locality64_Global();

inline void Locality64_NoteDemand(LocalityKind kind, uint64_t bytes, bool local) {
    Locality64_Global().noteDemand(kind, bytes, local);
}
inline void Locality64_NoteHostToDevice(uint64_t bytes, bool critical) {
    Locality64_Global().noteHostToDevice(bytes, critical);
}
inline void Locality64_NoteInterGpu(uint64_t bytes) {
    Locality64_Global().noteInterGpu(bytes);
}
inline void Locality64_NoteGpuForwardSpan(unsigned gpu, uint64_t token,
                                          uint64_t start_ns, uint64_t end_ns) {
    Locality64_Global().noteGpuForwardSpan(gpu, token, start_ns, end_ns);
}

} // namespace Deep2
