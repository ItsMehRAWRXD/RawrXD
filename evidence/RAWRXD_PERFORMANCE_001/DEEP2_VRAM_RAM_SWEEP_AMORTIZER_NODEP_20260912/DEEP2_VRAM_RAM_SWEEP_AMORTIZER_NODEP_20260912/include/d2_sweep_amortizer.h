#pragma once
#include <cstddef>
#include <cstdint>

#ifndef D2_MAX_VERIFY_WINDOW
#define D2_MAX_VERIFY_WINDOW 32u
#endif

namespace d2 {

enum class ResidencyTier : std::uint8_t {
    GPU0_TARGET = 0,
    GPU1_DRAFT  = 1,
    RAM_BACKING = 2,
    UNPLACED    = 3
};

struct ResidencyInputs {
    std::uint64_t gpu0_bytes;
    std::uint64_t gpu1_bytes;
    std::uint64_t ram_bytes;

    std::uint64_t target_weight_bytes;
    std::uint64_t target_kv_reserve_bytes;
    std::uint64_t target_scratch_reserve_bytes;

    std::uint64_t draft_weight_bytes;
    std::uint64_t draft_kv_reserve_bytes;

    std::uint64_t safety_margin_gpu0_bytes;
    std::uint64_t safety_margin_gpu1_bytes;
};

struct ResidencyPlan {
    bool target_fully_gpu_resident;
    bool draft_fully_gpu_resident;
    bool steady_state_ram_to_vram_required;

    std::uint64_t gpu0_target_weight_bytes;
    std::uint64_t gpu0_reserved_bytes;
    std::uint64_t gpu1_draft_weight_bytes;
    std::uint64_t gpu1_reserved_bytes;
    std::uint64_t ram_backing_bytes;
};

ResidencyPlan make_residency_plan(const ResidencyInputs& in) noexcept;

struct VerifyBatchResult {
    // target_greedy[i] is the target model's authoritative greedy token
    // aligned with proposed[i]. target_greedy[proposed_count] is a bonus token.
    std::uint32_t proposed_count;
    std::int32_t target_greedy[D2_MAX_VERIFY_WINDOW + 1u];
    void* transaction;
};

using DraftProposeFn = std::uint32_t (*)(
    void* user,
    std::uint32_t max_tokens,
    std::int32_t* out_tokens) noexcept;

using TargetVerifyGreedyFn = bool (*)(
    void* user,
    const std::int32_t* proposed,
    std::uint32_t proposed_count,
    VerifyBatchResult* out) noexcept;

// Commit exactly accepted_candidate_prefix candidate KV entries from the
// verification transaction. The emitted mismatch/bonus token is not part of
// this count because its KV is produced when consumed by the next pass.
using FinalizeVerifyFn = bool (*)(
    void* user,
    void* transaction,
    std::uint32_t accepted_candidate_prefix) noexcept;

using AbortVerifyFn = void (*)(
    void* user,
    void* transaction) noexcept;

using EmitTokenFn = bool (*)(
    void* user,
    std::int32_t token) noexcept;

struct Bindings {
    void* user;
    DraftProposeFn draft_propose;
    TargetVerifyGreedyFn target_verify_greedy;
    FinalizeVerifyFn finalize_verify;
    AbortVerifyFn abort_verify;
    EmitTokenFn emit_token;
};

struct ControllerConfig {
    std::uint32_t min_window = 2;
    std::uint32_t initial_window = 4;
    std::uint32_t max_window = 12;

    // Grow after this many fully accepted windows.
    std::uint32_t full_accepts_to_grow = 2;

    // If the first mismatch occurs before this fraction of the current window,
    // shrink the next verification window.
    // Stored as numerator/denominator to avoid floating-point policy state.
    std::uint32_t early_mismatch_num = 1;
    std::uint32_t early_mismatch_den = 2;
};

struct SweepStats {
    std::uint64_t target_sweeps = 0;
    std::uint64_t draft_tokens_proposed = 0;
    std::uint64_t draft_tokens_accepted = 0;
    std::uint64_t target_forced_tokens = 0;
    std::uint64_t bonus_tokens = 0;
    std::uint64_t generated_tokens = 0;
    std::uint64_t full_accept_windows = 0;
    std::uint64_t mismatch_windows = 0;

    double tokens_per_target_sweep() const noexcept {
        return target_sweeps
            ? static_cast<double>(generated_tokens) / static_cast<double>(target_sweeps)
            : 0.0;
    }

    double draft_acceptance() const noexcept {
        return draft_tokens_proposed
            ? static_cast<double>(draft_tokens_accepted) /
              static_cast<double>(draft_tokens_proposed)
            : 0.0;
    }
};

class SweepAmortizer {
public:
    explicit SweepAmortizer(ControllerConfig cfg = {}) noexcept;

    bool bind(const Bindings& b) noexcept;

    // Generate up to max_output_tokens. Returns false on callback failure.
    bool generate(std::uint64_t max_output_tokens) noexcept;

    const SweepStats& stats() const noexcept { return stats_; }
    std::uint32_t current_window() const noexcept { return window_; }

private:
    void on_full_accept() noexcept;
    void on_mismatch(std::uint32_t mismatch_index) noexcept;

    Bindings b_{};
    ControllerConfig cfg_{};
    SweepStats stats_{};
    std::uint32_t window_ = 0;
    std::uint32_t consecutive_full_accepts_ = 0;
    bool bound_ = false;
};

} // namespace d2
