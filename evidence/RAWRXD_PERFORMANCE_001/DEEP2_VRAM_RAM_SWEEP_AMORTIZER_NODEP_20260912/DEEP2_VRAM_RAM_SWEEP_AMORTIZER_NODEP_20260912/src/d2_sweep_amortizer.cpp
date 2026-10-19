#include "d2_sweep_amortizer.h"

namespace d2 {

static std::uint32_t clamp_u32(std::uint32_t v, std::uint32_t lo, std::uint32_t hi) noexcept {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

SweepAmortizer::SweepAmortizer(ControllerConfig cfg) noexcept : cfg_(cfg) {
    if (cfg_.min_window < 1u) cfg_.min_window = 1u;
    if (cfg_.max_window > D2_MAX_VERIFY_WINDOW) cfg_.max_window = D2_MAX_VERIFY_WINDOW;
    if (cfg_.max_window < cfg_.min_window) cfg_.max_window = cfg_.min_window;
    if (cfg_.initial_window < cfg_.min_window) cfg_.initial_window = cfg_.min_window;
    if (cfg_.initial_window > cfg_.max_window) cfg_.initial_window = cfg_.max_window;
    if (cfg_.full_accepts_to_grow == 0u) cfg_.full_accepts_to_grow = 1u;
    if (cfg_.early_mismatch_den == 0u) cfg_.early_mismatch_den = 1u;
    window_ = cfg_.initial_window;
}

bool SweepAmortizer::bind(const Bindings& b) noexcept {
    if (!b.draft_propose || !b.target_verify_greedy ||
        !b.finalize_verify || !b.abort_verify || !b.emit_token) {
        bound_ = false;
        return false;
    }
    b_ = b;
    bound_ = true;
    return true;
}

void SweepAmortizer::on_full_accept() noexcept {
    ++consecutive_full_accepts_;
    ++stats_.full_accept_windows;

    if (consecutive_full_accepts_ >= cfg_.full_accepts_to_grow) {
        consecutive_full_accepts_ = 0;
        if (window_ < cfg_.max_window) {
            // Conservative +1 growth avoids overshooting the draft's useful horizon.
            ++window_;
        }
    }
}

void SweepAmortizer::on_mismatch(std::uint32_t mismatch_index) noexcept {
    consecutive_full_accepts_ = 0;
    ++stats_.mismatch_windows;

    const std::uint64_t lhs =
        static_cast<std::uint64_t>(mismatch_index + 1u) *
        static_cast<std::uint64_t>(cfg_.early_mismatch_den);
    const std::uint64_t rhs =
        static_cast<std::uint64_t>(window_) *
        static_cast<std::uint64_t>(cfg_.early_mismatch_num);

    if (lhs <= rhs && window_ > cfg_.min_window) {
        // Halve on an early miss, bounded by min_window.
        std::uint32_t next = window_ / 2u;
        window_ = clamp_u32(next, cfg_.min_window, cfg_.max_window);
    }
}

bool SweepAmortizer::generate(std::uint64_t max_output_tokens) noexcept {
    if (!bound_) return false;

    std::int32_t proposed[D2_MAX_VERIFY_WINDOW]{};

    while (stats_.generated_tokens < max_output_tokens) {
        const std::uint64_t remain64 = max_output_tokens - stats_.generated_tokens;
        std::uint32_t ask = window_;
        if (remain64 < ask) ask = static_cast<std::uint32_t>(remain64);
        if (ask == 0u) break;

        std::uint32_t proposed_count = b_.draft_propose(b_.user, ask, proposed);
        if (proposed_count == 0u || proposed_count > ask || proposed_count > D2_MAX_VERIFY_WINDOW) {
            return false;
        }

        stats_.draft_tokens_proposed += proposed_count;

        VerifyBatchResult vr{};
        vr.proposed_count = proposed_count;

        if (!b_.target_verify_greedy(b_.user, proposed, proposed_count, &vr)) {
            if (vr.transaction) b_.abort_verify(b_.user, vr.transaction);
            return false;
        }
        ++stats_.target_sweeps;

        std::uint32_t accepted_prefix = 0u;
        while (accepted_prefix < proposed_count &&
               proposed[accepted_prefix] == vr.target_greedy[accepted_prefix]) {
            ++accepted_prefix;
        }

        if (!b_.finalize_verify(b_.user, vr.transaction, accepted_prefix)) {
            b_.abort_verify(b_.user, vr.transaction);
            return false;
        }

        // Emit all target-validated draft tokens in the accepted prefix.
        for (std::uint32_t i = 0; i < accepted_prefix; ++i) {
            if (stats_.generated_tokens >= max_output_tokens) break;
            if (!b_.emit_token(b_.user, proposed[i])) return false;
            ++stats_.draft_tokens_accepted;
            ++stats_.generated_tokens;
        }

        if (stats_.generated_tokens >= max_output_tokens) {
            if (accepted_prefix == proposed_count) on_full_accept();
            else on_mismatch(accepted_prefix);
            break;
        }

        if (accepted_prefix < proposed_count) {
            // First mismatch: target token is authoritative.
            const std::int32_t forced = vr.target_greedy[accepted_prefix];
            if (!b_.emit_token(b_.user, forced)) return false;
            ++stats_.target_forced_tokens;
            ++stats_.generated_tokens;
            on_mismatch(accepted_prefix);
        } else {
            // All proposed tokens matched. Emit the target bonus token.
            const std::int32_t bonus = vr.target_greedy[proposed_count];
            if (!b_.emit_token(b_.user, bonus)) return false;
            ++stats_.bonus_tokens;
            ++stats_.generated_tokens;
            on_full_accept();
        }
    }

    return true;
}

} // namespace d2
