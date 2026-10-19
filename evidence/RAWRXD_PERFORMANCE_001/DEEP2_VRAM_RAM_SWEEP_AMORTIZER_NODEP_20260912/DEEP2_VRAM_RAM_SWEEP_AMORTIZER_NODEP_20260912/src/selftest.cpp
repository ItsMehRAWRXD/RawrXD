#include "d2_sweep_amortizer.h"
#include <cstdio>
#include <cstdint>

struct Fake {
    std::int32_t next = 100;
    std::uint64_t emitted = 0;
};

static std::uint32_t draft(void* u, std::uint32_t max_tokens, std::int32_t* out) noexcept {
    Fake* f = static_cast<Fake*>(u);
    for (std::uint32_t i = 0; i < max_tokens; ++i) {
        // Every seventh token is intentionally wrong to exercise mismatch handling.
        std::int32_t exact = f->next + static_cast<std::int32_t>(i);
        out[i] = ((exact % 7) == 0) ? exact + 999 : exact;
    }
    return max_tokens;
}

static bool verify(void* u,
                   const std::int32_t*,
                   std::uint32_t n,
                   d2::VerifyBatchResult* out) noexcept {
    Fake* f = static_cast<Fake*>(u);
    out->proposed_count = n;
    for (std::uint32_t i = 0; i <= n; ++i) {
        out->target_greedy[i] = f->next + static_cast<std::int32_t>(i);
    }
    // Transaction handle is opaque to the scheduler. The fake uses a stable non-null marker.
    out->transaction = u;
    return true;
}

static bool finalize(void* u, void*, std::uint32_t accepted_prefix) noexcept {
    Fake* f = static_cast<Fake*>(u);
    // Accepted candidate tokens have been consumed by the target verification.
    f->next += static_cast<std::int32_t>(accepted_prefix);
    return true;
}

static void abort_txn(void*, void*) noexcept {}

static bool emit(void* u, std::int32_t token) noexcept {
    Fake* f = static_cast<Fake*>(u);
    // If this is a mismatch or bonus token, it becomes the next input token.
    // In a real Deep2 bind, its KV is generated on the next target verification pass.
    if (token >= f->next) {
        f->next = token + 1;
    }
    ++f->emitted;
    return true;
}

int main() {
    d2::ResidencyInputs ri{};
    ri.gpu0_bytes = 32ull << 30;
    ri.gpu1_bytes = 16ull << 30;
    ri.ram_bytes  = 64ull << 30;
    ri.target_weight_bytes = 25ull << 30;
    ri.target_kv_reserve_bytes = 2ull << 30;
    ri.target_scratch_reserve_bytes = 1ull << 30;
    ri.draft_weight_bytes = 8ull << 30;
    ri.draft_kv_reserve_bytes = 1ull << 30;
    ri.safety_margin_gpu0_bytes = 2ull << 30;
    ri.safety_margin_gpu1_bytes = 1ull << 30;

    const d2::ResidencyPlan rp = d2::make_residency_plan(ri);
    if (!rp.target_fully_gpu_resident || !rp.draft_fully_gpu_resident ||
        rp.steady_state_ram_to_vram_required) {
        std::puts("RESIDENCY_TEST=FAIL");
        return 2;
    }

    Fake f{};

    d2::ControllerConfig cc{};
    cc.min_window = 2;
    cc.initial_window = 4;
    cc.max_window = 8;
    cc.full_accepts_to_grow = 2;

    d2::SweepAmortizer a(cc);
    d2::Bindings b{};
    b.user = &f;
    b.draft_propose = &draft;
    b.target_verify_greedy = &verify;
    b.finalize_verify = &finalize;
    b.abort_verify = &abort_txn;
    b.emit_token = &emit;

    if (!a.bind(b)) {
        std::puts("BIND=FAIL");
        return 3;
    }

    if (!a.generate(64)) {
        std::puts("GENERATE=FAIL");
        return 4;
    }

    const d2::SweepStats& s = a.stats();
    std::printf("RESIDENCY_TEST=PASS\n");
    std::printf("GENERATED=%llu\n", static_cast<unsigned long long>(s.generated_tokens));
    std::printf("TARGET_SWEEPS=%llu\n", static_cast<unsigned long long>(s.target_sweeps));
    std::printf("DRAFT_PROPOSED=%llu\n", static_cast<unsigned long long>(s.draft_tokens_proposed));
    std::printf("DRAFT_ACCEPTED=%llu\n", static_cast<unsigned long long>(s.draft_tokens_accepted));
    std::printf("TARGET_FORCED=%llu\n", static_cast<unsigned long long>(s.target_forced_tokens));
    std::printf("BONUS=%llu\n", static_cast<unsigned long long>(s.bonus_tokens));
    std::printf("TOKENS_PER_TARGET_SWEEP=%.3f\n", s.tokens_per_target_sweep());
    std::printf("DRAFT_ACCEPTANCE=%.3f\n", s.draft_acceptance());

    if (s.generated_tokens != 64 || s.target_sweeps == 0) return 5;
    return 0;
}
