#include "d2_sweep_amortizer.h"

namespace d2 {

static bool fits(std::uint64_t cap,
                 std::uint64_t a,
                 std::uint64_t b,
                 std::uint64_t c,
                 std::uint64_t d) noexcept {
    if (a > cap) return false;
    cap -= a;
    if (b > cap) return false;
    cap -= b;
    if (c > cap) return false;
    cap -= c;
    return d <= cap;
}

ResidencyPlan make_residency_plan(const ResidencyInputs& in) noexcept {
    ResidencyPlan p{};

    p.target_fully_gpu_resident = fits(
        in.gpu0_bytes,
        in.target_weight_bytes,
        in.target_kv_reserve_bytes,
        in.target_scratch_reserve_bytes,
        in.safety_margin_gpu0_bytes);

    p.draft_fully_gpu_resident = fits(
        in.gpu1_bytes,
        in.draft_weight_bytes,
        in.draft_kv_reserve_bytes,
        in.safety_margin_gpu1_bytes,
        0u);

    if (p.target_fully_gpu_resident) {
        p.gpu0_target_weight_bytes = in.target_weight_bytes;
        p.gpu0_reserved_bytes =
            in.target_kv_reserve_bytes +
            in.target_scratch_reserve_bytes +
            in.safety_margin_gpu0_bytes;
    }

    if (p.draft_fully_gpu_resident) {
        p.gpu1_draft_weight_bytes = in.draft_weight_bytes;
        p.gpu1_reserved_bytes =
            in.draft_kv_reserve_bytes +
            in.safety_margin_gpu1_bytes;
    }

    // RAM holds the backing images even when both models are GPU-resident.
    p.ram_backing_bytes = in.target_weight_bytes + in.draft_weight_bytes;

    // A fully resident target does not require RAM->VRAM transfers in steady-state decode.
    // If it does not fit, the target verifier must use Deep2's TP or exact-range streaming path.
    p.steady_state_ram_to_vram_required = !p.target_fully_gpu_resident;

    return p;
}

} // namespace d2
