#include "nilw_auth.hpp"
#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
#endif

namespace rawrxd {

static uint64_t MulDiv(uint64_t a, uint64_t b, uint64_t d) {
    if (!d) return 0;
#if defined(_MSC_VER) && defined(_M_X64)
    unsigned __int64 hi = 0;
    unsigned __int64 lo = _umul128(a, b, &hi);
    if (hi) return 0; // bounded-runtime contract
    return lo / d;
#else
    __uint128_t v = (__uint128_t)a * b;
    return (uint64_t)(v / d);
#endif
}

uint64_t RatioScaled(uint64_t num, uint64_t den, uint64_t scale) {
    return MulDiv(num, scale, den);
}

NilwResult EvaluateNilw(const NilwWitness& w) {
    NilwResult r{};

    const uint64_t base_valid =
        w.total_logical_weights > 0 &&
        w.active_logical_weights > 0 &&
        w.generated_tokens > 0 &&
        w.wall_ns > 0;

    r.physicalization_ppm =
        RatioScaled(w.active_logical_weights,
                    w.total_logical_weights,
                    1000000ull);

    // Separation law:
    // Form A derives codec density from total active representation bits.
    // Form B derives active density from new payload bits only.
    if (w.form == NILW_FORM_A) {
        r.numerator_separation_ok =
            w.active_representation_bits > 0 &&
            w.new_information_bits <= w.active_representation_bits &&
            w.new_payload_bits == 0;

        r.active_codec_bpw_x1e6 =
            RatioScaled(w.active_representation_bits,
                        w.active_logical_weights,
                        1000000ull);

        r.new_information_fraction_ppm =
            RatioScaled(w.new_information_bits,
                        w.active_representation_bits,
                        1000000ull);

        const uint64_t total_new_bits =
            w.new_information_bits + w.overhead_bits;

        r.token_nilw_x1e9 =
            RatioScaled(total_new_bits,
                        w.total_logical_weights,
                        1000000000ull);

        if (w.generated_tokens)
            r.new_payload_bytes_per_token =
                total_new_bits / 8ull / w.generated_tokens;

        if (w.wall_ns)
            r.information_rate_bps =
                MulDiv(total_new_bits, 1000000000ull, w.wall_ns);
    } else if (w.form == NILW_FORM_B) {
        r.numerator_separation_ok =
            w.new_payload_bits > 0 &&
            w.active_representation_bits == 0 &&
            w.new_information_bits == 0;

        r.active_new_bpw_x1e6 =
            RatioScaled(w.new_payload_bits,
                        w.active_logical_weights,
                        1000000ull);

        const uint64_t total_new_bits =
            w.new_payload_bits + w.overhead_bits;

        r.token_nilw_x1e9 =
            RatioScaled(total_new_bits,
                        w.total_logical_weights,
                        1000000000ull);

        if (w.generated_tokens)
            r.new_payload_bytes_per_token =
                total_new_bits / 8ull / w.generated_tokens;

        if (w.wall_ns)
            r.information_rate_bps =
                MulDiv(total_new_bits, 1000000000ull, w.wall_ns);
    }

    if (w.wall_ns)
        r.tps_x1000 =
            MulDiv(w.generated_tokens, 1000000000000ull, w.wall_ns);

    r.envelope_100mb_token =
        base_valid &&
        r.new_payload_bytes_per_token <= 100000000ull;

    r.envelope_10tps =
        base_valid &&
        r.tps_x1000 >= 10000ull;

    r.envelope_1gbps =
        base_valid &&
        r.information_rate_bps <= 1000000000ull;

    r.independent_proofs_pass =
        w.active_subset_measured == PROOF_PASS &&
        w.reuse_measured == PROOF_PASS &&
        w.overhead_accounted == PROOF_PASS &&
        w.quality_gate == PROOF_PASS;

    r.no_full_materialization =
        w.full_materialization == 0;

    r.valid =
        base_valid &&
        r.numerator_separation_ok;

    r.authorized_pass =
        r.valid &&
        r.envelope_100mb_token &&
        r.envelope_10tps &&
        r.envelope_1gbps &&
        r.independent_proofs_pass &&
        r.no_full_materialization;

    return r;
}

}
